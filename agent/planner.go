package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	findingRecorder   FindingRecorder
	prov              llm.Provider
	model             string
	tx                *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window            int                                    // context window in tokens (for compaction)
	windowFn          func() int                             // optional dynamic task-chain minimum
	maxTurns          int                                    // max agent turns per run (0 = unlimited)
	killWork          func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork         func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr         string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert       string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch         WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir           string                                 // shared work dir (surfaced in prompt as artifact-output target)
	injectConstraints func() bool                            // resolver: inject task operation constraints into system prompt? (nil = yes)
	nonStreamingFn    func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn      func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn       func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
	compactor         *Compactor                             // cold-node compaction (§7); nil = disabled

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

func (p *Planner) SetCompactionWindowResolver(fn func() int) { p.windowFn = fn }

// SetCompactor wires the cold-node compactor (cold-digest §7). Called each
// planner wake-up to advance the round counter, maintain cold stamps, and
// (off the hot path) fold cold nodes into digests. nil = feature disabled.
func (p *Planner) SetCompactor(c *Compactor) { p.compactor = c }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (p *Planner) SetNonStreaming(fn func() bool) { p.nonStreamingFn = fn }

func (p *Planner) nonStreaming() bool { return p.nonStreamingFn != nil && p.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (p *Planner) SetNoaEnabled(fn func() bool) { p.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (p *Planner) SetMaxTokens(fn func() int) { p.maxTokensFn = fn }

func (p *Planner) maxTokens() int {
	if p.maxTokensFn == nil {
		return 0
	}
	return p.maxTokensFn()
}

func (p *Planner) compactionWindow() int {
	if p.windowFn != nil {
		return p.windowFn()
	}
	return p.window
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the planner system prompt. Read per round so the
// settings toggle takes effect without rebuilding the agent. nil = inject (default).
func (p *Planner) SetConstraintInject(fn func() bool) { p.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (p *Planner) wantConstraints() bool { return p.injectConstraints == nil || p.injectConstraints() }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your planning todo list (kept across wake-ups; you wrote it in a previous round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Proceed from this list: dispatch an intent only for the next step whose [prerequisite steps are completed / the facts it depends on already exist]; update the list with TodoWrite (mark steps already satisfied by a fact as completed). Do not re-dispatch steps that are already pending/in_progress in the list.")
	return b.String()
}

// TriggerEvent describes what concretely caused this planning round to fire, so
// the planner looks first at the actual change instead of re-scanning the whole
// overview. Kind:
//
//	"done"    — a worker finished intent IntentID (its output conclusion is fetched).
//	"finding" — a worker reported a finding on intent IntentID (Detail = summary).
//	"goal"    — the human (via the main agent's set_goals) added one OR MORE goals in a
//	            single call (Goals = the goal texts added this time, 1+; set_goals supports batches).
//	"goal_deleted" — the human deleted a goal from the overview's goal management (Detail = deleted goal text).
//	"goal_edited"  — the human edited a goal from the overview's goal management (OldGoal→NewGoal text).
//	"cancelled" — the human deleted intent IntentID (Detail = deletion reason). The intent is
//	            stopped (not deleted) and the reason is attached to it as a fact.
type TriggerEvent struct {
	Kind     string
	IntentID int64
	Detail   string
	Summary  string   // Kind=="cancelled" only: intent summary captured before deletion (after a real delete the node is gone and can no longer be looked up)
	Goals    []string // Kind=="goal" only: goal texts added by this set_goals call (one or more)
	OldGoal  string   // Kind=="goal_edited" only: goal text before the edit
	NewGoal  string   // Kind=="goal_edited" only: goal text after the edit
	Hints    []string // Kind=="hint" only: hint texts added by this add_hint call (one or more)
}

// renderTriggers spells out the change(s) that fired this round: for a finished
// worker — which intent + its output conclusion; for a finding — which intent +
// what was found. Empty for time/heartbeat wakes. Reads the store (best-effort;
// a blank field never blocks the round).
func renderTriggers(ts *db.ExplorationStore, evs []TriggerEvent) string {
	if len(evs) == 0 || ts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Actual changes that triggered this round (look here first, then decide whether to add directions)]:")
	for _, ev := range evs {
		switch ev.Kind {
		case "goal":
			if len(ev.Goals) == 1 {
				b.WriteString(fmt.Sprintf("\n- The human (via the main agent) added a goal: %s — a new goal to achieve; add exploration directions for it accordingly (if no intent covers it yet).", ev.Goals[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The human (via the main agent) added %d goals: %s — all are new goals to achieve; add exploration directions one by one for each goal that has no matching intent yet.", len(ev.Goals), strings.Join(ev.Goals, "; ")))
			}
		case "hint":
			if len(ev.Hints) == 1 {
				b.WriteString(fmt.Sprintf("\n- The human (via the main agent) added a strategic hint: %s — it is now attached to the exploration graph; adjust/add exploration directions accordingly (if no intent covers it yet).", ev.Hints[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The human (via the main agent) added %d strategic hints: %s — all are now attached to the exploration graph; adjust/add exploration directions for each of them.", len(ev.Hints), strings.Join(ev.Hints, "; ")))
			}
		case "goal_deleted":
			b.WriteString(fmt.Sprintf("\n- The human deleted this goal: %s — the goal has been removed; re-evaluate the remaining goals/directions accordingly (no need to dispatch intents for it any more).", ev.Detail))
		case "goal_edited":
			b.WriteString(fmt.Sprintf("\n- The human edited a goal, from \"%s\" to \"%s\" — adjust the exploration directions to the new goal (stop dispatching the old direction if it no longer applies).", ev.OldGoal, ev.NewGoal))
		case "finding":
			b.WriteString(fmt.Sprintf("\n- The worker of intent #%d (%s) reported a finding: %s", ev.IntentID, intentSummary(ts, ev.IntentID), ev.Detail))
		case "cancelled":
			// Prefer the Summary captured at deletion time for the intent content (after a real delete the node is gone and intentSummary cannot find it).
			sm := ev.Summary
			if sm == "" {
				sm = intentSummary(ts, ev.IntentID)
			}
			b.WriteString(fmt.Sprintf("\n- Intent #%d was deleted by the user. Intent content: %s; deletion reason: %s. The intent has been deleted (it will not be executed any more); re-plan accordingly.", ev.IntentID, sm, ev.Detail))
		default: // "done"
			b.WriteString(fmt.Sprintf("\n- The worker of intent #%d (%s) finished. Output conclusion: %s", ev.IntentID, intentSummary(ts, ev.IntentID), workerOutput(ts, ev.IntentID)))
			if fids := factIDsYielded(ts, ev.IntentID); fids != "" {
				b.WriteString(fmt.Sprintf("; fact ids newly produced by this intent: %s ", fids))
			}
		}
	}
	b.WriteString("\n(Full details can be looked up with node_detail / get_worker_output / list_findings.)")
	return b.String()
}

// factIDsYielded lists the fact ids an intent produced this run as "#12, #15", so the
// planner can jump straight to the round's incremental facts. Empty (best-effort) when
// the intent yielded no facts or the lookup fails.
func factIDsYielded(ts *db.ExplorationStore, id int64) string {
	ids, err := ts.FactsYielded(id)
	if err != nil || len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, fid := range ids {
		parts[i] = fmt.Sprintf("#%d", fid)
	}
	return strings.Join(parts, ", ")
}

// intentSummary reads an intent node's one-line summary (best-effort, "?" on miss).
func intentSummary(ts *db.ExplorationStore, id int64) string {
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		return "?"
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

// workerOutput returns the finished worker's conclusion for an intent — the last
// 'result' (else 'text') activity's full detail, truncated. Same source get_worker_output uses.
func workerOutput(ts *db.ExplorationStore, id int64) string {
	acts, _, err := ts.ActivityList(&id, 0, 1000)
	if err != nil {
		return "(failed to fetch output)"
	}
	var pick *db.Activity
	for i := range acts {
		if acts[i].Kind == "result" {
			pick = &acts[i]
		} else if acts[i].Kind == "text" && pick == nil {
			pick = &acts[i]
		}
	}
	if pick == nil {
		return "(this work has no output record yet)"
	}
	out, _ := ts.ActivityDetail(pick.ID)
	if out == "" {
		out = pick.Summary
	}
	return truncOutput(out, 800)
}

// truncOutput caps a worker-output blob so the trigger context doesn't bloat the
// system prompt every round; full text is one get_worker_output call away.
func truncOutput(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + " … (truncated; see get_worker_output for the full text)"
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[Situation this round (graph_overview pre-fetched; identical to what calling the tool would return; call node_detail/list_facts etc. on demand when you need details)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (section [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the intermediate-artifact output rules
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "Planner" of an authorized penetration-testing system on a cybersecurity platform, and you are woken frequently (every time the graph changes). Your job: read the situation → judge the goals → add exploration intents **only when there is a genuinely new direction that is not yet covered**. You are the Planner, not an executor: everything you produce this round must be either [generating/clarifying intents] or [judging goals] — never do the actual work yourself while planning.

Task goal: {{.Goal}}

**How many intents to produce this round (think this through first)**:
- **Hard floor (highest priority)**: whenever [the goal is not yet met] and [there is currently no open or running intent at all] (frontier_open=0 and running_intents is empty), this round [MUST] produce at least one intent that advances toward the goal — when there is no running work to wait for and no queued direction either, producing 0 intents = the task stalls; even if every known direction only appears in recent_done, open a new one or dispatch a continuation based on the done/exhausted/blocked judgment below.
- Beyond the hard floor, **producing 0 intents is a normal outcome, but it needs a legitimate reason** (it is not a "dispatching less is safer" default): ① **already covered** — every direction you can think of is already being handled by an intent that is still open/running (regenerating an existing intent in different words is a serious error); ② **waiting on a dependency** — the next step depends on the output of work that is currently running and that output is not there yet (forcing a dispatch now leaves the downstream intent without its prerequisite and spinning idle; wait until the graph has updated on the next wake-up, then dispatch).
- Conversely: if there really is a new direction that is [not covered and does not depend on running work], or the goal is not met and untested surface remains in scope, then dispatch — do not treat 0 intents as a lazy default.

**Decision flow on every wake-up**:

1. **The full situation is attached below this prompt** (it is exactly what graph_overview returns; there is no need to call it again): task (original title + goal/root node), asset counts, goals + status, open/running/recent_done intents, sites_without_endpoints (sites with no endpoints, hinting at directions that may still need exploring), facts (number of exploration facts; a separate category from findings), recent_facts ({id,summary,confidence?}).
   - **Scope**: exploration nodes (goals/intents/facts/findings) contain only this task; **the asset graph is shared globally** (one copy for all tasks; asset counts are global in-scope numbers, not exclusive to this task) — ignore assets unrelated to this task when they show up.
   - **Lineage**: every intent carries parents (upstream: which facts/intents it was derived from) and yields (downstream: which facts/findings it produced), and every recent_facts entry carries from_intent; use these to understand "which facts came from which direction, and whether they can be combined into a new direction".
   - **Negative/doubtful observations** ("port closed / not injectable" and the like in recent_facts) are a worker's observations, not final verdicts: before accepting one, run node_detail(id) and look at the evidence — only when the evidence is solid, confidence=observed and the available techniques have been exhausted should the direction be treated as closed off for now; when the evidence is missing, it merely "looks like it / was probed only once", or confidence=inferred, treat it as [not yet established], and if it is in scope and no other intent covers it, by default dispatch one re-check intent to confirm or overturn it (**re-check the same negative direction at most once**; if it is still negative after the re-check and the evidence is reasonable, respect that conclusion and do not dispatch again).
   - **Call for deeper detail only on demand**: list_facts (paginated, newest first, default 20, filter with q, page with before, returns total/has_more), list_findings (all findings), node_detail(id) (full evidence/detail; lists and recent_facts only give summaries), list_assets (pull: q search, type/company_id/task_id filters, pagination, or fetch directly by id/ids), asset_neighbors. Assets are shared globally; do not pull the full set by default.

2. **Judge the goals (core responsibility)**: the goals field already contains the goals and their status; for an unmet goal that has been proven by some finding/fact, call prove_goal(goal_id, evidence_id, reason) to mark it met. **When the goal you mark happens to be the last unfinished one, the system automatically judges the whole task complete** — closing out the task is driven only by proving goals one by one with prove_goal; there is no other "one-click complete" mechanism.
   - ⚠️ **Quantified acceptance check (no premature sign-off)**: when a goal contains a quantifiable condition (coverage reaches X%, capture N flags, obtain a certain privilege), before prove_goal you [MUST] check the measured values in the graph_overview above (coverage.pct, the findings_total count, etc.): if the bar is not reached, prove_goal is [FORBIDDEN] — dispatch intents to close the gap instead; you may not mark it met early on grounds such as "mostly achieved / the core part is already taken". Example: the required coverage is 100% but the measured coverage.pct=40% → not met; keep dispatching intents for the remaining tests.

3. **(Optional, opening only, extremely lightweight) Probe to understand**: only when the graph has almost no facts yet (recent_facts is essentially empty, the task has just started) and the situation alone is not enough to make the initial intents specific, use Bash etc. to do a very small amount of read-only probing of the target (e.g. 1–2 curl requests to look at the home page/fingerprint). **The only legitimate product is one more precise intent description** — never the discovery/verification/exploitation of a vulnerability, and not an enumeration of endpoints/directories/parameters either (that is worker work; write it as an intent and dispatch it). Three hard boundaries:
   - The graph already has worker-produced facts (facts>0 / recent_facts non-empty) → probing yourself is [FORBIDDEN]; base every judgment on the existing facts, and this round's product can only be "dispatch new intents" or "finish"; if you want to dig deeper into a lead → dispatch an intent so a worker investigates it, do not curl it yourself.
   - Even at the opening, stop after at most ≤3 probes, only to make the initial intents clear; the moment you notice you are "investigating in depth" rather than "quickly settling a direction" (enumerating endpoints/directories one by one, trying ids one by one, decoding chains, probing the same endpoint repeatedly, any testing or verification of injection/authorization bypass/vulnerabilities — all of that is the worker's heavy work), stop immediately and write it as an intent.
   - Whatever can be judged from the existing facts/situation needs no probing at all.

4. **Decide which new directions to add**: **"restraint" here only means [not duplicating intents that already exist], not "dispatch as few as you can"** — while the goal is not met, the default question to ask is "to get closer to the goal, which deeper, harder-hitting approaches are still uncovered", not "can we wrap up". An intent is an [open-ended exploration direction] (not a fixed type/menu); judge directions yourself from the known facts, assets and goals, and compare each one against open + running + recent_done:
   - Already covered by an open/running intent → do not generate it again (it is being handled).
   - It has appeared in recent_done → **first look at that intent's state (every entry carries one) to tell how it stopped, then decide**:
     · **done (ran to completion normally)**: already covered → do not re-dispatch it as is; whether it is a dead end depends on the conclusions of the facts it yields, not on the state; re-dispatch only when a [materially new mechanism] appears (a new fact/asset/parameter/clearly different approach), and state clearly in the summary how it differs from last time; rewording or "one more try might work" does not count — retrying is forbidden.
     · **exhausted (budget ran out, cut off halfway through exploring, only partial results written back) / blocked (model or network failure, essentially nothing explored)**: both ended badly midway with incomplete information — first use get_worker_trace / get_worker_output to see how far it actually got and where it got stuck, then choose from the following: close to a breakthrough but cut off by the budget → dispatch "continue from the previous progress"; a pure external failure that never really ran (blocked is often this) → re-dispatch the same direction directly; stuck at the same place every time → change the approach/direction. The basis is always the real progress in the trace, not the state itself.
   - A brand-new direction that no intent covers at all → generate it.
   - Every known direction is covered by an intent that is still open/running → generate nothing and finish directly (work is running/queued; wait for it to advance); but if only recent_done covers them, nothing is open/running any more and the goal is not met → per the hard floor at the top you must open a new one or dispatch a continuation.
   - **Depth takes priority over coverage**: coverage is a floor/acceptance item, not the exploration goal itself; once a high-value entry point is found (one that may lead to RCE/privilege escalation/data exfiltration), prioritize dispatching intents that [drive that path all the way through in depth], rather than spreading wide and shallow-testing asset after asset just to even out coverage.
   - **Keep the routes diverse; do not converge too early**: while the goal is not met, if the existing intents are all crowded onto the same route/entry point while a [fundamentally different] uncovered direction exists (another entry surface/another class of asset/another exploit chain), prioritize adding that divergent direction rather than adding synonymous intents on the same line (look at the substantive difference, not the wording); if that divergent direction is already covered by an existing intent, still do not generate it. The ideal is 2–3 routes with different mechanisms coexisting (e.g. "attack via the upload chain" and "attack via authentication bypass"), concentrating resources on one only after it delivers evidence of [getting closer to the goal]. **But diversity is always subordinate to the [Operation constraints] at the top**: for an entry surface/port/host/operation excluded by a constraint, never generate an intent, even if it is fundamentally different.

   **Serial exploit chains: dispatch step by step, do not split them into parallel intents.** For a strongly dependent serial chain (①→②→③, where each step depends on the actual output of the previous one): do not dispatch it all at once in parallel (a downstream step that cannot get a prerequisite which does not exist yet will only duplicate work/spin idle); use TodoWrite to record the whole chain as todos (one item per step), dispatch this round only the step whose "prerequisite is already satisfied" (usually the first step), and once it has produced a fact, on the next wake-up (the prompt will carry the todo list) dispatch the next step and mark the satisfied ones completed. Do not split "one and the same thing" into two intents ("confirm the trigger point" and "trigger the trigger point" are the same step); use multiple parallel intents only for [parallel, mutually independent] dimensions (such as enumerating several unrelated endpoints).

5. **Submit**: submit the selected new directions in bulk with [a single] add_intent call (the intents array, at most the 4 highest-value ones; do not call it repeatedly one by one):
   - **summary**: one natural-language sentence describing the direction (full address of the test target + what to do + why), not forced into a fixed category; deduplication relies mainly on comparing it with the existing intents.
   - **asset_ids**: ids of the target assets this direction will test/attack (pass them whenever possible; 0/1/many, taken from list_assets) — whenever the direction revolves around concrete assets (site/endpoint/parameter/host) be sure to pass them; they are used for coverage deduplication and for linking into the asset chain, and when it spans several assets pass all of them; leave it empty only for purely global recon with no concrete asset.
   - **parent_ids**: which upstream nodes this direction was synthesized from (optional; 0/1/many) — when several facts combine into one intent pass all of them, when it derives from an upstream intent/finding pass that id too, and leave it empty for a brand-new top-level direction.

No duplicates, no padding; but when the goal is not met and an uncovered, deeper approach exists, dispatch what should be dispatched. Be concise, focused and efficient.`

func plannerSystem(goal, dataDir, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir)
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// triggers carries the concrete change(s) that fired this round — worker(s) done
// and/or finding(s) reported (may be several — the engine debounces a burst; empty
// for time/heartbeat wakes). They are spelled out at the top of the prompt so the
// planner looks first at the actual change (which intent, its output/finding).
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, triggers []TriggerEvent, emit func(db.Activity)) (met bool, reason string, err error) {
	// cold-digest §2.3/§7: advance this task's planner-round counter, maintain the
	// cold_since_round stamps, and (if a threshold is hit) kick off background
	// compaction. Synchronous part is cheap (a few queries); the LLM compaction
	// runs in a detached goroutine so it never adds latency to this round.
	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetFindingRecorder(p.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// Domain tools + the base default toolset (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash).
	// When asset coverage is disabled, add_task_scope/list_untested_assets are dropped (kept out of the prompt).
	base := append(tsx.DropCoverageTools(tsx.PlannerTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// The key situation (just-finished intents + the pre-fetched full graph) now lives in [this round's user input] (see input
	// below); system keeps only the static planning body. Moving it out keeps system stable every round and cache-friendly; the cost is that in a
	// long round the situation may get squeezed by compaction (planner rounds are usually short, so the risk is low). situational is appended to input below.
	situational := renderTriggers(ts, triggers) + renderGraphOverview(tsx.graphOverviewData())
	// Task-level deadline / final mode (injected via ctx, see taskclock.go). In the final round the planner's task-timeout
	// wrap-up prompt is appended to this round's user input (along with situational) as [this round's operating instruction], so it only does the final
	// goal judgment and produces no new intents.
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Task final wrap-up (special instruction for this round; overrides the regular planning flow above)]: " + resolveTaskTimeoutWrapup("planner")
	}
	// This task's working directory <workDir>/tasks/<taskID>; create it up front.
	taskDir := ensureRunDir(p.workDir, taskID, 0)
	ctx = intercept.WithReviewContext(ctx, taskDir, intercept.ReviewBackground{})
	sysBody := plannerSystem(goal, p.workDir, taskDir)
	if p.wantConstraints() {
		sysBody += constraintBlock(ts) // inject the operation constraints (if any) into the system prompt to bound exploration
	}
	system, boundary := deferredSystem(sysBody, def)
	// The planner has no wall-clock budget of its own; with a deadline, MaxDuration is clamped to the time left so that a running
	// planning round enters wrap-up when the task expires (timeout → task-timeout prompt, turns → per-run prompt).
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // goes through the recording proxy so it is logged; loads the proxy CA to verify MITM-re-signed HTTPS certs
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is a separate egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty = direct.
		EnableWebSearch:       p.webSearch.Enabled,
		WebSearchBackend:      p.webSearch.Backend,
		BraveSearchAPIKey:     p.webSearch.BraveKey,
		TavilySearchAPIKey:    p.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: p.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  p.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   p.webSearch.DeepSeekModel,
		WebSearchProxy:        p.webSearch.Proxy,
		BashEnv:               proxyEnv(p.proxyAddr, p.proxyCACert), // Bash subcommands use the proxy and trust its CA by default
		WorkingDir:            taskDir,                              // this task's working directory <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(taskDir),
		MaxTurns:              p.maxTurns, // 0 = unlimited (configurable in agent management)
		MaxDuration:           maxDur,     // 0 = unlimited; with a deadline = time left until the deadline
		Compaction:            compactionConfig(p.compactionWindow()),
		// Planning todos shared across wake-ups: keeps a serial chain alive across rounds (the session is new, the store is not).
		Todos: p.todoFor(ts.ID()),
		// Hitting [this round's] turn budget → the SDK runs wrap-up: land the conclusions already reached this round (add_intent what
		// should be dispatched, prove_goal what can be proven, record serial chains with TodoWrite) rather than stop planning — the planner keeps being woken afterwards.
		// When clamped (by the task deadline), PromptByReason is used instead (see wrapupSettlementForTask).
		Settlement:   settle,
		NonStreaming: p.nonStreaming(), // uses Provider.Complete when the profile selects non-streaming
		MaxTokens:    p.maxTokens(),    // 0 = send no cap; the server-side default decides
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// Experimental: when enabled, noa takes over context compression (archives are kept persistently under <workDir>/noa/<SessionID>).
	noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
	enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, noaWarn(noaSession))
	// The situation (just-finished intents + the full graph) is now appended to this round's user input (see input below). The user message also
	// holds the instruction + the cross-wake-up todos (the todo is the model's own planning note and is regenerable, so the user turn is fine).
	// The lead-in has two variants depending on whether this round has a concrete change: change → point at the [Actual changes] block below; no change
	// (heartbeat patrol / hint / resume etc.) → do not falsely claim "the graph changed"; instead prompt a review of the running intents while here.
	lead := "A concrete change has just happened (see [Actual changes that triggered this round] below); plan the next step accordingly:"
	if len(triggers) == 0 {
		lead = "This round is a **scheduled patrol (heartbeat fired) / no concrete change signal** wake-up — the graph does not necessarily have new changes. While you are here, review the running intents: use steer_work to correct those that have made no progress for a long time or have drifted off course, and kill_work to cut losses on those whose whole direction is wrong; then judge the goals and decide whether to add directions:"
		// On a heartbeat/no-change wake-up, if the whole graph has no open or running intent left → exploration has stalled (no worker running,
		// no queued direction either). Tell the planner explicitly and force it to add new directions this round instead of idling a round after only reviewing running intents.
		if active, err := ts.HasActiveIntent(); err == nil && !active {
			lead = "This round is a **scheduled patrol (heartbeat fired)** wake-up, and there is currently **no open or running intent at all** — no worker is running and no direction is queued, so exploration has stalled. You **must** produce this round one or more new intents that advance toward the goal and **do not duplicate** any existing intent in the graph (producing 0 intents is not allowed); first judge from the situation below whether the goal has been met, and if not, add directions immediately:"
		}
	}
	input := lead + situational + "\n\nBased on the situation above, judge the goals. When a goal has been [truly met] (the goal outcome has been obtained / the target vulnerability has been confirmed), mark such goals one by one with prove_goal. **Hard floor: whenever the goal is not yet met and there is currently no open or running intent at all (frontier_open=0 and running_intents is empty), this round must produce at least one intent that advances toward the goal — at that point there is no running work to wait for and no queued direction, so producing 0 intents = the task stalls. Only when open/running intents are already making progress, or the goal has been met, may this round produce no new intent.**" +
		renderPlannerTodos(opts.Todos.List())
	// MaxDuration now interrupts the running tool at the wall-clock deadline and enters wrap-up in place (on the live ctx), so a round that
	// hangs no longer bypasses wrap-up and no external hard ctx backstop is needed. ctx only carries pause / kill / shutdown.
	_, _, err = captureRun(ctx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
