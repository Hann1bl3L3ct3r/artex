package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// goalsDefaultTmpl is the built-in EDITABLE body (section [A]) of the goals-decomposer
// prompt, seeded into agent_prompts. No template vars are used today.
const goalsDefaultTmpl = `You are a penetration-testing goal decomposer. Your job is to identify, from the user's input, **the final outcomes to be achieved**, not to plan attack steps.

**Step one (do this before splitting goals): extract operation constraints**
From the "task goal / task description", identify the operator's explicit rules about [which operations may and may not be performed], and record them one by one by calling set_constraints (if the description and goal involve no operation constraints, you may skip extracting operation constraints):
- type=deny: forbidden operations (e.g. "do not scan ports", "no write/delete operations against production", "no brute forcing", "do not touch a certain subdomain").
- type=allow: an explicitly allowed/limited range of operations (e.g. "passive recon only", "only against a certain domain").
- A constraint ≠ a goal, and ≠ an attack step either: it is a rule about the boundary of operational behavior.
- **Constraints must be [self-contained, with the concrete target written out]**: replace **referring expressions** such as "the current target / the current port / the current IP / the current domain / this site" with the **concrete values** from the task goal/description. Constraints are injected on their own into the prompts of the execution phase; out of context, it is impossible to tell what a referring expression points to.
  Example: the goal is https://abc.example.net → write "only abc.example.net may be tested" rather than "only the current target may be tested"; "test only target port 443, do not scan other ports" rather than "test only the current port". If the original text only says "the current target" but the target address is clear, fill the address in.
- **Record only constraints that the goal/description [explicitly states or emphasizes]; inventing constraints is strictly forbidden**; when unsure of the type, use deny (more conservative).
- If the goal/description really contains no operation constraint at all, do **not** call set_constraints.
After recording the constraints (if any), carry on with the goal splitting below.

**Goal = a final deliverable/verifiable outcome**

**What is not a goal (must not be listed as a sub-goal)**:
- Information gathering, recon, endpoint scanning
- The vulnerability analysis and verification process
- Attack steps, exploitation techniques
- Result verification steps

**Splitting principles**:
- The user describes only one final goal → output one
- There are several **mutually independent** final deliverables → list them separately
- Annotate vulnclass where a goal maps to a clear vulnerability class; leave it empty for information-gathering/business-logic goals
- Inventing goals the user did not mention is strictly forbidden

Call set_goals to submit the result.`

// goalsScopeTail is the code-owned tail appended after the editable goals body
// WHEN an asset store + task context are available. It teaches the decomposer to
// also lift the explicit asset scope out of the goal/description and register it
// via add_task_scope. Kept in code (not the DB-editable body) so it always applies
// on released DBs and can't be edited away — same pattern as the trafficTool tail.
const goalsScopeTail = `

**Additional duty: register the test asset scope**
Besides splitting goals, you must also identify the **explicitly given test asset scope** in the "task goal / task description" and register it by calling add_task_scope (it is this task's authorization boundary and also the denominator of asset test coverage). **Minimal-scope principle: register only the one target the user explicitly pointed at; never widen it on your own.**
- The target is a URL or an address with a hostname (e.g. https://xxx.example.com/path, app.example.com) → take its **full hostname**: kind=subdomain, value=the full hostname.
  Example: target https://a1b2c3.lab.example.net/path → kind=subdomain, value=a1b2c3.lab.example.net (**not** example.net).
  It is **strictly forbidden** to shrink a hostname that has a subdomain down to the root domain — registering the whole example.com on seeing xxx.example.com widens the scope beyond the user's target and violates the minimal-scope principle.
- Only when what the user gave is a **bare root domain with no subdomain at all** (e.g. simply example.com), or the user explicitly says "the whole site / all subdomains / the entire domain" → use kind=root_domain, value=example.com.
- A plain IP or network range → kind=ip / cidr, value=the IP or CIDR.
- Do **not** register a company scope (company) — the task has only just been created and the asset system usually does not have this company yet, so it cannot be registered; company-level scope is left to the later plan phase.
Other rules:
- Register only scope that is **explicitly written in the goal/description**; inventing or inferring domains/IPs that were not mentioned is strictly forbidden.
- In reason, briefly state which sentence it is based on, to make auditing easier.
- If the goal/description contains no explicit asset scope at all, do **not** call add_task_scope.
First register the scope with add_task_scope (if any), then call set_goals to submit the goals.`

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoals asks the LLM to break a pentest task goal into discrete,
// independently-verifiable objectives (each becomes a goal node). Returns nil if
// no provider is configured or the call yields nothing — the caller then falls
// back to a rule-based split so goal nodes always exist.
//
// prov is supplied by the caller (rather than built here from a Config) so goal
// decomposition rides the SAME provider instance as the rest of the engine — it
// shares the rate limiter, gets recorded by llmrec, and participates in LLM
// failover instead of quietly bypassing all three.
//
// desc is the task's free-text description (background: target scope / number of flags / rules of engagement, etc.).
// It is fed alongside the goal so the decomposer no longer splits blind — the
// prompt still forbids inventing anything the two texts don't state.
//
// emit, when non-nil, receives every LLM step (thinking/tool_use/result) with
// Worker="planner" so the round-0 goal-decomposition activity is visible in the UI.
//
// as + taskID, when non-nil/positive, wire the add_task_scope tool so the
// decomposer can register the explicit asset scope it extracts from the goal.
//
// ts is the task's exploration store: set_goals writes the decomposed goal nodes
// straight into it (the same managed tool the main agent uses to add goals at
// runtime). The returned specs are read back from the store so callers can emit
// per-goal activity and detect the "LLM produced nothing" case for their fallback.
func DecomposeGoals(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	return DecomposeGoalsWithProvider(ctx, prov, dataDir, goalText, desc, as, ts, taskID, false, 0, emit)
}

// DecomposeGoalsWithProvider is the task-runtime variant used when a task has an
// ordered provider chain. It preserves the same tools and write behavior while
// letting the caller own provider selection/failover. maxTokens is the profile's
// per-reply output cap (0 = send none).
func DecomposeGoalsWithProvider(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, nonStreaming bool, maxTokens int, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	// Goal decomposition is a one-shot call: no transcript store is attached, so agentcore does not put a
	// session id on ctx (it only does so when there is a writer, see agentcore.Prompt). But gateways that do prompt caching /
	// sticky routing by a session-id header (opencode zen returns 400 MissingSessionID outright when x-opencode-session
	// is missing) read exactly this value from ctx — without it you get "chat works, decomposition 400s".
	// Attach a stable id explicitly: decomposition requests of the same exploration share it (good for cache hits), and its name
	// does not clash with planner/worker, so llmrec.parseSession can attribute it correctly.
	if ts != nil {
		ctx = transcript.WithSessionID(ctx, fmt.Sprintf("exp%d-goals", ts.ID()))
	}
	// worker="goals" tags the goal nodes' provenance; ts/taskID let set_goals link
	// each goal under the task root. This is the catalog's real set_goals tool, so a
	// web-edited description/schema on it applies here too.
	tsx := &ToolSet{as: as, ts: ts, taskID: taskID, worker: "goals"}
	// Description rides in the user message (same channel as the goal), NOT via the
	// {{.EngagementDescription}} template var — else a prompt that references the var
	// would inject the description twice. System prompt stays pure static instructions.
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{DataDir: dataDir, Now: nowStr()})
	// set_constraints is always available (it does not depend on the asset store): the body already contains the "extract operation constraints, then split goals" step
	// (its wording can be changed on the agent edit page); here we only need to wire up the tool.
	tools := []actool.CoreTool{tsx.setGoals(), tsx.setConstraints()}
	// Wire add_task_scope only when we have a real asset store + task to write to.
	// The scope-extraction tail is appended in lockstep so the prompt never asks for
	// a tool that isn't present.
	if as != nil && taskID > 0 {
		tools = append(tools, tsx.addTaskScope())
		sys += goalsScopeTail
	}
	userMsg := "Task goal:\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\nTask description (background information; may include the target scope / number of flags / rules of engagement; for reference only, do not invent anything it does not mention):\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  tools,
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		// The 3 steps (extract constraints → register scope → split goals) each need one tool call; allow enough turns so set_goals is not missed before the end.
		MaxTurns:     8,
		NonStreaming: nonStreaming, // uses Provider.Complete when the profile selects non-streaming
		MaxTokens:    maxTokens,    // 0 = send no cap; the server-side default decides
	}, userMsg, captureEmit)
	// set_goals persisted the goals directly; read them back so the caller sees what
	// was written (empty slice ⇒ the LLM produced nothing ⇒ caller falls back).
	if ts == nil {
		return nil
	}
	nodes, _ := ts.ListByKind(db.KindGoal, 10000)
	var out []GoalSpec
	for _, n := range nodes {
		var p struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if strings.TrimSpace(p.Text) != "" {
			out = append(out, GoalSpec{Text: p.Text, VulnClass: p.VulnClass})
		}
	}
	return out
}
