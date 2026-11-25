package agent

import (
	"strings"

	"github.com/Autumn-27/norma/harness"
)

// Wrap-up prompt (settlement prompt): when an agent is terminated because its [turns ran out (MaxTurns)] or it
// [timed out (run_seconds/MaxDuration)], the SDK's settlement phase injects this prompt so that the agent first
// persists what it identified but has not written back and then outputs a one-sentence summary, so nothing is left half-done.
//
// Each agent's wrap-up prompt can be overridden in the admin UI as needed (stored in agents.wrapup_prompt); when left empty the built-in
// default here is used. Only the [prompt body] is editable; which tools are disabled and how many turns wrap-up itself gets are code-fixed policy.

// WrapupOverride, if set, returns the stored wrap-up prompt for an agent key and
// whether a non-empty one exists. Wired by the server to the agents table (like
// PromptOverride for system prompts). nil / empty → the built-in default is used.
var WrapupOverride func(agentKey string) (string, bool)

// WrapupMaxTurnsOverride, if set, returns the admin-configured turn budget for the
// wrap-up phase of an agent and whether a positive one exists. Wired to the agents
// table. nil / ≤0 → the built-in per-agent default (wrapupTurnDefaults) is used.
var WrapupMaxTurnsOverride func(agentKey string) (int, bool)

// Built-in default wrap-up prompts, indexed by agent key. worker reuses the historically hard-coded settleWrapUpPrompt
// (defined in worker.go); planner/mainagent each have their own; anything else (custom agents) falls back to the generic one.
var wrapupDefaults = map[string]string{
	"worker":    settleWrapUpPrompt,
	"planner":   plannerWrapUpDefault,
	"mainagent": mainAgentWrapUpDefault,
}

// wrapupTurnDefaults: built-in defaults for the turn budget of each agent's wrap-up phase [itself] (overridable by an admin value >0).
// All get 10 turns, so the wrap-up phase has enough turns to persist. Anything else uses genericWrapupTurns.
var wrapupTurnDefaults = map[string]int{
	"worker":    10,
	"planner":   10,
	"mainagent": 10,
}

const genericWrapupTurns = 10

const plannerWrapUpDefault = "Your turn budget for this planning round is about to run out — note that only [this round] is ending; the system will wake you again to keep planning as the situation changes, the task is not terminating, and you do not need to wind up the whole plan here. Land the conclusions you have already reached this round so that the round is not wasted, but [do not pad out intents just for the sake of wrapping up] either (0 intents this round is still a perfectly normal outcome): (1) if you have already identified exploration directions that [should be dispatched right now], submit them in bulk with a single add_intent call (do not hold back what you have already thought through); (2) for goals proven met by some finding/fact, call prove_goal to mark them met (do not miss any); (3) if you have identified a serial exploit chain that needs to be done in steps, record it with TodoWrite so that dispatching can continue on the next wake-up. When done, end this round directly; no summary text is needed."

const mainAgentWrapUpDefault = "Your turn budget is about to run out and this interaction is about to end. Do not start any new exploration/operation. **In a single separate plain-text sentence**, summarize for the user the current progress, the key conclusions, and the suggested next step."

const genericWrapUpDefault = "You are about to be terminated because your budget is exhausted. First write back the results you have completed but not yet persisted, then **in a single separate plain-text sentence** summarize what you did and which key conclusions you reached (this sentence is shown as the result of this run)."

// WrapupDefault returns the built-in default wrap-up prompt for an agent key —
// used by the admin UI as the "restore default" value and empty-field placeholder.
func WrapupDefault(agentKey string) string {
	if d, ok := wrapupDefaults[agentKey]; ok {
		return d
	}
	return genericWrapUpDefault
}

// WrapupTurnsDefault returns the built-in wrap-up turn budget for an agent key —
// used by the admin UI as the "0 = default N" hint.
func WrapupTurnsDefault(agentKey string) int {
	if n, ok := wrapupTurnDefaults[agentKey]; ok {
		return n
	}
	return genericWrapupTurns
}

// resolveWrapup returns the effective wrap-up prompt: the DB override (if set and
// non-empty) over the built-in default.
func resolveWrapup(agentKey string) string {
	if WrapupOverride != nil {
		if t, ok := WrapupOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return WrapupDefault(agentKey)
}

// resolveWrapupTurns returns the effective wrap-up turn budget: a positive DB
// override over the built-in per-agent default.
func resolveWrapupTurns(agentKey string) int {
	if WrapupMaxTurnsOverride != nil {
		if v, ok := WrapupMaxTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return WrapupTurnsDefault(agentKey)
}

// wrapupSettlement builds the settlement config for an agent's run. Prompt and the
// turn budget are admin-editable per agent; disabled tools are code-owned policy so
// a user can't edit away the "stop probing" guardrail. Resolved fresh each run
// (reads DB live), so edits apply on the next run without a restart.
func wrapupSettlement(agentKey string, disabledTools []string) *harness.Settlement {
	return &harness.Settlement{
		Prompt:        resolveWrapup(agentKey),
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
}

// ---------- Task-level timeout wrap-up prompts (see the design doc on task-level timeout and wrap-up) ----------
//
// These are a [separate set] from the per-run wrap-up prompts: per-run means "the budget of this one run of yours is used up"; task timeout means
// "the whole task has expired and is about to end". The semantics are often opposite (especially for the planner: per-run says "do not stop, keep planning",
// task timeout says "time is up, stop planning and make the final judgment"). Configured only for worker/planner.

// WrapupTaskTimeoutOverride / …TurnsOverride: DB overrides for the task-timeout wrap-up prompt and turn count
// (wired to agents.task_timeout_wrapup_prompt / _max_turns, worker/planner only).
var (
	WrapupTaskTimeoutOverride      func(agentKey string) (string, bool)
	WrapupTaskTimeoutTurnsOverride func(agentKey string) (int, bool)
)

var taskTimeoutWrapupDefaults = map[string]string{
	"worker":  workerTaskTimeoutDefault,
	"planner": plannerTaskTimeoutDefault,
}

const workerTaskTimeoutDefault = "**The whole task has reached its timeout limit and is about to end** (this is not the budget of this run of yours; the entire exploration has run out of time). This is the last chance: (1) persist [everything] you have identified but not yet written back — insert_assets for new assets, record_fact for exploration conclusions/facts, report_finding for confirmed vulnerabilities; (2) do not start any new command/probe; (3) **finally, in a single separate plain-text sentence**, summarize your key conclusions on this intent."

const plannerTaskTimeoutDefault = "**The whole task has reached its timeout limit and is about to end** (not this round — the whole task is terminating). Based on [all] current facts and findings, make one final goal judgment: for goals proven met by evidence, call prove_goal to mark them met (do not miss any). **Do not generate any new intents** (an intent dispatched now would not be executed any more). Wind up as soon as the judgment is done; no summary text is needed."

// TaskTimeoutWrapupDefault returns an agent's built-in default task-timeout wrap-up prompt (used by the admin UI as placeholder / restore-default value).
func TaskTimeoutWrapupDefault(agentKey string) string {
	return taskTimeoutWrapupDefaults[agentKey] // not configured (mainagent/chat) → empty string
}

// resolveTaskTimeoutWrapup: DB override (non-empty) > built-in default. An empty string means the agent has no task-timeout prompt
// (not worker/planner); the caller should then fall back to the per-run prompt.
func resolveTaskTimeoutWrapup(agentKey string) string {
	if WrapupTaskTimeoutOverride != nil {
		if t, ok := WrapupTaskTimeoutOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return TaskTimeoutWrapupDefault(agentKey)
}

func resolveTaskTimeoutTurns(agentKey string) int {
	if WrapupTaskTimeoutTurnsOverride != nil {
		if v, ok := WrapupTaskTimeoutTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return resolveWrapupTurns(agentKey) // defaults to the per-run turn count
}

// wrapupSettlementForTask builds settlement for a worker/planner run that is aware
// of the task deadline. See §5 of the design doc:
//   - clamped=true  → this run is clamped by the task deadline: wrap-up due to Timeout = the task expired → task-timeout prompt;
//     wrap-up due to MaxTurns = the turns ran out first inside the clamped window with minutes of task time left → fall back to the per-run prompt.
//   - clamped=false → the task still has plenty of time: both reasons use the per-run prompt (i.e. it degrades to wrapupSettlement).
//
// The PromptByReason handed to the harness is picked on the spot at wrap-up time by the [actual] reason, so there is no build-time mismatch.
func wrapupSettlementForTask(agentKey string, disabledTools []string, clamped bool) *harness.Settlement {
	perRun := resolveWrapup(agentKey)
	st := &harness.Settlement{
		Prompt:        perRun, // fallback (also the value for both reasons when not clamped)
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
	if clamped {
		if tt := resolveTaskTimeoutWrapup(agentKey); tt != "" {
			st.PromptByReason = map[harness.TerminalReason]string{
				harness.ReasonTimeout:  tt,     // the task expired
				harness.ReasonMaxTurns: perRun, // turns ran out first, task time remains
			}
			st.MaxTurns = resolveTaskTimeoutTurns(agentKey)
		}
	}
	return st
}
