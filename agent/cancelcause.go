package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedByUser = cause("paused_by_user", "user paused the task",
		"The user paused the task through the task control endpoint (POST /api/tasks/{id}/control, action=pause). This Planner/Worker run was cancelled deliberately; running intents return to the frontier (open) and are re-claimed and executed from scratch once the task is resumed")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "orchestration agent paused the task",
		"The orchestration agent called the pause_task tool to pause this task. This Planner/Worker run was cancelled deliberately; running intents return to the frontier (open) and are executed again after the task is resumed")
	AbortTaskDeleted = cause("task_deleted", "task was deleted",
		"The task is being deleted (DELETE /api/tasks/{id}); the deletion barrier has cancelled the task's running Planner, Workers and main agent; the result of this run will no longer be used")
	AbortPausedOnReload = cause("paused_on_reload", "backend restored the paused state",
		"On startup the backend restored the task's paused state from the status persisted in the database. This run was cancelled; normally no agent is running during the restore phase")
	AbortGoalMet = cause("goal_met", "Planner judged the task goal met",
		"The Planner judged the task goal met and set the task to done, then cancelled the Workers that were still running; those intents are marked stopped rather than failed")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "timeout wrap-up grace period ran out",
		"After the task reached its timeout, the engine waited for running Workers to wrap up gracefully, but the 90-second drain grace period was not enough, so a hard cancel was performed; the intents are marked exhausted, and facts and assets already written during wrap-up are kept")

	// Per-work context.
	AbortKilledByPlanner = cause("killed_by_planner", "Planner terminated this intent",
		"The Planner called kill_work to terminate this intent deliberately, usually because it drifted off course or is no longer worth continuing; the intent is marked stopped and will not be re-claimed automatically")
	AbortWorkPausedByUser = cause("work_paused_by_user", "user paused this Worker intent",
		"The user paused the running Worker. This call was cancelled and the intent moved to paused; all recorded intents, facts, findings and activity records are kept, and the intent is executed from scratch after it is resumed")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "user deleted this Worker intent",
		"The user deleted the running Worker. This call was cancelled; once the Worker leaves the write section, the server handles the intent according to the deletion mode the user chose - a soft delete only marks it as deleted and keeps all of its output, while a hard delete cascades to remove the intent and the downstream nodes supported only by it")
	AbortWorkFinished = cause("work_finished", "Worker ended normally, context released",
		"The Worker ended normally and the engine released its context resources in detachWork. This is not a run interruption; if it shows up in an interruption message, the cancellation raced with the completion event")
	AbortPausedRaceGuard = cause("paused_race_guard", "new runs refused while task is paused",
		"While the task is paused the engine refuses to hand out a new execution context, to prevent a race between claim and pause from letting a Worker start anyway; intents already claimed return to the frontier")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "user stopped this conversation turn",
		"The user clicked stop, deliberately aborting this turn of the main agent or conversation agent. Activity records already produced are kept, and the next message can be sent as usual")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "task pause aborted the main agent chat",
		"When the user paused the task, the running main agent conversation was cancelled along with it. Activity records already produced are kept; this turn's message is not replayed automatically after the task is resumed")
	AbortChatTurnFinished = cause("chat_turn_finished", "turn ended normally, context released",
		"This conversation turn ended normally and the server is releasing the turn's context resources. This is not a run interruption; if it shows up in an interruption message, the cancellation raced with the completion event")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "backend process is shutting down",
		"The backend process received SIGINT or SIGTERM and is restarting, updating or shutting down. All running agents are cancelled; after the restart, leftover running intents are reset to open and executed again")
	AbortRunHardTimeout = cause("run_hard_timeout", "per-run hard-timeout backstop triggered",
		"A single run exceeded its soft wall-clock budget plus the extra grace period, which means a model request or a tool did not return for a long time, so the normal turn-boundary wrap-up could not run. Focus on the last tool call that had not returned before the interruption")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "upstream context hit its deadline",
			"The upstream context hit its deadline, but whoever set it did not attach a named cause via WithTimeoutCause: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "canceller attached no named cause",
			"The upstream context was cancelled, but the canceller did not attach a named cause via context.WithCancelCause; register a cause in agent/cancelcause.go and wire it into that cancellation site", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}
