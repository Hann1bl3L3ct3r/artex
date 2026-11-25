package server

import (
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// Server-side resolution of the retry policy; see the LLM retry design doc. Of the five layers:
//   - connect / empty response / same-provider safety window "follow the endpoint": each LLM
//     profile can override the global default (a field left empty on the profile inherits the
//     global value; if the global one is unset too, the built-in default applies);
//   - circuit breaker / intent re-run are process-wide, with a single global copy.
//
// The global policy costs one DB read of one settings row, and every call site is on a
// low-frequency path (building a provider, work wrap-up, saving config), so another cache layer
// is not worth it; the circuit-breaker parameters are the exception -- they are read on every
// failure, so applyRetryPolicy pushes them to the Registry to hold.

// retryPolicy reads the global policy; a nil DB yields the zero policy (all
// layers on their built-in defaults).
func (s *Server) retryPolicy() db.LLMRetryPolicy {
	if s.m == nil || s.m.pg == nil {
		return db.LLMRetryPolicy{}
	}
	return s.m.pg.LLMRetryPolicy()
}

// resolveRetry layers one profile's override on top of the global policy and
// converts the result into the form agent.Config carries. Rules combine field by
// field, so a profile that only pins an interval still inherits the global count.
func resolveRetry(o db.RetryOverride, pol db.LLMRetryPolicy) agent.RetryConfig {
	connect := o.Connect.Or(pol.Connect)
	empty := o.Empty.Or(pol.Empty)
	stream := o.Stream.Or(pol.Stream)
	return agent.RetryConfig{
		// Counts keep their raw "0 = default / negative = off" semantics here: the SDK's
		// MaxRetries / EmptyResponseRetries are exactly isomorphic, so let it resolve them itself.
		ConnectAttempts: connect.Attempts, ConnectInterval: connect.Interval(),
		EmptyAttempts: empty.Attempts, EmptyInterval: empty.Interval(),
		StreamAttempts: stream.Attempts, StreamInterval: stream.Interval(),
	}
}

// applyProfileRetry fills cfg.Retry for a profile read from the DB.
func (s *Server) applyProfileRetry(cfg *agent.Config, p *db.LLMProfile) {
	if p == nil {
		return
	}
	cfg.Retry = resolveRetry(p.Retry, s.retryPolicy())
}

// Circuit-breaker (failover cooldown) defaults match llmpool's built-in ones -- they are only
// overridden here when the user configured a value. For the intent re-run defaults see
// modelErrorRetries / modelErrorRetryBackoff in engine.go.

// applyRetryPolicy pushes the process-wide layers of the policy into the objects
// that consume them on a hot path: the circuit-breaker registry. Called at
// startup and whenever the policy is saved.
func (s *Server) applyRetryPolicy() {
	pol := s.retryPolicy()
	if s.llmHealth != nil {
		s.llmHealth.SetPolicy(pol.Breaker.Attempts, pol.Breaker.Interval())
	}
}

// modelErrorRetryPolicy resolves the intent-level replay knobs (layer ⑤): how
// many times a model_error work is re-run and how long to back off between runs.
func (e *Engine) modelErrorRetryPolicy() (retries int, backoff time.Duration) {
	retries, backoff = modelErrorRetries, modelErrorRetryBackoff
	if e == nil || e.m == nil || e.m.pg == nil {
		return retries, backoff
	}
	rule := e.m.pg.LLMRetryPolicy().Intent
	if rule.Attempts != 0 {
		retries = max(rule.Attempts, 0)
	}
	if d := rule.Interval(); d > 0 {
		backoff = d
	}
	return retries, backoff
}

// emptyTurnNudgeLimit resolves how many empty-turn continuations one work may
// inject (see steerHooks.Stop). It deliberately reuses layer ②'s knob -- the "empty
// response retry count": the two are two means to the same end. The SDK layer handles "not a
// single content block" by resending the same request verbatim; this one handles "thinking
// only, with neither text nor tool calls" by appending an instruction so the model carries on
// from its existing thinking (a verbatim resend is pointless for an empty turn that is
// determined by the shape of the context). The emptiness criteria differ because the SDK goes
// by "was any event yielded" and a thinking delta is itself an event -- but what a user means
// by "retry empty responses N times" is "try again when the model produced nothing of
// substance", and only a single shared count across both layers matches that mental model.
//
// Read the global policy rather than one profile's override: a run may switch profiles midway
// through failover, and this is a total budget for the whole intent, so it should not change
// with the endpoint. Semantics are isomorphic to the SDK's emptyRetries():
// 0 = default defaultEmptyTurnNudges; -1 (negative) = empty-turn continuation off; >0 = use that value.
func (e *Engine) emptyTurnNudgeLimit() int {
	if e == nil || e.m == nil || e.m.pg == nil {
		return defaultEmptyTurnNudges
	}
	switch n := e.m.pg.LLMRetryPolicy().Empty.Attempts; {
	case n == 0:
		return defaultEmptyTurnNudges
	case n < 0:
		return 0
	default:
		return n
	}
}
