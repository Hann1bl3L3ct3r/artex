package agent

import (
	"log"
	"path/filepath"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/noaadapter"
)

// noaWarn returns a diagnostics sink tagging non-fatal noa messages with the
// session, routed through the package logger (agents have no per-instance one).
func noaWarn(session string) func(string) {
	return func(msg string) { log.Printf("[noa] %s: %s", session, msg) }
}

// noa is the "model-driven context compression" mechanism introduced in norma v0.4.0; as an experimental platform feature the user toggles it
// in the system settings. It is mutually exclusive with the built-in compaction: noaadapter.Enable is the only entry point and attaches, in one go,
// the context manager (Compactor), the Compress tool and three resident prompt sections; not calling Enable means it is off
// (the built-in compaction works as usual). The toggle is resolved by the noaEnabledFn injected into each agent and read once per
// run, so switching only affects runs started afterwards and no agent needs to be rebuilt.

// enableNoa wires noa into opts when the resolver reports it enabled. archiveRoot is the persistent base directory for the compressed originals
// (the global workDir; every agent lands under <workDir>/noa instead of being scattered across task/intent directories), and sessionID
// names the archive subdirectory beneath it (globally unique, so there are no clashes within the same base directory).
//
// noa is experimental: a failure to wire it in must not interrupt a real task. On error it reports via onWarn and falls back to the built-in compaction.
// On success it clears opts.Compaction, so that agentcore does not warn that "two context managers are set at the same time".
func enableNoa(opts *agentcore.Options, enabled func() bool, archiveRoot, sessionID string, onWarn func(string)) {
	if enabled == nil || !enabled() {
		return
	}
	if opts.OnWarn == nil {
		opts.OnWarn = onWarn
	}
	if err := noaadapter.Enable(opts, noaadapter.Options{
		ArchiveBaseDir: filepath.Join(archiveRoot, "noa"),
		SessionID:      sessionID,
		OnWarn:         onWarn,
	}); err != nil {
		if onWarn != nil {
			onWarn("failed to enable noa compression, falling back to built-in compaction: " + err.Error())
		}
		return
	}
	// Compactor overrides Compaction, but agentcore warns every time both are set; clear it explicitly.
	opts.Compaction = nil
}
