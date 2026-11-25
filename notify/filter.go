package notify

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Filter is the contract of the notification_channels.filter JSONB column: the filter
// conditions of a channel instance. All fields are optional, and the default is "no
// filtering" - which is exactly the fallback semantics for malformed config, see ParseFilter.
type Filter struct {
	// MinSeverity is the minimum severity threshold (low/medium/high/critical); empty = no threshold.
	MinSeverity string `json:"min_severity"`
	// Empty TaskIDs / AssetIDs arrays mean unrestricted; non-empty ones require the event to intersect them.
	TaskIDs  []int64 `json:"task_ids"`
	AssetIDs []int64 `json:"asset_ids"`
	// An empty VulnClassInclude accepts everything; non-empty requires vulnclass to hit any of its keywords.
	// Hitting any VulnClassExclude keyword excludes the event (exclude takes priority over include).
	// Matching is by case-insensitive substring - safer than regex: a user's bad regex cannot make the channel fail silently.
	VulnClassInclude []string `json:"vulnclass_include"`
	VulnClassExclude []string `json:"vulnclass_exclude"`
	// OnStatusChange decides whether the channel receives finding status-change events (only meaningful in realtime mode).
	OnStatusChange bool `json:"on_status_change"`
}

// ParseFilter parses the channel filter config.
//
// **It never returns an error.** This is a deliberate design choice: malformed filter
// config always degrades to the zero-value Filter (= no filtering = everything matches),
// because for a finding notification system, **pushing one extra message is far better than
// silently dropping one high-severity finding**. Turning a parse failure into "no push"
// gives the user a channel that looks configured but pushes nothing - the worst failure mode.
func ParseFilter(raw []byte) Filter {
	var f Filter
	if len(raw) == 0 {
		return f
	}
	// On parse failure f stays the zero value, i.e. no filtering.
	_ = json.Unmarshal(raw, &f)
	return f
}

// ValidMinSeverity reports whether s is a valid severity threshold (the empty string means no threshold).
func ValidMinSeverity(s string) bool {
	if s == "" {
		return true
	}
	_, ok := severityRank[s]
	return ok
}

// Validate checks the **value-restricted** fields of the filter config; called when saving a channel.
//
// Why this must be blocked at write time: Match's verdict for an unknown threshold is
// `rank >= 0`, which is always true - meaning one typo in min_severity ("hgih") makes the
// filter **fail silently** into "push everything". That is consistent with this package's
// trade-off of "rather push too much than miss one" (nothing is missed), but the consequence
// is that the user believes they are doing tiered pushing while actually pouring every
// finding into the group, with no sign at all that the config is wrong. This kind of
// "silent degradation" is exactly what should be blocked at the entry point.
//
// Note that Validate is only used on the **write** path. The read path still goes through
// ParseFilter's lenient semantics, so bad values already present in historical data do not
// make the whole channel unreadable.
func (f Filter) Validate() error {
	if !ValidMinSeverity(f.MinSeverity) {
		return fmt.Errorf("invalid minimum severity %q; valid values: low / medium / high / critical, or leave empty for no threshold", f.MinSeverity)
	}
	return nil
}

// Match decides whether an event should be delivered to a channel with this filter.
//
// **It never returns an error**, for the same reason as ParseFilter: any internal anomaly is treated as a "match".
// Decision order: event kind → severity threshold → task/asset scope → vulnerability class keywords.
func Match(f Filter, s Snapshot) bool {
	// Status-change events are only received by channels that explicitly opt in. Off by
	// default, because the vast majority of users expect "push" to mean "a new finding was
	// discovered", not a running log following every status transition.
	if s.Kind == EventFindingStatusChanged && !f.OnStatusChange {
		return false
	}
	if !AtLeast(s.Severity, f.MinSeverity) {
		return false
	}
	if len(f.TaskIDs) > 0 && !slices.Contains(f.TaskIDs, s.TaskID) {
		return false
	}
	if len(f.AssetIDs) > 0 && !intersectsInt(f.AssetIDs, s.AssetIDs) {
		return false
	}
	// Exclude takes priority: hitting any exclude keyword is out, even if the include list is hit too.
	if len(f.VulnClassExclude) > 0 && containsAnyFold(s.VulnClass, f.VulnClassExclude) {
		return false
	}
	if len(f.VulnClassInclude) > 0 && !containsAnyFold(s.VulnClass, f.VulnClassInclude) {
		return false
	}
	return true
}

func intersectsInt(a, b []int64) bool {
	// A linear scan is enough for small sets; both sides are on the order of "a few dozen
	// hand-picked entries", so building a map costs more than it gains.
	for _, v := range b {
		if slices.Contains(a, v) {
			return true
		}
	}
	return false
}

// containsAnyFold reports whether s contains any of the keywords (case-insensitive).
func containsAnyFold(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw != "" && strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
