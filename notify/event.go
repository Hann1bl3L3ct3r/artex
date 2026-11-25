package notify

// Snapshot is the contract of the notification_events.snapshot JSONB column. The writer is
// the db layer's finding-persist transaction; the readers are the server layer's delivery
// engine and filter matching. It is defined in this package because it is a payload of the
// "notification domain": db only serializes it and does not understand the fields.
//
// Why the finding fields are stored redundantly instead of looked up at render time: a
// finding can later be renamed, re-rated or change status, while the pushed content should
// reflect the conclusion **at the time of the event** - a lookup would yield the dangerously
// misleading "later changed to low". It also means fan-out and rendering do not have to
// JOIN the findings/tasks/assets tables.
type Snapshot struct {
	// Event kind: finding_created / finding_status_changed
	Kind      string  `json:"kind"`
	FindingID int64   `json:"finding_id"`
	TaskID    int64   `json:"task_id"`
	VulnClass string  `json:"vulnclass"`
	Name      string  `json:"name"`
	Severity  string  `json:"severity"`
	Summary   string  `json:"summary"`
	AssetIDs  []int64 `json:"asset_ids"`
	// Non-empty only when kind=finding_status_changed.
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
}

// Item is one finding to be pushed, for channels to render.
type Item struct {
	FindingID int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string
	// Assets holds the resolved asset display names (e.g. domain/IP). Filled in by the
	// server layer - this package never touches the database and cannot get the names.
	Assets []string
	// DetailURL is the link back to the finding detail; empty means public_base_url is not
	// configured, and it is omitted when rendering.
	DetailURL string
	// Status-change events only; when both are non-empty it renders as "Pending → Fixed".
	FromStatus string
	ToStatus   string
}

// IsStatusChange reports whether the item is a status-change event.
func (i Item) IsStatusChange() bool { return i.FromStatus != "" || i.ToStatus != "" }

// Title returns the item's display title: the human-assigned name first, falling back to
// the vulnerability class vulnclass, and a placeholder when both are empty - an empty title
// is never emitted.
func (i Item) Title() string {
	if i.Name != "" {
		return i.Name
	}
	if i.VulnClass != "" {
		return i.VulnClass
	}
	return "(unnamed finding)"
}

// Message is the full content of one channel send.
type Message struct {
	// Length 1 for a single push; a whole batch for a digest push.
	// An empty slice is invalid; the caller must guarantee at least one item.
	Items []Item
	// When Batch=true it is rendered as a digest message (different title, with the time
	// window and item count).
	Batch bool
	// WindowMinutes is the digest period in minutes, used only when Batch=true for the
	// "last N minutes" wording. It is deliberately passed in explicitly from config rather
	// than computed with time.Since at render time: rendering stays deterministic, which
	// keeps it testable.
	WindowMinutes int
	// HomeURL is the platform console address (the global public_base_url); when empty no
	// console link is included.
	HomeURL string
}
