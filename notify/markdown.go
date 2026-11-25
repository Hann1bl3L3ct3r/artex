package notify

import (
	"fmt"
	"strings"
)

// This file holds the message rendering shared by the "Markdown family" channels (DingTalk, WeCom).
// Feishu uses card JSON, Telegram uses HTML, email uses HTML; each renders in its own adapter.

// maxAssetsShown is the maximum number of assets listed in a message. A finding may be
// anchored to dozens of assets; listing them all would blow up the message and carries no
// information - nobody reads the domains after the 4th one in an IM client.
const maxAssetsShown = 3

// maxSummaryRunes is how many characters the summary is compressed to. An IM message is a
// "go look at the details" prompt, not the report itself; the full content is in the platform.
const maxSummaryRunes = 120

// markdownReservedBytes is reserved for the message head (digest line + severity
// distribution + a possible truncation notice) and tail (platform link). When packing whole
// items, this part is deducted from the budget so the head and tail are never cut off -
// once they are, the reader cannot even tell "which batch this is, and how many items are not shown".
const markdownReservedBytes = 320

// markdownEscape escapes markdown metacharacters.
//
// Why this is mandatory: finding titles, summaries, classes and asset display names all come
// from **untrusted sources** - titles and summaries come from model output (the model reads
// the responses of the target under test), and an asset url is the full URL obtained from
// scanning (including a target-controlled query string). Without escaping, a finding titled
//
//	Login SQL injection\n[URGENT: click here to verify your account](http://attacker.tld)
//
// would render as a **clickable external link** in the security engineer's DingTalk/Feishu;
// and `![](http://attacker.tld/beacon)` would be fetched by the client at render time, which
// amounts to announcing "this finding has been viewed" and leaking the reader's IP. Even
// with non-malicious content, injected bold text or a quote block can push the critical
// findings below it past the fold.
//
// The escape set covers the characters for headings/links/emphasis/lists/quotes/strikethrough
// that change structure or produce clickable elements. `\` must be handled first, otherwise
// the backslashes added afterwards would be escaped again.
func markdownEscape(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		"`", "\\`",
		"*", `\*`,
		"_", `\_`,
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
		"!", `\!`,
		"#", `\#`,
		">", `\>`,
		"|", `\|`,
		"~", `\~`,
	)
	return replacer.Replace(s)
}

// markdownText collapses untrusted text into a single line and escapes it, for use in a
// markdown body. Single-lining is the other half besides escaping: a newline by itself can
// forge a new list item or quote block, and escaping characters cannot stop that.
func markdownText(s string, maxRunes int) string {
	return markdownEscape(OneLine(s, maxRunes))
}

// markdownTitle returns the message title (the IM platform's title bar / card title); the
// content is the **unescaped original text**.
//
// Escaping is deliberately not done here: this title is shared by renderers in four
// contexts - markdown bodies, Telegram's HTML, Feishu cards' plain_text, and the generic
// webhook's JSON and the email subject. Each context has different escaping rules (markdown
// escapes put into HTML leave visible backslashes, and put into JSON they pollute the
// data), so escaping must be the responsibility of each output side, see writeItem /
// feishuItemLines / telegramEscape. Markdown escaping was once added in the shared function,
// and as a result visible backslashes like `\(1\)` showed up in Telegram messages.
func markdownTitle(m Message) string {
	if m.Batch {
		return fmt.Sprintf("Findings digest · %d total", len(m.Items))
	}
	if len(m.Items) == 0 {
		return "Finding notification"
	}
	it := m.Items[0]
	return fmt.Sprintf("[%s] %s", SeverityLabel(it.Severity), OneLine(it.Title(), 0))
}

// markdownBody renders the message body and returns the body and the **number of items
// actually written**.
//
// The return value kept is the number of items this delivery actually got across; the
// caller uses it to mark only the first kept items as delivered - items kept out by the
// channel length limit must be left for the next batch instead of being marked successful
// along with the rest. This is exactly where "silent loss" comes from: the message was
// truncated, but the delivery records show everything delivered, and nowhere can you see
// that the second half was never sent.
//
// maxBytes<=0 means unlimited.
func markdownBody(m Message, maxBytes int) (string, int) {
	if !m.Batch {
		if len(m.Items) == 0 {
			return "", 0
		}
		var b strings.Builder
		writeItem(&b, m.Items[0], "", true)
		// A single message is sent even when over-long (the final truncation is the safety
		// net): partial information about a finding is better than sending nothing.
		return TruncateBytes(b.String(), maxBytes), 1
	}

	footer := ""
	if m.HomeURL != "" {
		footer = fmt.Sprintf("\n[View all in the platform](%s)\n", m.HomeURL)
	}
	kept := packItemCount(m.Items, maxBytes, markdownReservedBytes, footer, byteSize, func(it Item, idx int) string {
		var b strings.Builder
		writeItem(&b, it, fmt.Sprintf("%d. ", idx+1), false)
		return b.String()
	})

	items := m.Items[:kept]
	var b strings.Builder
	b.WriteString(markdownBatchIntro(m, items, len(m.Items)))
	for i, it := range items {
		writeItem(&b, it, fmt.Sprintf("%d. ", i+1), false)
	}
	b.WriteString(footer)
	return TruncateBytes(b.String(), maxBytes), kept
}

// markdownBatchIntro renders the opening of a digest message: time window, item count and
// severity distribution. With these, whoever receives the digest can judge whether this
// batch needs immediate attention without clicking into the platform.
//
// items are the entries that **actually fit**, total is the number this batch should have.
// When the two differ it must be stated explicitly "how many more are in the next message" -
// otherwise the reader would assume the number in the message head is everything, while the
// items that were never sent do not exist anywhere in the UI.
func markdownBatchIntro(m Message, items []Item, total int) string {
	var b strings.Builder
	if m.WindowMinutes > 0 {
		fmt.Fprintf(&b, "**New findings in the last %d minutes: %d**", m.WindowMinutes, total)
	} else {
		fmt.Fprintf(&b, "**New findings: %d**", total)
	}
	if extra := total - len(items); extra > 0 {
		fmt.Fprintf(&b, " (this message shows the first %d; the remaining %d will continue in the next message)", len(items), extra)
	}
	// Give the distribution by severity so the reader sees at a glance whether there are
	// critical items. Only the items **actually included in this message** are counted, so
	// that "Critical 3" matches the entries that can be counted below.
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", SeverityLabel(sev), n))
		}
	}
	if len(parts) > 0 {
		b.WriteString("\n" + strings.Join(parts, " · "))
	}
	b.WriteString("\n\n")
	return b.String()
}

// writeItem renders a single finding entry.
//
// prefix is used for the ordinal in a digest list; with single=true the full version is
// rendered (with summary and back-link), while in a digest list only a one-line summary is
// rendered - otherwise a 50-item digest would turn into a long document.
//
// All content from outside (title/class/assets/summary) goes through markdownText:
// single-lining + escaping. The back-link is assembled from the admin-configured
// public_base_url, is not untrusted content, and must be a clickable link, so it is
// emitted as-is.
func writeItem(b *strings.Builder, it Item, prefix string, single bool) {
	line := fmt.Sprintf("%s**%s · %s**", prefix, SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if !single {
		// Digest mode: shown on a single line, with compressed assets and summary following.
		var extras []string
		if a := assetLine(it.Assets, maxAssetsShown); a != "" {
			extras = append(extras, markdownText(a, 0))
		}
		if it.Summary != "" {
			extras = append(extras, markdownText(it.Summary, 60))
		}
		if len(extras) > 0 {
			line += " — " + strings.Join(extras, " · ")
		}
		b.WriteString(line + "\n")
		return
	}
	b.WriteString(line + "\n")
	if it.IsStatusChange() {
		fmt.Fprintf(b, "**Status change**: %s → %s\n",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		fmt.Fprintf(b, "**Type**: %s\n", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		fmt.Fprintf(b, "**Assets**: %s\n", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			fmt.Fprintf(b, "**Summary**: %s\n", s)
		}
	}
	if it.DetailURL != "" {
		fmt.Fprintf(b, "[View details](%s)\n", it.DetailURL)
	}
}
