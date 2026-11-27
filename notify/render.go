package notify

import (
	"strings"
	"unicode/utf8"
)

const ellipsis = "…"

// TruncateBytes truncates s to at most max bytes, guaranteeing the result is valid UTF-8
// and no character is cut in half.
//
// Why it must cut on character boundaries: WeCom group-bot markdown has a hard limit of
// 4096 **bytes** (not characters), and a CJK character takes 3 bytes. Slicing by raw bytes
// would cut a multi-byte character in half and produce invalid UTF-8 - the platform either
// rejects the whole message or shows garbage boxes. The approach here is to walk back from
// the budget position to the nearest rune start byte (utf8.RuneStart detects continuation
// bytes 0b10xxxxxx).
//
// max<=0 means unlimited. An ellipsis is appended after truncation, unless max is too small
// to hold the ellipsis.
func TruncateBytes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	budget := max - len(ellipsis)
	suffix := ellipsis
	if budget < 0 {
		// max is shorter than the ellipsis: drop the ellipsis and truncate plainly, so the
		// result does not end up exceeding max.
		budget = max
		suffix = ""
	}
	cut := budget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// OneLine collapses multi-line text into a single line: it folds all whitespace, then
// truncates by character count. Used for the title line of IM messages - summaries often
// contain newlines, and putting them straight into a table/title breaks the layout.
// max<=0 means no length limit.
func OneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	return TruncateRunes(s, max)
}

// TruncateRunes truncates s to at most max characters (not bytes), appending an ellipsis
// when it is exceeded. max<=0 means unlimited.
//
// The difference from TruncateBytes is the platform's unit: WeCom limits by bytes, Telegram
// by character count. Using the wrong unit raises no error, it only gets the message cut far
// shorter than expected (1 CJK character = 3 bytes, so cutting 4096 by bytes leaves only
// about 1365 characters), so both functions must stay and be chosen per channel.
func TruncateRunes(s string, max int) string {
	if max <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + ellipsis
}

// TruncateHTML truncates an HTML fragment by character count and guarantees no half tag is
// produced.
//
// Truncating HTML by characters directly cuts out broken tags like `<a href="htt`; the
// platform parser either errors out and rejects the whole message, or swallows the following
// body as an attribute value. The approach here: truncate by characters first, then check
// whether the tail has an unclosed `<`, and if so back up to before it.
//
// No tag balancing (completing </b> and the like) is done: Telegram's HTML parser closes
// unclosed tags automatically, while implementing balancing ourselves would mean handling
// quotes in attributes, comments and self-closing tags - complexity out of proportion to
// the benefit.
func TruncateHTML(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	cut := TruncateRunes(s, max)
	// If the tail is a fragment starting with `<` (no `>` after the last `<`), back up to before the `<`.
	if lt := strings.LastIndex(cut, "<"); lt >= 0 && !strings.Contains(cut[lt:], ">") {
		cut = cut[:lt]
	}
	// If the tail is a cut-off HTML entity (e.g. `&amp;` cut to `&amp`), back up as well.
	// In a parser that only accepts whole entities, an entity fragment can get the **entire
	// message** rejected - a digest message over the length limit is common anyway, and it
	// is not worth losing the whole notification over this.
	if amp := strings.LastIndex(cut, "&"); amp >= 0 && !strings.Contains(cut[amp:], ";") {
		cut = cut[:amp]
	}
	return cut
}

// packItemCount computes how many items fit **in full** within the budget, so digest
// messages can be packed by whole items.
//
// Why whole items rather than rendering everything and then truncating: truncation makes
// the trailing items vanish into thin air while their delivery records are still marked as
// delivered - invisible in the message, invisible in the delivery history, and the findings
// are simply gone. With whole-item packing, the items that do not fit stay in the database
// and become the next batch, and the kept the caller receives is the number of items this
// message actually delivered.
//
// Parameters: maxSize<=0 means unlimited; reserve is the amount set aside for the message
// head/tail; size does the measuring (platforms differ: WeCom/DingTalk by bytes, Telegram
// by character count - the wrong unit raises no error, it only squeezes multi-byte messages
// far below the limit); render turns item idx into its actual text - length varies with
// content and cannot be estimated.
//
// Returns at least 1 (as long as there are items). An extremely over-long single item must
// still be sent, with the caller's final truncation as the safety net, otherwise one
// over-long finding would keep the whole batch stuck forever.
func packItemCount(items []Item, maxSize, reserve int, footer string, size func(string) int, render func(Item, int) string) int {
	if maxSize <= 0 {
		return len(items)
	}
	budget := maxSize - reserve - size(footer)
	if budget < 0 {
		budget = 0
	}
	used := 0
	for i, it := range items {
		used += size(render(it, i))
		if used > budget && i > 0 {
			return i
		}
	}
	return len(items)
}

// byteSize / runeSize are the two measuring units for packItemCount; they are named so call
// sites do not carry bare func(s string) int closures, where it is hard to tell at a glance
// which unit is in use.
func byteSize(s string) int { return len(s) }
func runeSize(s string) int { return utf8.RuneCountInString(s) }

// assetLine renders the asset list as one line of display text; beyond limit entries the
// rest are omitted and the total is stated. A finding may be anchored to dozens of assets,
// and listing them all would blow up the message.
func assetLine(assets []string, limit int) string {
	if len(assets) == 0 {
		return ""
	}
	if limit <= 0 || len(assets) <= limit {
		return strings.Join(assets, ", ")
	}
	return strings.Join(assets[:limit], ", ") + " and more, " + itoa(len(assets)) + " in total"
}

// itoa is a short alias for strconv.Itoa, used only to assemble display text, to avoid
// importing strconv everywhere.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
