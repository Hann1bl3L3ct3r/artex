package db

import "fmt"

// legacyBuiltinPrefix is the name/note prefix that builds before the English
// translation gave their seeded rules. It is matched against persisted rows, so it
// has to stay in its original spelling.
const legacyBuiltinPrefix = "[内置]"

// hanPattern is a POSIX regex matching any CJK ideograph (U+4E00..U+9FFF).
const hanPattern = "[一-鿿]"

// LocalizeBuiltinRules renames the built-in intercept and asset-intercept rules that
// an older, Chinese-language build seeded into an existing database. The seeds are
// gated by one-shot flags, so without this an upgraded database would keep showing
// the Chinese rule names and returning the Chinese deny messages forever.
//
// A rule is recognised by its unchanged pattern plus the legacy name prefix, so rules
// the user renamed are left alone; a message is replaced only while it still contains
// Chinese, so an edited English message survives. Enabled state, priority and action
// are never touched. Idempotent: a database seeded in English matches nothing.
func (d *DB) LocalizeBuiltinRules() error {
	type text struct{ pattern, name, message string }
	var rules []text
	for _, r := range defaultInterceptRulesV1() {
		rules = append(rules, text{r.pattern, r.name, r.message})
	}
	for _, r := range defaultInterceptRulesV2 {
		rules = append(rules, text{r.pattern, r.name, r.message})
	}
	rules = append(rules, text{deleteEndpointPathPattern, deleteEndpointRuleName, deleteEndpointRuleMessage})
	for _, r := range rules {
		if _, err := d.Exec(`
UPDATE intercept_rules
   SET name = $2,
       message = CASE WHEN message ~ $4 THEN $3 ELSE message END
 WHERE pattern = $1 AND left(name, char_length($5)) = $5`,
			r.pattern, r.name, r.message, hanPattern, legacyBuiltinPrefix); err != nil {
			return fmt.Errorf("localize intercept rule %q: %w", r.name, err)
		}
	}
	for _, r := range defaultAssetInterceptRules {
		if _, err := d.Exec(`
UPDATE asset_intercept_rules
   SET note = $3
 WHERE kind = $1 AND pattern = $2 AND builtin AND left(note, char_length($4)) = $4`,
			r.kind, r.pattern, r.note, legacyBuiltinPrefix); err != nil {
			return fmt.Errorf("localize asset intercept rule %q: %w", r.pattern, err)
		}
	}
	return nil
}
