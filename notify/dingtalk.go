package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// dingTalkChannel implements the DingTalk custom robot.
//
// Platform characteristics (which drive the implementation trade-offs here):
//   - Each robot is rate limited to 20 messages/minute, and anything beyond that is
//     silently dropped (HTTP may still be 200), so rate limiting must be done on the
//     client side; see DefaultRatePerMin.
//   - Security settings are one of three: signing / custom keywords / IP allowlist.
//     Signing is the only scheme that does not depend on message content, so only
//     signing is supported (a bare webhook with none of the three enabled is
//     supported too).
//   - Both success and failure return HTTP 200 and are told apart by errcode in the
//     body -- not checking errcode would record a failed delivery as a success.
type dingTalkChannel struct{}

func (dingTalkChannel) Kind() string { return KindDingTalk }

func (dingTalkChannel) DefaultRatePerMin() int { return 20 }

// DingTalk's Webhook URL carries the access_token and is itself a credential, so
// it is masked as a whole.
func (dingTalkChannel) SecretKeys() []string { return []string{"webhook", "secret"} }

// The destination is DingTalk's Webhook URL itself; changing the URL requires
// restating the signing secret for the new URL at the same time.
func (dingTalkChannel) DestinationKeys() []string { return []string{"webhook"} }

func (dingTalkChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("missing Webhook URL")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("invalid Webhook URL: %w", err)
	}
	return nil
}

// Send delivers one message. With a deep link and a single item it uses an
// ActionCard (with a button); otherwise it uses markdown.
func (c dingTalkChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	hook := cfgString(cfg, "webhook")
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, err := dingTalkSignedURL(hook, cfgString(cfg, "secret"), time.Now())
	if err != nil {
		return 0, Permanent(err)
	}

	title := markdownTitle(m)
	// DingTalk's markdown body has no explicit byte limit, but a cap is still applied
	// as protection against evidence fields ballooning abnormally.
	text, kept := markdownBody(m, 20000)

	var payload any
	if !m.Batch && len(m.Items) == 1 && m.Items[0].DetailURL != "" {
		payload = map[string]any{
			"msgtype": "actionCard",
			"actionCard": map[string]any{
				"title":          title,
				"text":           text,
				"btnOrientation": "0",
				"singleTitle":    "View details",
				"singleURL":      m.Items[0].DetailURL,
			},
		}
	} else {
		payload = map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"title": title, "text": text},
		}
	}

	raw, err := doJSON(ctx, "POST", endpoint, nil, payload)
	if err != nil {
		return 0, err
	}
	// DingTalk hides business errors inside a 200 response.
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("failed to parse DingTalk response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 301000 is a signature verification failure and 310000 is a keyword
		// mismatch -- both are configuration errors that retrying will not heal.
		return 0, Permanent(fmt.Errorf("DingTalk returned error %d: %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}

// dingTalkSignedURL appends the timestamp and sign parameters to the webhook
// following the official signing rules.
//
// Rule: string to sign = timestamp + "\n" + secret, the HMAC-SHA256 **key is also
// secret**, and the result is base64-encoded and then URL-encoded. timestamp is in
// milliseconds. When secret is empty the URL is returned unchanged, to support
// robots that do not have signing enabled.
func dingTalkSignedURL(hook, secret string, now time.Time) (string, error) {
	if secret == "" {
		return hook, nil
	}
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + secret))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	u, err := url.Parse(hook)
	if err != nil {
		// Do not pass err through: the error text from url.Parse carries the full
		// URL (including the access_token).
		return "", fmt.Errorf("failed to parse Webhook URL: %s", redactRequestTarget(hook))
	}
	q := u.Query()
	q.Set("timestamp", ts)
	q.Set("sign", sign)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// validateHTTPURL checks that the URL is usable and its scheme is supported, and
// applies the internal-network check to literal IP targets.
//
// Two points matter here:
//
//  1. **Error messages must be redacted**. What url.Parse itself returns is a
//     *url.Error whose Error() carries the **full original URL**, and for the
//     vendors in this feature the URL embeds the credential (DingTalk access_token,
//     WeCom key, Telegram bot token, Feishu hook id). This used to do a plain
//     `return err`, so the "malformed URL" error carried the credential out with
//     it, flowing into the 400 response of the test endpoint, the last_error
//     persisted on every delivery, the server logs and the delivery history API.
//
//  2. **Literal IPs are checked against internal ranges right away**, while domain
//     names are left to the dial stage (blockInternalDial is the final enforcement
//     point and also covers DNS rebinding). Doing it once here is so that the user
//     gets the hint when saving the configuration instead of waiting for the first
//     delivery to fail.
//
// Restricting the scheme is defensive: things like file:///gopher:// would make
// http.Client behave in unexpected ways (they are already stopped by the scheme
// check, but there is no reason to open up this surface).
func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("URL cannot be parsed (%s)", redactRequestTarget(raw))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http/https is supported, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("missing hostname")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isBlockedDialIP(ip) && !allowLocalTargets() {
		return fmt.Errorf("refusing to deliver to loopback/link-local address %s (to deliver to a local service, set %s=1)", ip, AllowLocalTargetsEnv)
	}
	return nil
}
