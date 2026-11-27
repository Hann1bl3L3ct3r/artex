package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// weComMarkdownLimit is the hard limit on the markdown content of a WeCom group
// robot (in bytes, not characters). It is the tightest limit among all six channels
// and the main reason TruncateBytes exists.
const weComMarkdownLimit = 4096

// weComChannel implements the WeCom group robot.
//
// Platform characteristics:
//   - It is the only one that authenticates via a key in the URL and does not
//     support signing -- so the webhook URL itself is the entire credential.
//   - markdown content is limited to 4096 **bytes**, and an over-long message is
//     rejected as a whole (not truncated). Chinese takes 3 bytes per character,
//     which means the body only has room for a bit over a thousand characters, so
//     it must be truncated on the client side.
//   - Rate limited to 20 messages/minute, likewise held back by client-side rate
//     limiting.
type weComChannel struct{}

func (weComChannel) Kind() string { return KindWeCom }

func (weComChannel) DefaultRatePerMin() int { return 20 }

// WeCom has only one credential, the Webhook (the key in the URL), and it does not
// support signing -- the whole URL is the entire credential, and no other field
// needs masking.
func (weComChannel) SecretKeys() []string { return []string{"webhook"} }

// WeCom has only the single Webhook field, which is both the destination and the
// credential, so there is no such thing as "credentials left behind after changing
// the address".
func (weComChannel) DestinationKeys() []string { return []string{"webhook"} }

func (weComChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("missing Webhook URL")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("invalid Webhook URL: %w", err)
	}
	return nil
}

func (c weComChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	// A digest batch can be very long (50 items x one line each + prefix) and easily
	// exceeds 4096 bytes. Truncation is done here instead of relying on the platform
	// to report an error: rejection means the whole batch is lost, while truncation
	// at least delivers the first several items.
	content, kept := markdownBody(m, weComMarkdownLimit)
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]any{"content": content},
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("failed to parse WeCom response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 45009 means the API call limit was exceeded -- the platform's rate-limit
		// window rolls, so retrying after backoff works, and it is explicitly
		// classified as retryable. Getting here means the client-side rate_per_min
		// is configured too aggressively; retrying is only a safety net, and the
		// real fix is to lower this channel's rate limit.
		if res.ErrCode == 45009 {
			return 0, fmt.Errorf("WeCom rate limited %d: %s", res.ErrCode, res.ErrMsg)
		}
		// 93000 means the webhook key is invalid -- a permanent failure that
		// retrying will not heal.
		return 0, Permanent(fmt.Errorf("WeCom returned error %d: %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}
