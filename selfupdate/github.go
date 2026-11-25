package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Enabled reports whether online self-update is compiled into this build.
//
// It is forced OFF in this fork and is a const, not a setting: no config key,
// environment variable, or admin session can turn it back on without editing
// and rebuilding the source. Every online entry point (FetchLatest, Stage)
// checks it and refuses before touching the network, so this binary never
// reaches a remote release feed. Re-enabling online update means flipping this
// to true, re-pointing Repo at a trusted release source, and re-auditing the
// download/verify path.
const Enabled = false

// ErrDisabled is returned by every online-update entry point while Enabled is
// false.
var ErrDisabled = errors.New("online update is disabled: local builds do not check for or download remote versions")

// Repo remains a fixed source identifier; online access is disabled above.
// Keep the URL derived from it so a future reviewed source edit cannot leave
// a second, stale release source behind.
const Repo = "failsafe-security/artex"
const latestURL = "https://api.github.com/repos/" + Repo + "/releases/latest"

// allowedHosts restricts the hosts the upgrade chain may reach. Together with checkRedirect below,
// any hop redirected to a host outside the list fails immediately -- this is the first gate against DNS poisoning / a man-in-the-middle
// swapping out the binary; the second is the SHA256SUMS comparison.
var allowedHosts = map[string]bool{
	"api.github.com":                       true,
	"github.com":                           true,
	"objects.githubusercontent.com":        true, // object storage where release assets actually live
	"release-assets.githubusercontent.com": true,
	"raw.githubusercontent.com":            true,
}

// Release holds the fields of a GitHub Release that we care about.
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Assets      []Asset   `json:"assets"`
}

// Asset is one file attached to a Release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// NewClient builds an HTTP client that only accepts GitHub hosts. An empty proxy means a direct connection.
//
// The default Transport is deliberately not reused: the upgrade chain must enforce TLS with certificate verification and must not be
// affected by something like an InsecureSkipVerify set elsewhere.
func NewClient(proxy string) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if p := strings.TrimSpace(proxy); p != "" {
		if pu, err := url.Parse(p); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Minute, // downloads the whole package, so a per-request timeout must not kill it
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return checkURL(req.URL)
		},
	}
}

// checkURL enforces https + the host allowlist.
func checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-HTTPS URL: %s", u.Scheme+"://"+u.Host)
	}
	if !allowedHosts[strings.ToLower(u.Hostname())] {
		return fmt.Errorf("refusing non-GitHub host: %s", u.Hostname())
	}
	return nil
}

// FetchLatest queries the latest stable release.
//
// Disabled in this fork: it returns ErrDisabled without making any network
// request while Enabled is false.
func FetchLatest(ctx context.Context, c *http.Client) (*Release, error) {
	if !Enabled {
		return nil, ErrDisabled
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURL, nil)
	if err != nil {
		return nil, err
	}
	if err := checkURL(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "artex-selfupdate")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach GitHub (a global proxy can be configured in system settings): %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusTooManyRequests:
		// The unauthenticated GitHub API allows 60 requests per hour per IP, which is easy to hit behind a shared egress IP.
		return nil, fmt.Errorf("GitHub API rate limit hit (60 requests per hour); please try again later")
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("repository %s is not accessible or has not published a release yet", Repo)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GitHub returned %d", resp.StatusCode)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("failed to parse release: %w", err)
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return nil, fmt.Errorf("release is missing a tag")
	}
	return &rel, nil
}

// AssetName returns the release package name for the current platform, matching package_binary in build.sh:
// artex-<version>-<os>-<arch>.zip (the version carries no v prefix).
func AssetName(tag, goos, goarch string) string {
	return fmt.Sprintf("artex-%s-%s-%s.zip", strings.TrimPrefix(tag, "v"), goos, goarch)
}

// FindAsset looks up an asset in the Release by name.
func (r *Release) FindAsset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Asset{}, false
}
