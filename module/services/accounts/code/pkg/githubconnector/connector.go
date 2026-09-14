package githubconnector

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultBaseURL is the public GitHub REST API host. GitHub Enterprise Server
// installations override it via WithBaseURL.
const DefaultBaseURL = "https://api.github.com"

// DefaultOAuthBaseURL is where GitHub serves the user-token exchange. It is not
// the API host: an Enterprise Server deployment overrides both independently.
const DefaultOAuthBaseURL = "https://github.com"

// tokenRefreshWindow re-mints an installation token this long before it
// actually expires, so a token handed out for a fetch never lapses mid-request.
const tokenRefreshWindow = time.Minute

// Connector authenticates as a GitHub App installation and pulls repository
// contents. It caches minted installation tokens per installation (they are
// valid for an hour) so a sync that fetches many files does not re-mint on
// every request or hit GitHub's token-creation rate limit. It is safe for
// concurrent use.
type Connector struct {
	baseURL      string
	oauthBaseURL string
	httpClient   *http.Client
	now          func() time.Time

	mu      sync.Mutex
	tokens  map[string]InstallationToken
	minting singleflight.Group
}

// Option configures a Connector.
type Option func(*Connector)

// WithBaseURL points the connector at a non-default API host (GitHub Enterprise
// Server, or a test server).
func WithBaseURL(baseURL string) Option {
	return func(c *Connector) {
		if trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/"); trimmed != "" {
			c.baseURL = trimmed
		}
	}
}

// WithOAuthBaseURL points the connector at a non-default OAuth host. GitHub
// serves the user-token exchange from github.com rather than from the API host,
// so it is a separate setting from WithBaseURL.
func WithOAuthBaseURL(baseURL string) Option {
	return func(c *Connector) {
		if trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/"); trimmed != "" {
			c.oauthBaseURL = trimmed
		}
	}
}

// WithClock overrides the time source, for deterministic token-expiry tests.
func WithClock(now func() time.Time) Option {
	return func(c *Connector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewConnector builds a connector against api.github.com unless overridden.
func NewConnector(opts ...Option) *Connector {
	c := &Connector{
		baseURL:      DefaultBaseURL,
		oauthBaseURL: DefaultOAuthBaseURL,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		now:          time.Now,
		tokens:       make(map[string]InstallationToken),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// FetchRepoContents authenticates with the source's credential and pulls the
// contents at path. It reuses a cached installation token when one is still
// comfortably valid. This is the entry point SyncSource and webhook re-fetch
// call.
func (c *Connector) FetchRepoContents(ctx context.Context, cred AppCredential, owner, repo, path, ref string) (*RepoContent, error) {
	token, err := c.InstallationToken(ctx, cred)
	if err != nil {
		return nil, err
	}
	return c.GetRepoContents(ctx, token, owner, repo, path, ref)
}

// InstallationToken returns a cached token for the credential's installation,
// minting and caching a fresh one when none is cached or the cached one is
// within the refresh window of expiry. Minting is de-duplicated per
// installation: concurrent callers that all miss the cache share a single mint
// rather than each creating a token (GitHub rate-limits token creation).
func (c *Connector) InstallationToken(ctx context.Context, cred AppCredential) (string, error) {
	key := cred.cacheKey()

	if token, ok := c.cachedToken(key); ok {
		return token, nil
	}

	minted, err, _ := c.minting.Do(key, func() (any, error) {
		// A concurrent leader may have filled the cache while this call waited to
		// become the singleflight leader; re-check before minting.
		if token, ok := c.cachedToken(key); ok {
			return token, nil
		}
		token, err := c.MintInstallationToken(ctx, cred)
		if err != nil {
			return "", err
		}
		c.mu.Lock()
		c.sweepExpiredLocked()
		c.tokens[key] = token
		c.mu.Unlock()
		return token.Token, nil
	})
	if err != nil {
		return "", err
	}
	return minted.(string), nil
}

// cachedToken returns a still-valid cached token for key, if any, dropping the
// entry when it has aged out.
func (c *Connector) cachedToken(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cached, ok := c.tokens[key]
	if !ok {
		return "", false
	}
	if c.now().Before(cached.ExpiresAt.Add(-tokenRefreshWindow)) {
		return cached.Token, true
	}
	delete(c.tokens, key)
	return "", false
}

// sweepExpiredLocked drops every entry past its expiry. The cache is keyed by
// the exact authority a token carries — app, installation, repository scope and
// binding — so a source that is re-bound, or a repository that stops being
// read, leaves an entry nothing ever looks up again. Without this the map grows
// for the life of the process; sweeping on mint bounds it to the authorities
// actually in use, and a mint is rare (at most one per authority per hour).
func (c *Connector) sweepExpiredLocked() {
	now := c.now()
	for key, token := range c.tokens {
		if !now.Before(token.ExpiresAt) {
			delete(c.tokens, key)
		}
	}
}
