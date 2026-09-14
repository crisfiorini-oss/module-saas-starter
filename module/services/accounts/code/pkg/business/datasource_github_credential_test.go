package business_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"accounts/pkg/business"
	"accounts/pkg/githubconnector"
)

// The installation id the fake resolves for a repository. Tests assert the
// stored binding carries this, never a value a caller supplied.
const testInstallationID = 4242

// fakeGitHubApp serves the two app-authenticated endpoints the host calls:
// resolving which installation covers a repository, and minting an
// installation token for it.
type fakeGitHubApp struct {
	mintStatus   int // non-zero fails the mint with this status
	lookupStatus int // non-zero fails the installation lookup with this status

	mu        sync.Mutex
	mints     int
	lastScope map[string]any
}

func (f *fakeGitHubApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/installation"):
		if f.lookupStatus != 0 {
			http.Error(w, `{"message":"not installed"}`, f.lookupStatus)
			return
		}
		writeAppJSON(w, http.StatusOK, map[string]any{"id": testInstallationID})
	case strings.HasSuffix(r.URL.Path, "/access_tokens"):
		if f.mintStatus != 0 {
			http.Error(w, `{"message":"denied"}`, f.mintStatus)
			return
		}
		var scope map[string]any
		_ = json.NewDecoder(r.Body).Decode(&scope)
		f.mu.Lock()
		f.mints++
		token := fmt.Sprintf("ghs_%d", f.mints)
		f.lastScope = scope
		f.mu.Unlock()
		writeAppJSON(w, http.StatusCreated, map[string]any{
			"token":      token,
			"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	default:
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}
}

func (f *fakeGitHubApp) mintCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mints
}

func (f *fakeGitHubApp) scope() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastScope
}

func writeAppJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// githubTokens records every bearer token handed to a repository client, which
// is how a test proves which credential actually authenticated a fetch.
type githubTokens struct {
	mu   sync.Mutex
	seen []string
}

func (r *githubTokens) record(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, token)
}

func (r *githubTokens) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func (r *githubTokens) last() string {
	all := r.all()
	if len(all) == 0 {
		return ""
	}
	return all[len(all)-1]
}

type appHarness struct {
	svc       *business.Service
	store     *datasourceFakeStore
	audit     *recordingAudit
	producer  *recordingProducer
	tokens    *githubTokens
	app       *fakeGitHubApp
	serverURL string
}

// restart drops the connector's in-memory token cache, standing in for a
// replica restart or a token reaching its hour-long expiry — the points at
// which the host has to mint again and therefore learns that access changed.
func (h *appHarness) restart() {
	h.svc.SetGitHubConnector(githubconnector.NewConnector(githubconnector.WithBaseURL(h.serverURL)))
}

func newAppHarness(t *testing.T, app *fakeGitHubApp) *appHarness {
	t.Helper()
	server := httptest.NewServer(app)
	t.Cleanup(server.Close)

	store := newDatasourceFakeStore()
	producer := &recordingProducer{}
	svc, audit := newDatasourceService(store, producer, &fakeGitHub{defaultBranch: "main", commit: "abc"})
	svc.SetGitHubConnector(githubconnector.NewConnector(githubconnector.WithBaseURL(server.URL)))
	svc.SetGitHubAppRegistration("123456", testAppKeyPEM(t), "")

	tokens := &githubTokens{}
	gh := &fakeGitHub{defaultBranch: "main", commit: "abc"}
	svc.SetDatasourceGitHubClientFactory(func(token string) business.GitHubContentClient {
		tokens.record(token)
		return gh
	})
	return &appHarness{svc: svc, store: store, audit: audit, producer: producer, tokens: tokens, app: app, serverURL: server.URL}
}

func testAppKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

// storedCredential returns the plaintext behind a source's envelope. The fake
// cipher embeds the purpose, so this also proves the envelope stayed bound to
// the source it belongs to.
func (h *appHarness) storedCredential(t *testing.T, sourceID string) string {
	t.Helper()
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	source := h.store.sources[sourceID]
	require.NotNil(t, source)
	plaintext, ok := strings.CutPrefix(source.CredentialSecretRef, "enc:github-connector:"+sourceID+":")
	require.True(t, ok, "credential envelope is not bound to this source")
	return plaintext
}

func (h *appHarness) addPATSource(t *testing.T, repo, pat string) *business.DatasourceSource {
	t.Helper()
	return addSource(t, h.svc, business.AddGitHubSourceInput{
		OrgID:           testOrg,
		Repo:            repo,
		CollectionLabel: "docs-" + repo,
		AccessToken:     pat,
	})
}

func (h *appHarness) credentialAudits() []map[string]any {
	h.audit.mu.Lock()
	defer h.audit.mu.Unlock()
	var out []map[string]any
	for _, entry := range h.audit.entries {
		if entry.EventType == business.EventDatasourceCredentialUpdated {
			out = append(out, entry.Payload)
		}
	}
	return out
}

// The installation is whatever GitHub says covers the repository, and what
// lands on the source is that binding — never a token, never the app's key.
func TestMigrateGitHubSourceToApp_BindsTheInstallationTheHostResolved(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	source := h.addPATSource(t, "acme/docs", "pat-old")
	before := h.storedCredential(t, source.ID)

	migrated, err := h.svc.MigrateGitHubSourceToApp(context.Background(), "actor-1", testOrg, source.ID)
	require.NoError(t, err)

	require.Equal(t, source.ID, migrated.ID, "migration must not recreate the source")
	require.Equal(t, source.BoundaryNodeID, migrated.BoundaryNodeID)
	require.Equal(t, source.Repo, migrated.Repo)

	stored := h.storedCredential(t, source.ID)
	require.NotEqual(t, before, stored)
	require.Contains(t, stored, `"kind":"app"`)
	require.Contains(t, stored, fmt.Sprintf(`"installation_id":"%d"`, testInstallationID))
	require.NotContains(t, stored, "pat-old", "the replaced PAT must not survive in the envelope")
	require.NotContains(t, stored, "ghs_", "an installation token must never be stored")
	require.NotContains(t, stored, "PRIVATE KEY", "the app signing key must never reach a source record")

	audits := h.credentialAudits()
	require.Len(t, audits, 1)
	require.Equal(t, "app", audits[0]["credential_kind"])
	require.Equal(t, "acme/docs", audits[0]["repo"])
}

func TestMigrateGitHubSourceToApp_NarrowsTheTokenToTheSourceRepository(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	source := h.addPATSource(t, "acme/docs", "pat-old")

	_, err := h.svc.MigrateGitHubSourceToApp(context.Background(), "actor-1", testOrg, source.ID)
	require.NoError(t, err)

	scope := h.app.scope()
	require.Equal(t, []any{"docs"}, scope["repositories"],
		"the token must be narrowed to this source's repository, not the whole installation")
	require.Equal(t, map[string]any{"contents": "read", "metadata": "read"}, scope["permissions"])
}

// The stored PAT is only retired once App access has actually been proven.
func TestMigrateGitHubSourceToApp_KeepsThePATWhenAppAccessIsNotProven(t *testing.T) {
	for _, tc := range []struct {
		name string
		app  *fakeGitHubApp
	}{
		{"app is not installed on the repository", &fakeGitHubApp{lookupStatus: http.StatusNotFound}},
		{"installation refuses to mint a token", &fakeGitHubApp{mintStatus: http.StatusForbidden}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAppHarness(t, tc.app)
			source := h.addPATSource(t, "acme/docs", "pat-old")
			before := h.storedCredential(t, source.ID)

			_, err := h.svc.MigrateGitHubSourceToApp(context.Background(), "actor-1", testOrg, source.ID)
			require.Error(t, err)

			require.Equal(t, before, h.storedCredential(t, source.ID),
				"an unproven migration must leave the working credential in place")
			require.Empty(t, h.credentialAudits(), "no credential change happened, so none may be recorded")
		})
	}
}

// A source connected before the App lifecycle stored its PAT as bare text.
func TestGitHubSource_LegacyPATEnvelopeStillAuthenticates(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	h.svc.SetGitHubAppRegistration("", "", "")
	source := h.addPATSource(t, "acme/docs", "pat-old")

	_, err := h.svc.SyncDatasourceSource(context.Background(), "actor-1", testOrg, source.ID)
	require.NoError(t, err)
	require.Equal(t, "pat-old", h.tokens.last())
	require.Equal(t, 0, h.app.mintCount(), "a PAT source must not reach the app")
}

// Once a source authenticates as the App, losing that access is terminal: it
// must never quietly reach for a PAT again.
func TestGitHubSource_AppBackedSourceNeverFallsBackToAPAT(t *testing.T) {
	app := &fakeGitHubApp{}
	h := newAppHarness(t, app)
	source := h.addPATSource(t, "acme/docs", "pat-old")
	_, err := h.svc.MigrateGitHubSourceToApp(context.Background(), "actor-1", testOrg, source.ID)
	require.NoError(t, err)

	app.mintStatus = http.StatusForbidden
	h.restart()
	enqueued := len(h.producer.jobs)
	authenticated := len(h.tokens.all())

	_, err = h.svc.SyncDatasourceSource(context.Background(), "actor-1", testOrg, source.ID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no longer grants access")
	require.Len(t, h.tokens.all(), authenticated,
		"a revoked installation must build no client at all, least of all one on the retired PAT")
	require.Len(t, h.producer.jobs, enqueued, "a denied source must not enqueue a sync that would read nothing")
}

// A stored credential naming a kind this deployment does not implement must
// fail closed. Falling through to the PAT branch would hand the client an empty
// token, and an empty token is not "no credential" — it is an anonymous client,
// which reads a public repository successfully and reports a sync that proved
// no authorization at all.
func TestGitHubSource_UnrecognizedCredentialKindFailsClosed(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	source := h.addPATSource(t, "acme/docs", "pat-old")
	authenticated := len(h.tokens.all())

	h.store.mu.Lock()
	h.store.sources[source.ID].CredentialSecretRef =
		"enc:github-connector:" + source.ID + `:{"kind":"app_v2","installation_id":"4242"}`
	h.store.mu.Unlock()

	_, err := h.svc.SyncDatasourceSource(context.Background(), "actor-1", testOrg, source.ID)
	require.Error(t, err)
	require.Len(t, h.tokens.all(), authenticated, "an unreadable credential must build no client")
}

func TestGitHubSource_EmptyStoredPATFailsClosed(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	source := h.addPATSource(t, "acme/docs", "pat-old")
	authenticated := len(h.tokens.all())

	h.store.mu.Lock()
	h.store.sources[source.ID].CredentialSecretRef = "enc:github-connector:" + source.ID + ":"
	h.store.mu.Unlock()

	_, err := h.svc.SyncDatasourceSource(context.Background(), "actor-1", testOrg, source.ID)
	require.Error(t, err)
	require.Len(t, h.tokens.all(), authenticated, "an empty credential must never become an anonymous client")
}

// Re-binding a source to the App after an intervening PAT reconnect must mint
// under a fresh identity. GitHub documents no mid-life invalidation when an
// installation is narrowed, so serving the token minted for the binding that
// was replaced would carry authority the operator may have revoked in between.
func TestGitHubSource_PATReconnectDoesNotResurrectASupersededToken(t *testing.T) {
	app := &fakeGitHubApp{}
	h := newAppHarness(t, app)
	source := h.addPATSource(t, "acme/docs", "pat-old")
	ctx := context.Background()

	_, err := h.svc.MigrateGitHubSourceToApp(ctx, "actor-1", testOrg, source.ID)
	require.NoError(t, err)
	firstToken := h.tokens.last()
	mintsAfterFirst := app.mintCount()

	_, err = h.svc.SyncDatasourceSource(ctx, "actor-1", testOrg, source.ID, "pat-new")
	require.NoError(t, err)

	_, err = h.svc.MigrateGitHubSourceToApp(ctx, "actor-1", testOrg, source.ID)
	require.NoError(t, err)
	_, err = h.svc.SyncDatasourceSource(ctx, "actor-1", testOrg, source.ID)
	require.NoError(t, err)

	require.Greater(t, app.mintCount(), mintsAfterFirst, "a re-binding must mint its own token")
	require.NotEqual(t, firstToken, h.tokens.last(), "the superseded binding's token must not be served again")

	// Every write of this source's credential is attributable to a kind, so an
	// App binding replaced by a PAT is visible in the audit trail rather than
	// looking like a record written before the field existed.
	var kinds []any
	for _, payload := range h.credentialAudits() {
		kinds = append(kinds, payload["credential_kind"])
	}
	require.Equal(t, []any{"app", "pat", "app"}, kinds)
}

// A minted token is reused until it is superseded: a rotation re-binds the
// installation at a new binding, and the old token is never served for it.
func TestGitHubSource_TokenIsCachedAndReMintedOnRotation(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	source := h.addPATSource(t, "acme/docs", "pat-old")
	ctx := context.Background()
	_, err := h.svc.MigrateGitHubSourceToApp(ctx, "actor-1", testOrg, source.ID)
	require.NoError(t, err)

	_, err = h.svc.SyncDatasourceSource(ctx, "actor-1", testOrg, source.ID)
	require.NoError(t, err)
	minted := h.app.mintCount()
	firstToken := h.tokens.last()
	require.True(t, strings.HasPrefix(firstToken, "ghs_"))

	// Failures are collected and asserted on the test goroutine: require's
	// FailNow from a spawned goroutine does not stop the test and can report the
	// failure against whatever is running when it lands.
	var wg sync.WaitGroup
	concurrent := make([]error, 20)
	for i := range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, concurrent[i] = h.svc.SyncDatasourceSource(ctx, "actor-1", testOrg, source.ID)
		}()
	}
	wg.Wait()
	require.NoError(t, errors.Join(concurrent...))
	require.Equal(t, minted, h.app.mintCount(), "concurrent fetches must reuse the cached installation token")

	_, err = h.svc.MigrateGitHubSourceToApp(ctx, "actor-2", testOrg, source.ID)
	require.NoError(t, err)
	_, err = h.svc.SyncDatasourceSource(ctx, "actor-1", testOrg, source.ID)
	require.NoError(t, err)
	require.NotEqual(t, firstToken, h.tokens.last(), "a rotated binding must not be served the superseded token")
}
