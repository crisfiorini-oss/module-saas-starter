package business

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codefly-dev/core/wool"

	"accounts/pkg/githubconnector"
	"accounts/pkg/jobs"
)

// How a GitHub source authenticates. A `pat` source presents a stored
// fine-grained token; an `app` source presents an installation token the host
// mints for each fetch and never stores. These are the only kinds a stored
// credential may name — anything else is refused rather than interpreted.
const (
	githubCredentialKindPAT = "pat"
	githubCredentialKindApp = "app"
)

// githubMigrationProbeTimeout bounds the GitHub round trips a migration makes,
// matching the budget connect-time validation already uses.
const githubMigrationProbeTimeout = 10 * time.Second

// githubInstallationReadPermissions is the whole authority a source needs to
// read a repository: file contents, plus the metadata every request resolves
// the repository through. Narrowing here is defence in depth, not the boundary
// — repository permission has no path grain, so the host still enforces the
// source's configured path prefixes itself.
var githubInstallationReadPermissions = map[string]string{"contents": "read", "metadata": "read"}

// githubStoredCredential is the plaintext behind a GitHub source's credential
// envelope. An app source stores only the installation it was bound to and when
// that binding was made — never a token (they last an hour) and never the App's
// signing key, which is deployment custody.
type githubStoredCredential struct {
	Kind           string `json:"kind"`
	AccessToken    string `json:"access_token,omitempty"`
	InstallationID string `json:"installation_id,omitempty"`
	// BoundAt is when this binding was created, in Unix nanoseconds, and becomes
	// the connector's cache identity for it. It must never return to a value an
	// earlier binding used: GitHub documents no mid-life invalidation when an
	// installation's repository selection or permissions are narrowed, so a
	// token minted under a superseded binding keeps working until it expires. A
	// counter cannot carry this — an intervening PAT reconnect replaces the whole
	// envelope, so the count restarts and re-collides with that live token.
	BoundAt int64 `json:"bound_at,omitempty"`
}

func (c githubStoredCredential) marshal() (string, error) {
	blob, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(blob), nil
}

// parseGitHubStoredCredential decodes a source's credential envelope. Sources
// connected before the App lifecycle stored the PAT as bare text rather than a
// JSON object, so anything that does not decode into this shape is that PAT.
func parseGitHubStoredCredential(plaintext string) githubStoredCredential {
	var cred githubStoredCredential
	if err := json.Unmarshal([]byte(plaintext), &cred); err != nil || cred.Kind == "" {
		return githubStoredCredential{Kind: githubCredentialKindPAT, AccessToken: plaintext}
	}
	return cred
}

// SetGitHubAppRegistration wires the deployment's GitHub App: the id it is
// registered under, the RSA private key its installation tokens are signed
// with, the URL slug its install link is built from, and the secret GitHub
// signs the App's own lifecycle deliveries with. All four are operator-managed
// deployment configuration, held once here rather than copied onto each source,
// and never leave accounts. An empty registration leaves every source on its
// own stored PAT.
func (s *Service) SetGitHubAppRegistration(appID, privateKeyPEM, slug, webhookSecret string) {
	s.githubAppID = strings.TrimSpace(appID)
	s.githubAppKeyPEM = strings.TrimSpace(privateKeyPEM)
	s.githubAppSlug = strings.TrimSpace(slug)
	s.githubAppWebhookSecret = strings.TrimSpace(webhookSecret)
}

// SetGitHubAppOAuth wires the App's OAuth client, which tenant onboarding uses
// to identify the person returning from an install. It is deliberately separate
// from the signing registration above: that credential acts as the App, this one
// acts as a user, and only the latter can attribute an installation to a caller.
// An empty pair leaves App onboarding off.
func (s *Service) SetGitHubAppOAuth(clientID, clientSecret string) {
	s.githubAppClientID = strings.TrimSpace(clientID)
	s.githubAppClientSecret = strings.TrimSpace(clientSecret)
}

// GitHubAppConfigured reports whether this deployment can mint installation
// tokens at all.
func (s *Service) GitHubAppConfigured() bool {
	return s.githubAppID != "" && s.githubAppKeyPEM != ""
}

// appCredentialFor composes the deployment registration with one source's
// installation binding and repository. The scope narrows the minted token to
// that single repository, so a token minted for one source is useless against
// another repository the same installation covers.
func (s *Service) appCredentialFor(cred githubStoredCredential, repo string) githubconnector.AppCredential {
	_, name, _ := strings.Cut(repo, "/")
	return githubconnector.AppCredential{
		AppID:          s.githubAppID,
		InstallationID: cred.InstallationID,
		PrivateKeyPEM:  s.githubAppKeyPEM,
		Scope: &githubconnector.InstallationScope{
			Repositories: []string{name},
			Permissions:  githubInstallationReadPermissions,
		},
		Binding: strconv.FormatInt(cred.BoundAt, 10),
	}
}

// githubClientForSource resolves a source's stored credential into an
// authenticated client. Every GitHub read — connect-time validation, the
// recurring reconcile, a webhook-triggered compile, and immutable content
// fetch — goes through here, so token acquisition and refresh are one
// behaviour rather than five.
func (s *Service) githubClientForSource(ctx context.Context, source *DatasourceSource) (GitHubContentClient, error) {
	w := wool.Get(ctx).In("githubClientForSource")
	if s.datasourceCipher == nil || s.newGitHubClient == nil {
		return nil, w.NewError("datasource connector is not configured")
	}
	plaintext, err := s.datasourceCipher.DecryptSecret(ctx, DatasourceConnectorSecretPurpose(source.ID), source.CredentialSecretRef)
	if err != nil {
		return nil, datasourceCredentialError(err)
	}
	token, err := s.githubToken(ctx, parseGitHubStoredCredential(plaintext), source.Repo)
	if err != nil {
		return nil, err
	}
	return s.newGitHubClient(token), nil
}

// githubToken presents a stored credential as the bearer token a fetch uses. A
// PAT is presented as-is; an App binding is exchanged for a short-lived,
// repository-scoped installation token, which the connector caches per
// authority and re-mints before it lapses.
//
// The kinds are an allow-list. Falling through to "treat it as a PAT" would
// hand the caller whatever the access token field happened to hold, and an
// empty one is not "no credential" — the GitHub client omits the Authorization
// header entirely, so a public repository would sync as though it had been
// authorized. An App-backed source likewise never falls back to a PAT: once
// access is denied, revoked or suspended, the source fails with an actionable
// error until an operator repairs the installation.
func (s *Service) githubToken(ctx context.Context, cred githubStoredCredential, repo string) (string, error) {
	switch cred.Kind {
	case githubCredentialKindPAT:
		if strings.TrimSpace(cred.AccessToken) == "" {
			return "", jobs.NewProcessingError("datasource.credential_unreadable",
				"The stored GitHub credential for this source is empty. Reconnect the source with a valid token. This sync job will not retry.", false)
		}
		return cred.AccessToken, nil
	case githubCredentialKindApp:
		if s.githubConnector == nil || !s.GitHubAppConfigured() {
			return "", jobs.NewProcessingError("datasource.github_app_unconfigured",
				"This source authenticates through a GitHub App that this deployment has no registration for. Restore the App registration, or reconnect the source. This sync job will not retry.", false)
		}
		token, err := s.githubConnector.InstallationToken(ctx, s.appCredentialFor(cred, repo))
		if err != nil {
			return "", githubInstallationTokenError(err)
		}
		return token, nil
	default:
		return "", jobs.NewProcessingError("datasource.credential_unreadable",
			"The stored GitHub credential for this source is not in a form this deployment understands. Reconnect the source. This sync job will not retry.", false)
	}
}

// githubInstallationTokenError classifies a failed mint. A revoked, suspended
// or uninstalled App — and a repository dropped from the installation's
// selection — can never succeed by retrying, so those are terminal; anything
// else is treated as GitHub being briefly unavailable. The provider's own
// message is never surfaced: it can carry request context.
func githubInstallationTokenError(err error) error {
	var apiErr *githubconnector.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
			return jobs.NewProcessingError("datasource.github_app_access_denied",
				"The GitHub App installation for this source no longer grants access to the repository. Reinstall the App or re-select this repository, then sync again. This sync job will not retry.", false)
		case http.StatusUnprocessableEntity:
			return jobs.NewProcessingError("datasource.github_app_scope_denied",
				"The GitHub App installation does not grant the read permissions this source requires. Approve the App's updated permissions, then sync again. This sync job will not retry.", false)
		case http.StatusTooManyRequests:
			return jobs.NewProcessingError("datasource.github_rate_limited",
				"GitHub rate limited the installation-token request. This job may retry.", true)
		}
	}
	return jobs.NewProcessingError("datasource.github_app_token_unavailable",
		"Could not obtain a GitHub App installation token. GitHub may be unavailable; this job may retry.", true)
}

// MigrateGitHubSourceToApp re-points a PAT-backed source at the deployment's
// GitHub App, in place. The source keeps its identity, path scope, boundary,
// grants, delivery cursor and audit history — it is never deleted and
// recreated — and its stored PAT is only overwritten once App access to the
// same repository and branch has actually been proven.
//
// The installation is resolved server-side from the repository the source
// already names, so nothing a caller supplies decides which installation is
// bound to this tenant.
func (s *Service) MigrateGitHubSourceToApp(ctx context.Context, actorID, orgID, id string) (*DatasourceSource, error) {
	w := wool.Get(ctx).In("MigrateGitHubSourceToApp")
	source, err := s.GetDatasourceSource(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if source.Provider != DatasourceProviderGitHub {
		return nil, w.NewError("only a github source authenticates through the github app")
	}
	if s.githubConnector == nil || !s.GitHubAppConfigured() {
		return nil, w.NewError("no github app is registered for this deployment")
	}
	if s.datasourceCipher == nil {
		return nil, w.NewError("datasource secret cipher is not configured")
	}

	// Every GitHub and Vault round trip happens before the transaction opens, and
	// under its own deadline. The credential row is locked with SELECT … FOR
	// UPDATE and the GitHub client allows 30s per request, so resolving, minting
	// and validating inside the transaction would pin that lock and a pooled
	// database connection for minutes whenever GitHub is slow or rate-limiting.
	probeCtx, cancel := context.WithTimeout(ctx, githubMigrationProbeTimeout)
	defer cancel()

	owner, repoName, _ := strings.Cut(source.Repo, "/")
	registration := githubconnector.AppCredential{AppID: s.githubAppID, PrivateKeyPEM: s.githubAppKeyPEM}
	installationID, err := s.githubConnector.FindRepositoryInstallation(probeCtx, registration, owner, repoName)
	if err != nil {
		return nil, githubInstallationTokenError(err)
	}

	// The binding is stamped from the clock rather than counted up from whatever
	// is stored, so it cannot repeat a previous binding's value and be served
	// that binding's still-cached token.
	replacement := githubStoredCredential{
		Kind:           githubCredentialKindApp,
		InstallationID: installationID,
		BoundAt:        time.Now().UTC().UnixNano(),
	}
	token, err := s.githubToken(probeCtx, replacement, source.Repo)
	if err != nil {
		return nil, err
	}
	if err := validateGitHubAccess(probeCtx, s.newGitHubClient(token), source.Repo, source.Branch); err != nil {
		return nil, err
	}

	blob, err := replacement.marshal()
	if err != nil {
		return nil, w.Wrapf(err, "encode app credential")
	}
	encrypted, err := s.datasourceCipher.EncryptSecret(ctx, DatasourceConnectorSecretPurpose(id), blob)
	if err != nil {
		return nil, w.Wrapf(err, "encrypt app credential")
	}

	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		if _, err := s.store.LockDatasourceSourceCredentialRef(ctx, orgID, id); err != nil {
			return w.Wrapf(err, "lock credential")
		}
		if err := s.store.UpdateDatasourceSourceCredential(ctx, orgID, id, encrypted); err != nil {
			return w.Wrapf(err, "persist app credential")
		}
		// The routing index an App-level delivery resolves this source through,
		// written in the same transaction as the envelope it indexes so the two
		// never disagree about which installation this source was bound to.
		if err := s.store.SetDatasourceSourceGitHubInstallation(ctx, orgID, id, installationID); err != nil {
			return w.Wrapf(err, "persist installation binding")
		}
		source.CredentialSecretRef = encrypted
		source.GitHubInstallationID = installationID
		return s.emitTx(ctx, actorID, "user", EventDatasourceCredentialUpdated, "datasource", id, orgID,
			map[string]any{"repo": source.Repo, "credential_kind": githubCredentialKindApp})
	}); err != nil {
		return nil, err
	}
	return source, nil
}
