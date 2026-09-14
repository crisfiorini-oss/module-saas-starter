package business

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"accounts/pkg/githubconnector"
)

// githubAppSetupTTL bounds how long an install round-trip may take: long enough
// for a tenant to install the App and pick repositories, short enough that a
// state left in browser history or a referrer log is no longer redeemable.
const githubAppSetupTTL = 15 * time.Minute

// githubAppInstallBaseURL is where an App's public install page lives. GitHub
// Enterprise serves it from the appliance host instead; a deployment that needs
// that configures it when it configures the App.
const githubAppInstallBaseURL = "https://github.com"

// githubAppMetadataPermissions is the whole authority needed to enumerate what
// an installation grants. Listing repositories must never require the contents
// read a fetch does.
var githubAppMetadataPermissions = map[string]string{"metadata": "read"}

// ErrGitHubAppSetupRejected is the single answer to every failed redemption:
// unknown, expired, already consumed, or begun by a different user. One error
// for all of them keeps the endpoint from reporting which states exist.
var ErrGitHubAppSetupRejected = errors.New("github app setup state was rejected")

// GitHubAppSetup is one in-flight App installation round-trip, bound to the
// organization it was begun for and to the user who began it. Only the state's
// digest is persisted.
type GitHubAppSetup struct {
	ID          string
	OrgID       string
	InitiatedBy string
	StateHash   string
	ExpiresAt   time.Time
}

// GitHubAppSetupHandle is what a client needs to send a browser to GitHub and
// come back: where to go, the one-time state that ties the return to this
// organization and user, and when that state lapses.
type GitHubAppSetupHandle struct {
	InstallURL string
	State      string
	ExpiresAt  time.Time
}

// GitHubAppRepository is one repository a verified installation grants.
type GitHubAppRepository struct {
	Repo             string
	DefaultBranch    string
	AlreadyConnected bool
}

// GitHubAppInstallation is a verified installation and what it grants this
// organization.
type GitHubAppInstallation struct {
	InstallationID string
	Repositories   []GitHubAppRepository
}

// newGitHubAppSetupState mints the one-time state. 32 bytes of crypto/rand is
// far beyond guessing, and only its SHA-256 is stored, so a database read never
// yields a redeemable state.
func newGitHubAppSetupState() (plaintext, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	plaintext = base64.RawURLEncoding.EncodeToString(raw)
	return plaintext, hashGitHubAppSetupState(plaintext), nil
}

func hashGitHubAppSetupState(plaintext string) string {
	digest := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(digest[:])
}

// githubAppOnboardingReady reports whether this deployment can drive tenant App
// onboarding at all: it needs the registration to mint with and the slug to
// build an install link from.
func (s *Service) githubAppOnboardingReady() bool {
	return s.GitHubAppConfigured() && s.githubAppSlug != "" && s.githubConnector != nil
}

// BeginGitHubAppSetup mints a one-time setup state bound to this organization
// and to the calling user, and returns the URL that installs the deployment's
// App on repositories the tenant selects. Nothing about the App's credentials
// leaves accounts: the link carries only the App's public slug and the state.
func (s *Service) BeginGitHubAppSetup(ctx context.Context, actorID, orgID string) (*GitHubAppSetupHandle, error) {
	if !s.githubAppOnboardingReady() {
		return nil, status.Error(codes.FailedPrecondition,
			"This deployment has no GitHub App configured, so a source cannot be connected through one. Connect with a repository-scoped fine-grained PAT, or ask an operator to register the App.")
	}

	state, stateHash, err := newGitHubAppSetupState()
	if err != nil {
		return nil, status.Error(codes.Internal, "Could not start GitHub App setup. Retry shortly.")
	}
	setup := &GitHubAppSetup{
		ID:          NewIDString(),
		OrgID:       orgID,
		InitiatedBy: actorID,
		StateHash:   stateHash,
		ExpiresAt:   time.Now().UTC().Add(githubAppSetupTTL),
	}

	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		if err := s.store.InsertGitHubAppSetup(ctx, setup); err != nil {
			return err
		}
		return s.emitTx(ctx, actorID, "user", EventDatasourceGitHubAppSetupStarted, "organization", orgID, orgID)
	}); err != nil {
		return nil, err
	}

	return &GitHubAppSetupHandle{
		InstallURL: fmt.Sprintf("%s/apps/%s/installations/new?state=%s",
			githubAppInstallBaseURL, url.PathEscape(s.githubAppSlug), url.QueryEscape(state)),
		State:     state,
		ExpiresAt: setup.ExpiresAt,
	}, nil
}

// CompleteGitHubAppSetup redeems the state exactly once and only then decides
// whether the installation it came back with may be claimed.
//
// The ordering is deliberate. The state is burned first, in its own
// transaction, so a replayed redirect is refused before any work is done and a
// failed verification cannot be retried against the same state. Verification
// then asks GitHub — as the App — whether the installation exists, because an
// installation id arriving from a browser redirect is a claim and not authority.
// Finally the installation is claimed for this organization, where the table's
// primary key refuses one another tenant already holds.
func (s *Service) CompleteGitHubAppSetup(ctx context.Context, actorID, orgID, state, installationID string) (*GitHubAppInstallation, error) {
	if !s.githubAppOnboardingReady() {
		return nil, status.Error(codes.FailedPrecondition,
			"This deployment has no GitHub App configured, so there is no installation to complete.")
	}

	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		return s.store.ConsumeGitHubAppSetup(ctx, orgID, hashGitHubAppSetupState(state), actorID, time.Now().UTC())
	}); err != nil {
		if errors.Is(err, ErrGitHubAppSetupRejected) {
			return nil, status.Error(codes.PermissionDenied,
				"This GitHub App setup link is no longer valid. Start the connection again from your organization.")
		}
		return nil, err
	}

	registration := githubconnector.AppCredential{AppID: s.githubAppID, PrivateKeyPEM: s.githubAppKeyPEM}
	installation, err := s.githubConnector.GetInstallation(ctx, registration, installationID)
	if err != nil {
		return nil, githubInstallationTokenError(err)
	}
	if installation.SuspendedAt != nil {
		return nil, status.Error(codes.FailedPrecondition,
			"That GitHub App installation is suspended, so it grants no access. Unsuspend it on GitHub, then connect again.")
	}

	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		claimed, err := s.store.ClaimGitHubAppInstallation(ctx, installation.ID, orgID, actorID)
		if err != nil {
			return err
		}
		if !claimed {
			// Held by a different organization. Reported without naming the
			// holder: which tenant installed an App is not this caller's to learn.
			return status.Error(codes.PermissionDenied,
				"That GitHub App installation is already connected to a different organization.")
		}
		return s.emitTx(ctx, actorID, "user", EventDatasourceGitHubAppSetupCompleted, "organization", orgID, orgID,
			map[string]any{"installation_id": installation.ID})
	}); err != nil {
		return nil, err
	}

	repositories, err := s.listGitHubAppRepositories(ctx, orgID, installation.ID)
	if err != nil {
		return nil, err
	}
	return &GitHubAppInstallation{InstallationID: installation.ID, Repositories: repositories}, nil
}

// listGitHubAppRepositories enumerates what the installation grants, marking the
// repositories this organization already connects so a client does not offer the
// same source twice. The token minted here carries metadata read only — listing
// must not require the contents read a fetch does.
func (s *Service) listGitHubAppRepositories(ctx context.Context, orgID, installationID string) ([]GitHubAppRepository, error) {
	token, err := s.githubConnector.InstallationToken(ctx, githubconnector.AppCredential{
		AppID:          s.githubAppID,
		InstallationID: installationID,
		PrivateKeyPEM:  s.githubAppKeyPEM,
		Scope:          &githubconnector.InstallationScope{Permissions: githubAppMetadataPermissions},
	})
	if err != nil {
		return nil, githubInstallationTokenError(err)
	}
	granted, err := s.githubConnector.ListInstallationRepositories(ctx, token)
	if err != nil {
		return nil, githubInstallationTokenError(err)
	}

	connected := map[string]bool{}
	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		sources, err := s.store.ListDatasourceSources(ctx, orgID)
		if err != nil {
			return err
		}
		for _, source := range sources {
			if source.Provider == DatasourceProviderGitHub {
				connected[strings.ToLower(source.Repo)] = true
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	repositories := make([]GitHubAppRepository, 0, len(granted))
	for _, repo := range granted {
		repositories = append(repositories, GitHubAppRepository{
			Repo:             repo.FullName,
			DefaultBranch:    repo.DefaultBranch,
			AlreadyConnected: connected[strings.ToLower(repo.FullName)],
		})
	}
	return repositories, nil
}

// resolveGitHubConnectCredential proves a new source can read its repository and
// returns the plaintext to seal into its credential envelope.
//
// A supplied token is a repository-scoped fine-grained PAT and is stored as-is.
// An empty one connects through the App, and the installation is resolved from
// the repository server-side rather than taken from the caller — so no client
// decides which installation backs a tenant's source — and must already be
// claimed by this organization, which is what the setup round-trip established.
func (s *Service) resolveGitHubConnectCredential(ctx context.Context, orgID, repo, branch, accessToken string) (string, error) {
	if token := strings.TrimSpace(accessToken); token != "" {
		if err := s.validateGitHubSource(ctx, repo, branch, token); err != nil {
			return "", err
		}
		return token, nil
	}

	if !s.GitHubAppConfigured() || s.githubConnector == nil {
		return "", status.Error(codes.FailedPrecondition,
			"No access token was supplied and this deployment has no GitHub App configured. Supply a repository-scoped fine-grained PAT, or ask an operator to register the App.")
	}

	owner, name, _ := strings.Cut(repo, "/")
	installationID, err := s.githubConnector.FindRepositoryInstallation(ctx,
		githubconnector.AppCredential{AppID: s.githubAppID, PrivateKeyPEM: s.githubAppKeyPEM}, owner, name)
	if err != nil {
		return "", githubInstallationTokenError(err)
	}

	var claimed bool
	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		claimed, err = s.store.GitHubAppInstallationClaimedBy(ctx, installationID, orgID)
		return err
	}); err != nil {
		return "", err
	}
	if !claimed {
		return "", status.Error(codes.PermissionDenied,
			"The GitHub App installation covering that repository is not connected to this organization. Install the App from this organization first, then connect the repository.")
	}

	credential := githubStoredCredential{
		Kind:           githubCredentialKindApp,
		InstallationID: installationID,
		BoundAt:        time.Now().UTC().UnixNano(),
	}
	token, err := s.githubToken(ctx, credential, repo)
	if err != nil {
		return "", err
	}
	if err := validateGitHubAccess(ctx, s.newGitHubClient(token), repo, branch); err != nil {
		return "", err
	}
	return credential.marshal()
}
