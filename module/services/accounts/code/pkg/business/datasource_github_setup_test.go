package business_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"accounts/pkg/business"
)

// A second tenant, used to prove an installation one organization verified
// cannot be claimed by another.
const testOtherOrg = "22222222-2222-4222-8222-222222222222"

// The authorization code GitHub appends to the setup redirect. The fake accepts
// any value unless it is configured to reject.
const testSetupCode = "setup-code-1"

// beginSetup starts onboarding and returns the one-time state.
func beginSetup(t *testing.T, h *appHarness, actorID, orgID string) *business.GitHubAppSetupHandle {
	t.Helper()
	handle, err := h.svc.BeginGitHubAppSetup(context.Background(), actorID, orgID)
	require.NoError(t, err)
	return handle
}

func completeSetup(h *appHarness, actorID, orgID, state, installationID string) (*business.GitHubAppInstallation, error) {
	return h.svc.CompleteGitHubAppSetup(context.Background(), actorID, orgID, state, installationID, testSetupCode)
}

func TestBeginGitHubAppSetup_LinksToTheAppCarryingTheState(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})

	handle := beginSetup(t, h, "actor-1", testOrg)

	require.NotEmpty(t, handle.State)
	require.Contains(t, handle.InstallURL, "/apps/example-app/installations/new")
	require.Contains(t, handle.InstallURL, "state="+url.QueryEscape(handle.State),
		"the install link must carry the state, or the return leg has nothing to bind to")
	require.True(t, handle.ExpiresAt.After(time.Now().UTC()))
	require.NotContains(t, handle.InstallURL, "PRIVATE KEY")
}

// Without an OAuth client the host can prove an installation exists but not who
// controls it, so onboarding must stay off rather than bind on trust.
func TestBeginGitHubAppSetup_StaysOffWithoutAnOAuthClient(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	h.svc.SetGitHubAppOAuth("", "")

	_, err := h.svc.BeginGitHubAppSetup(context.Background(), "actor-1", testOrg)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// The state is the anti-replay device: redeeming it twice must fail even though
// the second attempt is otherwise identical to the first.
func TestCompleteGitHubAppSetup_StateIsRedeemableOnlyOnce(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	handle := beginSetup(t, h, "actor-1", testOrg)

	installation, err := completeSetup(h, "actor-1", testOrg, handle.State, "4242")
	require.NoError(t, err)
	require.Equal(t, "4242", installation.InstallationID)

	_, err = completeSetup(h, "actor-1", testOrg, handle.State, "4242")
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"a replayed setup state must be refused")
}

// The setup is bound to the user who began it, so a redirect captured from
// somebody else's browser is not redeemable by another member of the same org.
func TestCompleteGitHubAppSetup_RefusesAnotherInitiator(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	handle := beginSetup(t, h, "actor-1", testOrg)

	_, err := completeSetup(h, "actor-2", testOrg, handle.State, "4242")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCompleteGitHubAppSetup_RefusesAnExpiredState(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	handle := beginSetup(t, h, "actor-1", testOrg)

	h.store.mu.Lock()
	for _, setup := range h.store.setups {
		setup.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	}
	h.store.mu.Unlock()

	_, err := completeSetup(h, "actor-1", testOrg, handle.State, "4242")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCompleteGitHubAppSetup_RefusesAnUnknownState(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})

	_, err := completeSetup(h, "actor-1", testOrg, "not-a-real-state", "4242")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

// The attack this flow exists to stop, and the one an existence check alone does
// not: an organization naming another tenant's installation id, which is a small
// integer arriving from a browser. Asking GitHub as the App answers "yes, that
// installation exists" for every tenant's installation, so the refusal has to
// come from the authorizing user not being able to reach it.
func TestCompleteGitHubAppSetup_RefusesAnInstallationTheCallerCannotReach(t *testing.T) {
	// The person returning from the install reaches installation 99; they are
	// presenting 4242, which belongs to somebody else and is unclaimed.
	h := newAppHarness(t, &fakeGitHubApp{userInstallations: []int{99}})
	handle := beginSetup(t, h, "actor-1", testOrg)

	_, err := completeSetup(h, "actor-1", testOrg, handle.State, "4242")
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	claimed, err := h.store.GitHubAppInstallationClaimedBy(context.Background(), "4242", testOrg)
	require.NoError(t, err)
	require.False(t, claimed,
		"an installation the caller cannot reach must not be claimed, even when it is unclaimed")
}

// A code that GitHub refuses is reported exactly like an installation the user
// cannot reach, so the endpoint is not an oracle for which installations exist.
func TestCompleteGitHubAppSetup_RefusesARejectedAuthorizationCode(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{oauthError: "bad_verification_code"})
	handle := beginSetup(t, h, "actor-1", testOrg)

	_, err := completeSetup(h, "actor-1", testOrg, handle.State, "4242")
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	claimed, err := h.store.GitHubAppInstallationClaimedBy(context.Background(), "4242", testOrg)
	require.NoError(t, err)
	require.False(t, claimed)
}

func TestCompleteGitHubAppSetup_RefusesAMissingAuthorizationCode(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	handle := beginSetup(t, h, "actor-1", testOrg)

	_, err := h.svc.CompleteGitHubAppSetup(context.Background(), "actor-1", testOrg, handle.State, "4242", "")
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// Cross-tenant substitution where the victim did complete setup: the claim is
// already held, so the primary key refuses it before any of the above matters.
func TestCompleteGitHubAppSetup_RefusesAnInstallationAnotherOrgHolds(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})

	first := beginSetup(t, h, "actor-1", testOrg)
	_, err := completeSetup(h, "actor-1", testOrg, first.State, "4242")
	require.NoError(t, err)

	second := beginSetup(t, h, "actor-2", testOtherOrg)
	_, err = completeSetup(h, "actor-2", testOtherOrg, second.State, "4242")
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"an installation already bound to another organization must not be re-claimed")

	claimed, err := h.store.GitHubAppInstallationClaimedBy(context.Background(), "4242", testOrg)
	require.NoError(t, err)
	require.True(t, claimed, "the original organization must keep the installation")
}

func TestCompleteGitHubAppSetup_RefusesASuspendedInstallation(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{suspended: true})
	handle := beginSetup(t, h, "actor-1", testOrg)

	_, err := completeSetup(h, "actor-1", testOrg, handle.State, "4242")
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// Listing must not require the contents read a fetch does, and it must tell a
// client which repositories are already connected so it does not offer them
// twice.
func TestCompleteGitHubAppSetup_ListsGrantedRepositories(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{repositories: []map[string]any{
		{"full_name": "acme/docs", "default_branch": "main"},
		{"full_name": "acme/handbook", "default_branch": "trunk"},
	}})
	h.addPATSource(t, "acme/docs", "pat-1")
	handle := beginSetup(t, h, "actor-1", testOrg)

	installation, err := completeSetup(h, "actor-1", testOrg, handle.State, "4242")
	require.NoError(t, err)

	require.Len(t, installation.Repositories, 2)
	require.Equal(t, "acme/docs", installation.Repositories[0].Repo)
	require.True(t, installation.Repositories[0].AlreadyConnected)
	require.Equal(t, "acme/handbook", installation.Repositories[1].Repo)
	require.Equal(t, "trunk", installation.Repositories[1].DefaultBranch)
	require.False(t, installation.Repositories[1].AlreadyConnected)

	scope := h.app.scope()
	require.Equal(t, map[string]any{"metadata": "read"}, scope["permissions"],
		"enumerating an installation must not request contents read")
	require.NotContains(t, scope, "repositories",
		"the listing token is deliberately not narrowed to a repository: it is what discovers them")
}

// An installation that never stops serving full pages must end the walk with an
// error rather than looping forever. Without the bound this test does not fail,
// it hangs.
func TestCompleteGitHubAppSetup_RefusesAnInstallationBeyondThePageCap(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{alwaysFullRepoPages: true})
	handle := beginSetup(t, h, "actor-1", testOrg)

	_, err := completeSetup(h, "actor-1", testOrg, handle.State, "4242")
	require.Error(t, err)
}

// The point of the whole flow: a source connects with no pasted token, and what
// is stored is the installation binding rather than any credential material.
func TestAddGitHubSource_ConnectsThroughTheAppWithoutAToken(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	handle := beginSetup(t, h, "actor-1", testOrg)
	_, err := completeSetup(h, "actor-1", testOrg, handle.State, "4242")
	require.NoError(t, err)

	source, err := h.svc.AddGitHubSource(context.Background(), "actor-1", business.AddGitHubSourceInput{
		OrgID:           testOrg,
		Repo:            "acme/docs",
		CollectionLabel: "docs",
	})
	require.NoError(t, err)

	stored := h.storedCredential(t, source.ID)
	require.Contains(t, stored, `"kind":"app"`)
	require.Contains(t, stored, `"installation_id":"4242"`)
	require.NotContains(t, stored, "ghs_", "an installation token must never be stored")
	require.NotContains(t, stored, "PRIVATE KEY", "the app signing key must never reach a source record")
	require.NotEmpty(t, h.tokens.last(), "the connect-time validation must have authenticated with a minted token")
}

// The provider-agnostic call must accept the same connect the GitHub-specific
// one does, or a client using it cannot reach App onboarding at all.
func TestAddSource_ConnectsGitHubThroughTheAppWithoutACredential(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	handle := beginSetup(t, h, "actor-1", testOrg)
	_, err := completeSetup(h, "actor-1", testOrg, handle.State, "4242")
	require.NoError(t, err)

	source, err := h.svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID:           testOrg,
		Provider:        business.DatasourceProviderGitHub,
		Repo:            "acme/docs",
		CollectionLabel: "docs",
	})
	require.NoError(t, err)

	stored := h.storedCredential(t, source.ID)
	require.Contains(t, stored, `"kind":"app"`)
	require.Contains(t, stored, `"installation_id":"4242"`)
}

// Without a verified claim there is nothing authorizing this tenant to use the
// installation covering the repository, so the connect must fail closed rather
// than bind an installation the organization never installed.
func TestAddGitHubSource_RefusesAppConnectWithoutAVerifiedInstallation(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})

	_, err := h.svc.AddGitHubSource(context.Background(), "actor-1", business.AddGitHubSourceInput{
		OrgID:           testOrg,
		Repo:            "acme/docs",
		CollectionLabel: "docs",
	})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

// The PAT remains a first-class option for existing connections and development.
func TestAddGitHubSource_StillAcceptsARepositoryScopedPAT(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})

	source := h.addPATSource(t, "acme/docs", "pat-1")

	require.Equal(t, "pat-1", h.storedCredential(t, source.ID))
}
