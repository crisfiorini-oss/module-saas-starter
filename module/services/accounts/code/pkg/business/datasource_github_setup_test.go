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

// beginSetup starts onboarding and returns the one-time state.
func beginSetup(t *testing.T, h *appHarness, actorID, orgID string) *business.GitHubAppSetupHandle {
	t.Helper()
	handle, err := h.svc.BeginGitHubAppSetup(context.Background(), actorID, orgID)
	require.NoError(t, err)
	return handle
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

// The state is the anti-replay device: redeeming it twice must fail even though
// the second attempt is otherwise identical to the first.
func TestCompleteGitHubAppSetup_StateIsRedeemableOnlyOnce(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	handle := beginSetup(t, h, "actor-1", testOrg)

	installation, err := h.svc.CompleteGitHubAppSetup(context.Background(), "actor-1", testOrg, handle.State, "4242")
	require.NoError(t, err)
	require.Equal(t, "4242", installation.InstallationID)

	_, err = h.svc.CompleteGitHubAppSetup(context.Background(), "actor-1", testOrg, handle.State, "4242")
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"a replayed setup state must be refused")
}

// The setup is bound to the user who began it, so a redirect captured from
// somebody else's browser is not redeemable by another member of the same org.
func TestCompleteGitHubAppSetup_RefusesAnotherInitiator(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	handle := beginSetup(t, h, "actor-1", testOrg)

	_, err := h.svc.CompleteGitHubAppSetup(context.Background(), "actor-2", testOrg, handle.State, "4242")
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

	_, err := h.svc.CompleteGitHubAppSetup(context.Background(), "actor-1", testOrg, handle.State, "4242")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCompleteGitHubAppSetup_RefusesAnUnknownState(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})

	_, err := h.svc.CompleteGitHubAppSetup(context.Background(), "actor-1", testOrg, "not-a-real-state", "4242")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

// Cross-tenant substitution: a second organization that runs its own setup and
// presents the first organization's installation id must not capture it. The
// id arrives from a browser redirect, so it is a claim, not authority.
func TestCompleteGitHubAppSetup_RefusesAnInstallationAnotherOrgHolds(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})

	first := beginSetup(t, h, "actor-1", testOrg)
	_, err := h.svc.CompleteGitHubAppSetup(context.Background(), "actor-1", testOrg, first.State, "4242")
	require.NoError(t, err)

	second := beginSetup(t, h, "actor-2", testOtherOrg)
	_, err = h.svc.CompleteGitHubAppSetup(context.Background(), "actor-2", testOtherOrg, second.State, "4242")
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"an installation already bound to another organization must not be re-claimed")

	claimed, err := h.store.GitHubAppInstallationClaimedBy(context.Background(), "4242", testOrg)
	require.NoError(t, err)
	require.True(t, claimed, "the original organization must keep the installation")
}

func TestCompleteGitHubAppSetup_RefusesASuspendedInstallation(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{suspended: true})
	handle := beginSetup(t, h, "actor-1", testOrg)

	_, err := h.svc.CompleteGitHubAppSetup(context.Background(), "actor-1", testOrg, handle.State, "4242")
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

	installation, err := h.svc.CompleteGitHubAppSetup(context.Background(), "actor-1", testOrg, handle.State, "4242")
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

// The point of the whole flow: a source connects with no pasted token, and what
// is stored is the installation binding rather than any credential material.
func TestAddGitHubSource_ConnectsThroughTheAppWithoutAToken(t *testing.T) {
	h := newAppHarness(t, &fakeGitHubApp{})
	handle := beginSetup(t, h, "actor-1", testOrg)
	_, err := h.svc.CompleteGitHubAppSetup(context.Background(), "actor-1", testOrg, handle.State, "4242")
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
