package business_test

import (
	"context"
	"testing"

	"accounts/pkg/business"
	gen "accounts/pkg/gen/saas/accounts/v1"

	"github.com/stretchr/testify/require"
)

// resourceFollowStore answers the access oracle the way each case needs and
// records what actually reached the store, so the visibility rule is exercised
// without standing up a scope tree.
type resourceFollowStore struct {
	business.Store
	visible bool
	checked bool
	created []*business.ResourceFollow
	revoked int
}

func (store *resourceFollowStore) WithOrgTx(ctx context.Context, _ string, fn func(context.Context) error) error {
	return fn(ctx)
}

func (store *resourceFollowStore) WithUserTx(ctx context.Context, _ string, fn func(context.Context) error) error {
	return fn(ctx)
}

func (store *resourceFollowStore) CheckAccess(_ context.Context, _ string, _ gen.SubjectKind, _, _, _ string) (bool, string, error) {
	store.checked = true
	return store.visible, "", nil
}

func (store *resourceFollowStore) CreateResourceFollow(_ context.Context, follow *business.ResourceFollow) error {
	store.created = append(store.created, follow)
	return nil
}

func (store *resourceFollowStore) RevokeResourceFollow(_ context.Context, _, _, _ string) error {
	store.revoked++
	return nil
}

// A target the caller cannot currently see is reported as missing, and nothing
// is written. The answer has to be indistinguishable from a genuinely absent
// resource, or Follow becomes an existence oracle for other people's scopes.
func TestFollowReportsAnInvisibleTargetAsMissing(t *testing.T) {
	store := &resourceFollowStore{visible: false}
	service, err := business.NewService(store)
	require.NoError(t, err)

	follow, err := service.Follow(context.Background(), "user-1", "org-1", "doc", "doc-1")

	require.Error(t, err)
	require.Nil(t, follow)
	require.Contains(t, err.Error(), "not found")
	require.NotContains(t, err.Error(), "denied")
	require.Empty(t, store.created, "an unauthorized follow must write nothing")
}

func TestFollowRecordsAVisibleTarget(t *testing.T) {
	store := &resourceFollowStore{visible: true}
	service, err := business.NewService(store)
	require.NoError(t, err)

	follow, err := service.Follow(context.Background(), "user-1", "org-1", "doc", "doc-1")

	require.NoError(t, err)
	require.Len(t, store.created, 1)
	require.Equal(t, "user-1", follow.UserID)
	require.Equal(t, "org-1", follow.OrgID)
	require.Equal(t, "doc", follow.ResourceType)
	require.Equal(t, "doc-1", follow.ResourceID)
}

// Unfollow deliberately consults no oracle: someone who has lost access to a
// resource must still be able to stop hearing about it.
func TestUnfollowNeedsNoVisibility(t *testing.T) {
	store := &resourceFollowStore{visible: false}
	service, err := business.NewService(store)
	require.NoError(t, err)

	require.NoError(t, service.Unfollow(context.Background(), "user-1", "doc", "doc-1"))

	require.Equal(t, 1, store.revoked)
	require.False(t, store.checked, "unfollow must not consult the access oracle")
}
