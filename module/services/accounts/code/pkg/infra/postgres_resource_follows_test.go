//go:build !pure

package infra_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"accounts/pkg/business"
)

// resource_follows is RLS-protected by user_id, so every direct Store call is
// wrapped in the follower's WithUserTx exactly as the service does.

func followFixture(t *testing.T) (userID, orgID string) {
	t.Helper()
	userID = seedUser(t)
	orgID = seedOrg(t, userID)
	return userID, orgID
}

func follow(t *testing.T, userID, orgID, resourceType, resourceID string) string {
	t.Helper()
	record := &business.ResourceFollow{
		ID:           business.NewIDString(),
		OrgID:        orgID,
		UserID:       userID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}
	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		return testStore.CreateResourceFollow(ctx, record)
	}))
	return record.ID
}

func liveFollowCount(t *testing.T, userID, resourceID string) int {
	t.Helper()
	var count int
	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared "tx" key
		return tx.QueryRow(ctx, `
			SELECT COUNT(*) FROM resource_follows
			WHERE user_id = $1 AND resource_id = $2 AND revoked_at IS NULL`,
			userID, resourceID).Scan(&count)
	}))
	return count
}

// Following the same instance twice converges on the row that already exists.
// This is what stops overlapping follows producing two deliveries for one
// change, so it is asserted on the row count, not only on the returned id.
func TestCreateResourceFollowIsIdempotent(t *testing.T) {
	userID, orgID := followFixture(t)

	first := follow(t, userID, orgID, "doc", "doc-1")
	second := follow(t, userID, orgID, "doc", "doc-1")

	require.Equal(t, first, second, "a repeated follow must converge on the live row")
	require.Equal(t, 1, liveFollowCount(t, userID, "doc-1"))
}

// Revocation is a soft fact with a time, and the unique index covers only live
// rows — so a resource can be followed again after being unfollowed, and the
// revoked row is left behind as history rather than overwritten.
func TestRevokeResourceFollowAllowsFollowingAgain(t *testing.T) {
	userID, orgID := followFixture(t)

	original := follow(t, userID, orgID, "doc", "doc-2")
	// The revoke names no organization on purpose: the caller reaches it with
	// whichever org is active, and matching on that would strand the follow of
	// anyone who has since switched.
	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		return testStore.RevokeResourceFollow(ctx, userID, "doc", "doc-2")
	}))
	require.Equal(t, 0, liveFollowCount(t, userID, "doc-2"))

	revived := follow(t, userID, orgID, "doc", "doc-2")
	require.NotEqual(t, original, revived, "a follow after a revoke is a new fact")
	require.Equal(t, 1, liveFollowCount(t, userID, "doc-2"))
}

// Revoking a follow that was never taken, or is already revoked, succeeds and
// changes nothing — an unfollow must never report whether the follow existed.
func TestRevokeResourceFollowIsSilentWhenAbsent(t *testing.T) {
	userID, _ := followFixture(t)

	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		return testStore.RevokeResourceFollow(ctx, userID, "doc", "never-followed")
	}))
	require.Equal(t, 0, liveFollowCount(t, userID, "never-followed"))
}

// The RLS policy keys on the follower, so one person's follows are invisible to
// another even inside the same organization.
func TestResourceFollowsAreInvisibleToAnotherUser(t *testing.T) {
	owner, orgID := followFixture(t)
	follow(t, owner, orgID, "doc", "doc-3")

	other := seedUser(t)
	require.Equal(t, 0, liveFollowCount(t, other, "doc-3"))
}
