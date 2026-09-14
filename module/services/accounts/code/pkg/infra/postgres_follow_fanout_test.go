//go:build !pure

package infra_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"accounts/pkg/business"
)

// The fan-out reads followers across users, which no single follower's
// transaction can do, and re-reads one follower's own follow inside the
// transaction that writes. These exercise both against the real policies.

func seedFollowNotification(t *testing.T, userID, orgID, id, resourceType, resourceID string) error {
	t.Helper()
	return testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		return testStore.CreateNotification(ctx, &business.Notification{
			ID: id, UserID: userID, OrgID: orgID,
			Title: "A followed item changed", Body: "doc.renamed", Type: "info",
			ResourceType: resourceType, ResourceID: resourceID,
		})
	})
}

// A follow item's resource reference is what a read-time recheck filters on, so
// it has to survive the write and come back on the read.
func TestNotificationCarriesItsResourceReference(t *testing.T) {
	userID, orgID := followFixture(t)
	id := business.NewIDString()

	require.NoError(t, seedFollowNotification(t, userID, orgID, id, "doc", "doc-1"))

	var notifications []*business.Notification
	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		var err error
		notifications, _, err = testStore.ListNotifications(ctx, userID, 50, "")
		return err
	}))
	require.NotEmpty(t, notifications)
	var found *business.Notification
	for _, n := range notifications {
		if n.ID == id {
			found = n
		}
	}
	require.NotNil(t, found)
	require.Equal(t, "doc", found.ResourceType)
	require.Equal(t, "doc-1", found.ResourceID)
}

// An ordinary notification carries no reference, and the read path must leave it
// that way rather than inventing an empty-string resource.
func TestNotificationWithoutAReferenceStaysUnreferenced(t *testing.T) {
	userID, orgID := followFixture(t)
	id := business.NewIDString()
	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		return testStore.CreateNotification(ctx, &business.Notification{
			ID: id, UserID: userID, OrgID: orgID, Title: "Invitation", Body: "b", Type: "info",
		})
	}))

	var notifications []*business.Notification
	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		var err error
		notifications, _, err = testStore.ListNotifications(ctx, userID, 50, "")
		return err
	}))
	for _, n := range notifications {
		if n.ID == id {
			require.Empty(t, n.ResourceType)
			require.Empty(t, n.ResourceID)
		}
	}
}

// A half-set reference would be unfilterable, which is the one thing the
// reference exists for, so the database refuses it rather than trusting callers.
func TestNotificationResourceReferenceIsWholeOrAbsent(t *testing.T) {
	userID, orgID := followFixture(t)

	for name, columns := range map[string][2]any{
		"type without id": {"doc", nil},
		"id without type": {nil, "doc-1"},
		"empty type":      {"", "doc-1"},
	} {
		t.Run(name, func(t *testing.T) {
			err := testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
				tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared "tx" key
				_, e := tx.Exec(ctx, `
					INSERT INTO notifications (id, user_id, org_id, title, body, type, resource_type, resource_id)
					VALUES (gen_random_uuid(), $1, $2, 'x', 'y', 'info', $3, $4)`,
					userID, orgID, columns[0], columns[1])
				return e
			})
			require.ErrorContains(t, err, "notifications_resource_reference")
		})
	}
}

// The candidate read spans users. Under any one follower's transaction the RLS
// policy would reduce it to that follower, so this is the assertion that the
// control-plane boundary is the right one for it.
func TestListResourceFollowersSpansUsersAndExcludesRevoked(t *testing.T) {
	first, orgID := followFixture(t)
	second := seedUser(t)
	seedOrgMember(t, orgID, second)
	third := seedUser(t)
	seedOrgMember(t, orgID, third)

	follow(t, first, orgID, "doc", "doc-1")
	follow(t, second, orgID, "doc", "doc-1")
	follow(t, third, orgID, "doc", "doc-2")
	require.NoError(t, testStore.WithUserTx(testCtx, second, func(ctx context.Context) error {
		return testStore.RevokeResourceFollow(ctx, second, "doc", "doc-1")
	}))

	var followers []string
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		var err error
		followers, err = testStore.ListResourceFollowers(ctx, orgID, "doc", "doc-1")
		return err
	}))

	require.Equal(t, []string{first}, followers,
		"a revoked follow is not a follower, and another instance's follower is not this one's")
}

// The in-transaction re-read is what makes a follow revoked before it suppress
// the item, and is what stops a replay resurrecting a removed follow.
func TestResourceFollowIsLiveTracksRevocation(t *testing.T) {
	userID, orgID := followFixture(t)
	follow(t, userID, orgID, "doc", "doc-1")

	live := func() bool {
		var result bool
		require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
			var err error
			result, err = testStore.ResourceFollowIsLive(ctx, orgID, userID, "doc", "doc-1")
			return err
		}))
		return result
	}

	require.True(t, live())
	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		return testStore.RevokeResourceFollow(ctx, userID, "doc", "doc-1")
	}))
	require.False(t, live())
	require.False(t, func() bool {
		var result bool
		require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
			var err error
			result, err = testStore.ResourceFollowIsLive(ctx, orgID, userID, "doc", "doc-2")
			return err
		}))
		return result
	}(), "a follow on another instance is not this one")
}
