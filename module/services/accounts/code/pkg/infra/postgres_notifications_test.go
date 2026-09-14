//go:build !pure

package infra_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"accounts/pkg/business"
)

// notifications is RLS-protected by user_id (Phase 2G); each test
// wraps direct Store calls in WithUserTx for the seeded user.

func TestCreateAndListNotifications(t *testing.T) {
	userID := seedUser(t)

	// Each insert in its OWN WithUserTx so created_at increments
	// (CURRENT_TIMESTAMP returns the tx start time — wrapping all
	// 3 in one tx would give them the same value and break the
	// pagination cursor).
	for i := 0; i < 3; i++ {
		n := &business.Notification{
			ID:     business.NewIDString(),
			UserID: userID,
			Title:  "Notif",
			Body:   "Body",
			Type:   "info",
		}
		require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
			return testStore.CreateNotification(ctx, n)
		}))
		time.Sleep(5 * time.Millisecond)
	}

	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		notifs, nextToken, err := testStore.ListNotifications(ctx, userID, 2, "")
		require.NoError(t, err)
		require.Len(t, notifs, 2)
		require.NotEmpty(t, nextToken, "should have a next page token")

		notifs2, nextToken2, err := testStore.ListNotifications(ctx, userID, 2, nextToken)
		require.NoError(t, err)
		require.Len(t, notifs2, 1)
		require.Empty(t, nextToken2, "last page should have no token")
		return nil
	}))
}

func TestCreateNotificationRejectsConflictingIdempotentRetry(t *testing.T) {
	userID := seedUser(t)
	notification := &business.Notification{
		ID: business.NewIDString(), UserID: userID,
		Title: "Payment failed", Body: "Update your payment method.",
		Type: "billing", ActionURL: "/admin/billing",
	}

	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		require.NoError(t, testStore.CreateNotification(ctx, notification))
		require.NoError(t, testStore.CreateNotification(ctx, notification))

		conflict := *notification
		conflict.Body = "Different payload"
		require.ErrorContains(
			t,
			testStore.CreateNotification(ctx, &conflict),
			"idempotency key conflicts",
		)

		notifications, _, err := testStore.ListNotifications(ctx, userID, 20, "")
		require.NoError(t, err)
		require.Len(t, notifications, 1)
		require.Equal(t, notification.Body, notifications[0].Body)
		return nil
	}))
}

func TestGetUnreadCount(t *testing.T) {
	userID := seedUser(t)

	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		for i := 0; i < 3; i++ {
			n := &business.Notification{
				ID:     business.NewIDString(),
				UserID: userID,
				Title:  "Unread",
				Body:   "Body",
				Type:   "info",
			}
			require.NoError(t, testStore.CreateNotification(ctx, n))
		}

		count, err := testStore.GetUnreadCount(ctx, userID)
		require.NoError(t, err)
		require.Equal(t, 3, count)
		return nil
	}))
}

func TestMarkNotificationRead(t *testing.T) {
	userID := seedUser(t)

	n := &business.Notification{
		ID:     business.NewIDString(),
		UserID: userID,
		Title:  "Read me",
		Body:   "Body",
		Type:   "info",
	}
	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		require.NoError(t, testStore.CreateNotification(ctx, n))

		count, err := testStore.GetUnreadCount(ctx, userID)
		require.NoError(t, err)
		require.Equal(t, 1, count)

		require.NoError(t, testStore.MarkNotificationRead(ctx, n.ID))

		count, err = testStore.GetUnreadCount(ctx, userID)
		require.NoError(t, err)
		require.Equal(t, 0, count)

		// Marking again should be a no-op (read_at IS NULL guard).
		require.NoError(t, testStore.MarkNotificationRead(ctx, n.ID))
		return nil
	}))
}

func TestMarkAllNotificationsRead(t *testing.T) {
	userID := seedUser(t)

	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		for i := 0; i < 5; i++ {
			n := &business.Notification{
				ID:     business.NewIDString(),
				UserID: userID,
				Title:  "Bulk read",
				Body:   "Body",
				Type:   "info",
			}
			require.NoError(t, testStore.CreateNotification(ctx, n))
		}

		count, err := testStore.GetUnreadCount(ctx, userID)
		require.NoError(t, err)
		require.Equal(t, 5, count)

		require.NoError(t, testStore.MarkAllNotificationsRead(ctx, userID))

		count, err = testStore.GetUnreadCount(ctx, userID)
		require.NoError(t, err)
		require.Equal(t, 0, count)
		return nil
	}))
}

// The badge is settled from grouped references rather than from the rows
// themselves: only unread rows carrying a reference are grouped, a read row and
// an ordinary notification are not.
func TestListUnreadResourceReferencesGroupsUnreadFollowItems(t *testing.T) {
	userID := seedUser(t)
	orgID := seedOrg(t, userID)

	create := func(resourceType, resourceID string) string {
		n := &business.Notification{
			ID: business.NewIDString(), UserID: userID, OrgID: orgID,
			Title: "Followed resource changed", Body: "It changed", Type: "info",
			ResourceType: resourceType, ResourceID: resourceID,
		}
		require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
			return testStore.CreateNotification(ctx, n)
		}))
		return n.ID
	}

	create("doc", "doc-1")
	create("doc", "doc-1")
	create("doc", "doc-2")
	alreadyRead := create("doc", "doc-3")
	create("", "")

	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		return testStore.MarkNotificationRead(ctx, alreadyRead)
	}))

	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		refs, err := testStore.ListUnreadResourceReferences(ctx, userID)
		require.NoError(t, err)

		unreadByResource := map[string]int{}
		for _, ref := range refs {
			require.Equal(t, orgID, ref.OrgID)
			require.Equal(t, "doc", ref.ResourceType)
			unreadByResource[ref.ResourceID] = ref.Unread
		}
		require.Equal(t, map[string]int{"doc-1": 2, "doc-2": 1}, unreadByResource)
		return nil
	}))
}

func TestDeleteNotification(t *testing.T) {
	userID := seedUser(t)

	n := &business.Notification{
		ID:     business.NewIDString(),
		UserID: userID,
		Title:  "Delete me",
		Body:   "Body",
		Type:   "warning",
	}
	require.NoError(t, testStore.WithUserTx(testCtx, userID, func(ctx context.Context) error {
		require.NoError(t, testStore.CreateNotification(ctx, n))
		require.NoError(t, testStore.DeleteNotification(ctx, n.ID))

		notifs, _, err := testStore.ListNotifications(ctx, userID, 10, "")
		require.NoError(t, err)
		for _, notif := range notifs {
			require.NotEqual(t, n.ID, notif.ID, "deleted notification should not appear")
		}
		return nil
	}))
}
