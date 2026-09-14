package business_test

import (
	"context"
	"errors"
	"testing"

	"accounts/pkg/business"
	gen "accounts/pkg/gen/saas/accounts/v1"
	"accounts/pkg/usersettings"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type notificationPreferenceStore struct {
	business.Store
	settings      *gen.UserSettings
	settingsErr   error
	notifications []*business.Notification
}

func (store *notificationPreferenceStore) WithUserTx(
	ctx context.Context,
	_ string,
	fn func(context.Context) error,
) error {
	return fn(ctx)
}

func (store *notificationPreferenceStore) GetUserSettings(
	_ context.Context,
	_ string,
) (*gen.UserSettings, error) {
	if store.settingsErr != nil {
		return nil, store.settingsErr
	}
	if store.settings == nil {
		return &gen.UserSettings{}, nil
	}
	return proto.Clone(store.settings).(*gen.UserSettings), nil
}

func (store *notificationPreferenceStore) CreateNotification(
	_ context.Context,
	notification *business.Notification,
) error {
	for _, existing := range store.notifications {
		if existing.ID == notification.ID {
			return nil
		}
	}
	store.notifications = append(store.notifications, notification)
	return nil
}

// notificationVisibilityStore serves a fixed inbox page and a fixed answer from
// the access oracle, so the read-time recheck can be exercised without a scope
// tree. visible is keyed "org|resource_type".
type notificationVisibilityStore struct {
	business.Store
	page         []*business.Notification
	nextToken    string
	unread       int
	unreadRefs   []business.UnreadResourceReference
	visible      map[string][]string
	scopeLookups int
	scopedOrgs   []string
}

func (store *notificationVisibilityStore) WithUserTx(ctx context.Context, _ string, fn func(context.Context) error) error {
	return fn(ctx)
}

func (store *notificationVisibilityStore) WithOrgTx(ctx context.Context, orgID string, fn func(context.Context) error) error {
	store.scopedOrgs = append(store.scopedOrgs, orgID)
	return fn(ctx)
}

func (store *notificationVisibilityStore) ListNotifications(_ context.Context, _ string, _ int, _ string) ([]*business.Notification, string, error) {
	return store.page, store.nextToken, nil
}

func (store *notificationVisibilityStore) GetUnreadCount(_ context.Context, _ string) (int, error) {
	return store.unread, nil
}

func (store *notificationVisibilityStore) ListUnreadResourceReferences(_ context.Context, _ string) ([]business.UnreadResourceReference, error) {
	return store.unreadRefs, nil
}

func (store *notificationVisibilityStore) ListAccessibleResourceIDs(
	_ context.Context, orgID, _ string, _ gen.SubjectKind, resourceType, _ string, candidates []string,
) ([]string, error) {
	store.scopeLookups++
	allowed := store.visible[orgID+"|"+resourceType]
	var out []string
	for _, candidate := range candidates {
		for _, a := range allowed {
			if a == candidate {
				out = append(out, candidate)
			}
		}
	}
	return out, nil
}

func followItem(id, orgID, resourceType, resourceID string) *business.Notification {
	return &business.Notification{
		ID: id, UserID: "user-1", OrgID: orgID, Title: "Followed resource changed",
		Body: "It changed", Type: "info",
		ResourceType: resourceType, ResourceID: resourceID,
	}
}

// The stored title and body are a cache that outlives the grant, so an item
// whose resource is no longer readable must not be returned at all — redacting
// its fields would still concede the item exists.
func TestListNotificationsDropsItemsForUnreadableResources(t *testing.T) {
	store := &notificationVisibilityStore{
		page: []*business.Notification{
			{ID: "plain", UserID: "user-1", OrgID: "org-1", Title: "Welcome", Type: "info"},
			followItem("kept", "org-1", "doc", "doc-1"),
			followItem("revoked", "org-1", "doc", "doc-2"),
		},
		visible: map[string][]string{"org-1|doc": {"doc-1"}},
	}
	service, err := business.NewService(store)
	require.NoError(t, err)

	notifications, _, err := service.ListNotifications(context.Background(), "user-1", 10, "")

	require.NoError(t, err)
	var ids []string
	for _, n := range notifications {
		ids = append(ids, n.ID)
	}
	require.Equal(t, []string{"plain", "kept"}, ids,
		"an ordinary notification and a still-readable follow item survive; a revoked one does not")
}

// A reference with no org cannot be resolved against any scope tree, and
// notifications.org_id is nullable and descriptive. The unanswerable question
// fails closed rather than defaulting to visible.
func TestListNotificationsDropsFollowItemWithoutOrg(t *testing.T) {
	store := &notificationVisibilityStore{
		page:    []*business.Notification{followItem("orphan", "", "doc", "doc-1")},
		visible: map[string][]string{"|doc": {"doc-1"}},
	}
	service, err := business.NewService(store)
	require.NoError(t, err)

	notifications, _, err := service.ListNotifications(context.Background(), "user-1", 10, "")

	require.NoError(t, err)
	require.Empty(t, notifications)
	require.Zero(t, store.scopeLookups, "an org-less reference is never asked about")
}

// The cursor must advance by rows READ, not rows kept: deriving it from the
// filtered page would re-serve the dropped rows' neighbours forever.
func TestListNotificationsKeepsThePageTokenOfRowsRead(t *testing.T) {
	store := &notificationVisibilityStore{
		page:      []*business.Notification{followItem("revoked", "org-1", "doc", "doc-2")},
		nextToken: "cursor-from-rows-read",
	}
	service, err := business.NewService(store)
	require.NoError(t, err)

	notifications, next, err := service.ListNotifications(context.Background(), "user-1", 10, "")

	require.NoError(t, err)
	require.Empty(t, notifications, "the only row on the page is no longer readable")
	require.Equal(t, "cursor-from-rows-read", next, "a fully filtered page still advances the cursor")
}

// One call per (org, resource_type), not one point check per item.
func TestListNotificationsResolvesVisibilityOncePerOrgAndType(t *testing.T) {
	store := &notificationVisibilityStore{
		page: []*business.Notification{
			followItem("a", "org-1", "doc", "doc-1"),
			followItem("b", "org-1", "doc", "doc-2"),
			followItem("c", "org-2", "doc", "doc-3"),
			followItem("d", "org-1", "note", "note-1"),
		},
		visible: map[string][]string{
			"org-1|doc": {"doc-1", "doc-2"}, "org-2|doc": {"doc-3"}, "org-1|note": {"note-1"},
		},
	}
	service, err := business.NewService(store)
	require.NoError(t, err)

	notifications, _, err := service.ListNotifications(context.Background(), "user-1", 10, "")

	require.NoError(t, err)
	require.Len(t, notifications, 4)
	require.Equal(t, 3, store.scopeLookups,
		"four items across three (org, type) groups cost three lookups, not four")
	require.ElementsMatch(t, []string{"org-1", "org-2", "org-1"}, store.scopedOrgs)
}

// The badge is a cache of a past grant too: a count that still moves for a
// revoked resource reports its activity just as the title would.
func TestGetUnreadCountDiscountsUnreadableResources(t *testing.T) {
	store := &notificationVisibilityStore{
		unread: 6,
		unreadRefs: []business.UnreadResourceReference{
			{OrgID: "org-1", ResourceType: "doc", ResourceID: "doc-1", Unread: 1},
			{OrgID: "org-1", ResourceType: "doc", ResourceID: "doc-2", Unread: 2},
			{OrgID: "", ResourceType: "doc", ResourceID: "doc-3", Unread: 1},
		},
		visible: map[string][]string{"org-1|doc": {"doc-1"}},
	}
	service, err := business.NewService(store)
	require.NoError(t, err)

	count, err := service.GetUnreadCount(context.Background(), "user-1")

	require.NoError(t, err)
	require.Equal(t, 3, count,
		"6 unread less the 2 for a revoked resource and the 1 with no resolvable org")
}

// An inbox holding no follow items must cost nothing and read exactly as before.
func TestGetUnreadCountLeavesAnInboxWithoutFollowItemsAlone(t *testing.T) {
	store := &notificationVisibilityStore{unread: 4}
	service, err := business.NewService(store)
	require.NoError(t, err)

	count, err := service.GetUnreadCount(context.Background(), "user-1")

	require.NoError(t, err)
	require.Equal(t, 4, count)
	require.Zero(t, store.scopeLookups, "no references means no visibility call at all")
}

func TestCreateNotificationUsesEnabledDefault(t *testing.T) {
	store := &notificationPreferenceStore{}
	service, err := business.NewService(store)
	require.NoError(t, err)

	notification, err := service.CreateNotification(
		context.Background(),
		business.CreateNotificationInput{
			UserID: "user-1", OrgID: "org-1", Category: business.NotificationCategoryProduct,
			Title: "Invitation", Body: "You have been invited",
			Type: "info", ActionURL: "/invitations/accept?token=token",
		},
	)

	require.NoError(t, err)
	require.NotNil(t, notification)
	require.Len(t, store.notifications, 1)
	require.Equal(t, "/invitations/accept?token=token", store.notifications[0].ActionURL)
}

func TestCreateNotificationSkipsUserOptOut(t *testing.T) {
	settings := &gen.UserSettings{}
	require.NoError(t, usersettings.Fields.Notifications.InApp.Set(settings, false))
	store := &notificationPreferenceStore{settings: settings}
	service, err := business.NewService(store)
	require.NoError(t, err)

	notification, err := service.CreateNotification(
		context.Background(),
		business.CreateNotificationInput{
			UserID: "user-1", Category: business.NotificationCategoryProduct,
			Title: "Optional update", Body: "Body", Type: "info",
		},
	)

	require.NoError(t, err)
	require.Nil(t, notification)
	require.Empty(t, store.notifications)
}

func TestCreateNotificationDoesNotSuppressMandatoryCategories(t *testing.T) {
	settings := &gen.UserSettings{}
	require.NoError(t, usersettings.Fields.Notifications.InApp.Set(settings, false))

	for _, category := range []business.NotificationCategory{
		business.NotificationCategorySecurity,
		business.NotificationCategoryBilling,
	} {
		t.Run(string(category), func(t *testing.T) {
			store := &notificationPreferenceStore{settings: settings}
			service, err := business.NewService(store)
			require.NoError(t, err)

			notification, err := service.CreateNotification(
				context.Background(),
				business.CreateNotificationInput{
					UserID: "user-1", OrgID: "org-1", Category: category,
					Title: "Required update", Body: "Body",
					Type: "warning", ActionURL: "/settings/security",
				},
			)

			require.NoError(t, err)
			require.NotNil(t, notification)
			require.Len(t, store.notifications, 1)
		})
	}
}

func TestCreateNotificationFailsClosedWhenPreferenceCannotBeRead(t *testing.T) {
	store := &notificationPreferenceStore{settingsErr: errors.New("settings unavailable")}
	service, err := business.NewService(store)
	require.NoError(t, err)

	notification, err := service.CreateNotification(
		context.Background(),
		business.CreateNotificationInput{
			UserID: "user-1", Category: business.NotificationCategoryProduct,
			Title: "Optional update", Body: "Body", Type: "security",
		},
	)

	require.Error(t, err)
	require.Nil(t, notification)
	require.Empty(t, store.notifications)
}

func TestCreateNotificationConvergesIdempotentRetries(t *testing.T) {
	store := &notificationPreferenceStore{}
	service, err := business.NewService(store)
	require.NoError(t, err)
	input := business.CreateNotificationInput{
		UserID: "user-1", OrgID: "org-1",
		Title: "Payment failed", Body: "Update your payment method.",
		Type: "billing", Category: business.NotificationCategoryBilling,
		ActionURL: "/admin/billing", IdempotencyKey: "stripe-notification/event-1",
	}

	first, err := service.CreateNotification(context.Background(), input)
	require.NoError(t, err)
	second, err := service.CreateNotification(context.Background(), input)

	require.NoError(t, err)
	require.Equal(t, first.ID, second.ID)
	require.Len(t, store.notifications, 1)
}

func TestCreateNotificationRejectsInvalidCategoryBeforeReadingPreferences(t *testing.T) {
	store := &notificationPreferenceStore{settingsErr: errors.New("settings unavailable")}
	service, err := business.NewService(store)
	require.NoError(t, err)

	notification, err := service.CreateNotification(
		context.Background(),
		business.CreateNotificationInput{
			UserID: "user-1", Category: "unknown",
			Title: "Update", Body: "Body",
		},
	)

	require.ErrorContains(t, err, `notification category "unknown" is invalid`)
	require.Nil(t, notification)
	require.Empty(t, store.notifications)
}
