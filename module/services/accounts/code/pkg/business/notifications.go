package business

import (
	"context"
	"time"

	gen "accounts/pkg/gen/saas/accounts/v1"

	"github.com/codefly-dev/core/wool"
	"github.com/google/uuid"
)

// Notification is the domain representation of a user notification.
type Notification struct {
	ID        string
	UserID    string
	OrgID     string
	Title     string
	Body      string
	Type      string
	ActionURL string
	// ResourceType and ResourceID reference the resource a follow item is about
	// (FOLLOWS.md). They are the owning module's opaque strings and are set
	// together or not at all; an ordinary notification leaves both empty.
	ResourceType string
	ResourceID   string
	ReadAt       *time.Time
	CreatedAt    time.Time
}

// CreateNotificationInput separates delivery policy from presentation.
type CreateNotificationInput struct {
	UserID    string
	OrgID     string
	Title     string
	Body      string
	Type      string
	ActionURL string
	Category  NotificationCategory
	// ResourceType and ResourceID mark the item as being about one resource
	// instance, which is what a read-time visibility recheck filters on.
	ResourceType string
	ResourceID   string
	// IdempotencyKey makes retries of the same delivery command converge on one
	// row. Empty keys create a fresh notification.
	IdempotencyKey string
}

// CreateNotification creates an optional in-app notification when the
// recipient has the channel enabled. Mandatory security notifications are
// written by their owning transaction so a user preference cannot suppress
// account-protection messages.
func (s *Service) CreateNotification(
	ctx context.Context,
	input CreateNotificationInput,
) (*Notification, error) {
	w := wool.Get(ctx).In("CreateNotification")
	mandatory, err := notificationCategoryIsMandatory(input.Category)
	if err != nil {
		return nil, w.Wrapf(err, "cannot create notification")
	}

	var notification *Notification
	if err := s.store.WithUserTx(ctx, input.UserID, func(ctx context.Context) error {
		var settings *gen.UserSettings
		if !mandatory {
			var err error
			settings, err = s.store.GetUserSettings(ctx, input.UserID)
			if err != nil {
				return err
			}
		}
		var err error
		notification, err = s.createNotificationWithSettings(ctx, input, settings)
		return err
	}); err != nil {
		return nil, w.Wrapf(err, "cannot create notification")
	}

	return notification, nil
}

func (s *Service) createNotificationWithSettings(
	ctx context.Context,
	input CreateNotificationInput,
	settings *gen.UserSettings,
) (*Notification, error) {
	decision, err := EvaluateNotificationDelivery(
		settings,
		input.Category,
		NotificationChannelInApp,
	)
	if err != nil {
		return nil, err
	}
	if !decision.Deliver {
		return nil, nil
	}
	if input.Type == "" {
		input.Type = "info"
	}
	notificationID := NewIDString()
	if input.IdempotencyKey != "" {
		notificationID = uuid.NewSHA1(
			uuid.NameSpaceURL,
			[]byte("saas-starter/notification/"+input.IdempotencyKey),
		).String()
	}
	notification := &Notification{
		ID:           notificationID,
		UserID:       input.UserID,
		OrgID:        input.OrgID,
		Title:        input.Title,
		Body:         input.Body,
		Type:         input.Type,
		ActionURL:    input.ActionURL,
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
	}
	if err := s.store.CreateNotification(ctx, notification); err != nil {
		return nil, err
	}
	return notification, nil
}

// ListNotifications returns paginated notifications for a user.
// Wrapped in WithUserTx so the RLS policy on `notifications` filters
// to userID. Without the wrap the SQL still has WHERE user_id = $1
// but returns zero rows under app_tenant + no GUC — fail-closed.
func (s *Service) ListNotifications(ctx context.Context, userID string, pageSize int, pageToken string) ([]*Notification, string, error) {
	if pageSize <= 0 {
		pageSize = 50
	}
	var notifs []*Notification
	var next string
	if err := s.store.WithUserTx(ctx, userID, func(ctx context.Context) error {
		ns, nt, err := s.store.ListNotifications(ctx, userID, pageSize, pageToken)
		notifs, next = ns, nt
		return err
	}); err != nil {
		return nil, "", err
	}
	return notifs, next, nil
}

// GetUnreadCount returns the number of unread notifications for a user.
func (s *Service) GetUnreadCount(ctx context.Context, userID string) (int, error) {
	var count int
	if err := s.store.WithUserTx(ctx, userID, func(ctx context.Context) error {
		c, err := s.store.GetUnreadCount(ctx, userID)
		count = c
		return err
	}); err != nil {
		return 0, err
	}
	return count, nil
}

// MarkRead marks a caller-owned notification as read. Resolve and compare the
// owner before entering the user-scoped transaction so an ID substitution is
// indistinguishable from a missing notification.
func (s *Service) MarkRead(ctx context.Context, callerID, id string) error {
	userID, err := s.resolveNotificationUser(ctx, id)
	if err != nil {
		return err
	}
	if callerID == "" || userID != callerID {
		return wool.Get(ctx).NewError("notification not found")
	}
	return s.store.WithUserTx(ctx, userID, func(ctx context.Context) error {
		return s.store.MarkNotificationRead(ctx, id)
	})
}

// MarkAllRead marks all notifications as read for a user.
func (s *Service) MarkAllRead(ctx context.Context, userID string) error {
	return s.store.WithUserTx(ctx, userID, func(ctx context.Context) error {
		return s.store.MarkAllNotificationsRead(ctx, userID)
	})
}

// DeleteNotification deletes a caller-owned notification. Same owner-bound
// resolution as MarkRead.
func (s *Service) DeleteNotification(ctx context.Context, callerID, id string) error {
	userID, err := s.resolveNotificationUser(ctx, id)
	if err != nil {
		return err
	}
	if callerID == "" || userID != callerID {
		return wool.Get(ctx).NewError("notification not found")
	}
	return s.store.WithUserTx(ctx, userID, func(ctx context.Context) error {
		return s.store.DeleteNotification(ctx, id)
	})
}

// resolveNotificationUser looks up the user_id for a notification
// id. The lookup runs under WithControlPlane — it's a per-request resolve before
// entering the user-scoped tx. MarkRead/DeleteNotification compare this owner
// to the authenticated caller before mutating.
//
// Returns "" + error when the row doesn't exist, so a probe with a
// random id can't be used as an existence oracle.
func (s *Service) resolveNotificationUser(ctx context.Context, id string) (string, error) {
	var userID string
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		u, err := s.store.GetNotificationUserID(ctx, id)
		userID = u
		return err
	}); err != nil {
		return "", err
	}
	if userID == "" {
		return "", wool.Get(ctx).NewError("notification not found")
	}
	return userID, nil
}

// NotifyUser is a convenience helper for internal code to create a simple
// category-aware info notification.
func (s *Service) NotifyUser(
	ctx context.Context,
	userID string,
	category NotificationCategory,
	title string,
	body string,
) error {
	_, err := s.CreateNotification(ctx, CreateNotificationInput{
		UserID: userID, Category: category, Title: title, Body: body,
	})
	return err
}
