package business

import (
	"context"
	"errors"
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

// UnreadResourceReference is one resource the user's unread inbox refers to,
// with how many unread rows carry it — enough to settle the badge without
// reading the rows themselves.
type UnreadResourceReference struct {
	OrgID        string
	ResourceType string
	ResourceID   string
	Unread       int
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
		notificationID = notificationIDForKey(input.IdempotencyKey)
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

// notificationIDForKey derives the deterministic row id an idempotency key
// resolves to, which is what makes an identical retry converge on one row. A
// caller that needs to know whether a keyed delivery already exists derives the
// id through this rather than restating the rule.
func notificationIDForKey(idempotencyKey string) string {
	return uuid.NewSHA1(
		uuid.NameSpaceURL,
		[]byte("saas-starter/notification/"+idempotencyKey),
	).String()
}

// ListNotifications returns paginated notifications for a user, less any follow
// item whose resource they can no longer see.
//
// The page is read under WithUserTx so the RLS policy on `notifications` filters
// to userID. Without the wrap the SQL still has WHERE user_id = $1 but returns
// zero rows under app_tenant + no GUC — fail-closed.
//
// The page token is the one the store derived from the rows it READ, not from
// the rows kept: paging advances by rows read, so a heavily filtered page
// shortens rather than stalling the cursor or skipping the rows behind it.
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

	refs := make([]resourceRef, 0, len(notifs))
	for _, n := range notifs {
		if n.ResourceType != "" {
			refs = append(refs, resourceRef{n.OrgID, n.ResourceType, n.ResourceID})
		}
	}
	visible, err := s.visibleResources(ctx, userID, refs)
	if err != nil {
		return nil, "", err
	}

	kept := make([]*Notification, 0, len(notifs))
	for _, n := range notifs {
		if n.ResourceType != "" && !visible[resourceRef{n.OrgID, n.ResourceType, n.ResourceID}] {
			continue
		}
		kept = append(kept, n)
	}
	return kept, next, nil
}

// GetUnreadCount returns the number of unread notifications for a user, less any
// follow item whose resource they can no longer see. The badge is as much a
// cache of a past grant as the stored title and body are, and leaks the same way
// — a count that still moves for a revoked resource reports its activity.
//
// The total and the unread references are read in one user-scoped transaction,
// so a concurrent MarkRead cannot be counted in the total and missed in the
// references, which would subtract an item twice.
func (s *Service) GetUnreadCount(ctx context.Context, userID string) (int, error) {
	var count int
	var refs []UnreadResourceReference
	if err := s.store.WithUserTx(ctx, userID, func(ctx context.Context) error {
		c, err := s.store.GetUnreadCount(ctx, userID)
		if err != nil {
			return err
		}
		rs, err := s.store.ListUnreadResourceReferences(ctx, userID)
		count, refs = c, rs
		return err
	}); err != nil {
		return 0, err
	}
	if len(refs) == 0 {
		return count, nil
	}

	candidates := make([]resourceRef, 0, len(refs))
	for _, r := range refs {
		candidates = append(candidates, resourceRef{r.OrgID, r.ResourceType, r.ResourceID})
	}
	visible, err := s.visibleResources(ctx, userID, candidates)
	if err != nil {
		return 0, err
	}
	for _, r := range refs {
		if !visible[resourceRef{r.OrgID, r.ResourceType, r.ResourceID}] {
			count -= r.Unread
		}
	}
	return count, nil
}

// resourceRef is the resource a follow item points at, in the vocabulary the
// inbox row and the access oracles both speak.
type resourceRef struct {
	orgID        string
	resourceType string
	resourceID   string
}

// visibleResources reports which refs the user may currently read, as one
// org-scoped call per (org, resource_type) rather than a point check per item.
//
// Visibility is resolved in its own pass rather than as a join with the inbox:
// `notifications` is gated by app.current_user_id and the scope tree by
// app.current_org_id, each helper sets only its own GUC and neither may nest, so
// a single statement spanning both would fail closed on one side.
//
// A reference carrying no org cannot be resolved against a scope tree at all, so
// it never enters the result and its item is dropped: notifications.org_id is
// descriptive and nullable, and an unanswerable visibility question fails closed.
func (s *Service) visibleResources(ctx context.Context, userID string, refs []resourceRef) (map[resourceRef]bool, error) {
	type group struct {
		orgID        string
		resourceType string
	}
	byGroup := map[group][]string{}
	for _, ref := range refs {
		if ref.orgID == "" {
			continue
		}
		g := group{ref.orgID, ref.resourceType}
		byGroup[g] = append(byGroup[g], ref.resourceID)
	}

	visible := make(map[resourceRef]bool, len(refs))
	for g, ids := range byGroup {
		var allowed []string
		if err := s.store.WithOrgTx(ctx, g.orgID, func(ctx context.Context) error {
			var err error
			allowed, err = s.store.ListAccessibleResourceIDs(ctx, g.orgID, userID,
				gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, g.resourceType, "read", ids)
			return err
		}); err != nil {
			return nil, err
		}
		for _, id := range allowed {
			visible[resourceRef{g.orgID, g.resourceType, id}] = true
		}
	}
	return visible, nil
}

// ErrNotificationNotFound reports that no notification with this id is readable
// by the caller. A follow item whose resource the caller may no longer see
// reports exactly this error too: the two answers have to be indistinguishable,
// or following a link becomes an existence oracle for a revoked resource.
var ErrNotificationNotFound = errors.New("notification not found")

// ResolveNotificationAction re-authorizes a notification's deep link at the
// moment it is followed, and returns where to go.
//
// The stored action_url is a cache of a past grant, exactly as the title and
// body beside it are. Filtering the inbox at read time narrows the window but
// cannot close it: a page fetched at T is filtered against visibility at T, and
// the link may be followed minutes later, after a revocation, from a page still
// holding the item. So the resource is rechecked here — one point check, since
// exactly one resource is in question.
//
// The row is read under the caller's own user-scoped transaction, so the RLS
// policy on `notifications` rather than a comparison in Go is what makes another
// user's id indistinguishable from an absent one.
func (s *Service) ResolveNotificationAction(ctx context.Context, userID, id string) (string, error) {
	w := wool.Get(ctx).In("ResolveNotificationAction")
	var notification *Notification
	if err := s.store.WithUserTx(ctx, userID, func(ctx context.Context) error {
		n, err := s.store.GetNotification(ctx, id)
		notification = n
		return err
	}); err != nil {
		return "", w.Wrapf(err, "cannot resolve notification action")
	}
	if notification == nil || notification.ActionURL == "" {
		return "", ErrNotificationNotFound
	}
	if notification.ResourceType == "" {
		return notification.ActionURL, nil
	}
	// An org-less reference cannot be resolved against a scope tree at all, and
	// notifications.org_id is descriptive and nullable, so the unanswerable
	// question fails closed.
	if notification.OrgID == "" {
		return "", ErrNotificationNotFound
	}
	visible, err := s.resourceIsVisible(ctx, userID, notification.OrgID, notification.ResourceType, notification.ResourceID)
	if err != nil {
		return "", w.Wrapf(err, "cannot resolve notification action")
	}
	if !visible {
		return "", ErrNotificationNotFound
	}
	return notification.ActionURL, nil
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
