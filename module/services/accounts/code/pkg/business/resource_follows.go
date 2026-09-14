package business

import (
	"context"

	gen "accounts/pkg/gen/saas/accounts/v1"

	"github.com/codefly-dev/core/wool"
)

// ResourceFollow is one person's durable intent to be told when one specific
// resource instance changes. resource_type and resource_id are the owning
// module's own opaque strings; the host matches on them and never decodes them.
type ResourceFollow struct {
	ID           string
	OrgID        string
	UserID       string
	ResourceType string
	ResourceID   string
}

// followVisibilityAction is what a follower must be able to do on the target for
// it to count as visible to them. A follow is an intent to be told, never a
// capability, so read is both sufficient and necessary here.
const followVisibilityAction = "read"

// Follow records the caller's intent to hear about one resource instance. The
// subject is always the caller — there is no subject field to supply — so this
// can never report on another principal's access.
//
// A target the caller cannot currently see is reported as missing rather than
// denied. The two answers have to be indistinguishable, or Follow becomes an
// existence oracle for resources living in scopes the caller cannot reach.
func (s *Service) Follow(ctx context.Context, userID, orgID, resourceType, resourceID string) (*ResourceFollow, error) {
	w := wool.Get(ctx).In("Follow")
	visible, err := s.resourceIsVisible(ctx, userID, orgID, resourceType, resourceID)
	if err != nil {
		return nil, w.Wrapf(err, "cannot follow resource")
	}
	if !visible {
		return nil, w.NewError("resource not found")
	}
	follow := &ResourceFollow{
		ID:           NewIDString(),
		OrgID:        orgID,
		UserID:       userID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}
	if err := s.store.WithUserTx(ctx, userID, func(ctx context.Context) error {
		return s.store.CreateResourceFollow(ctx, follow)
	}); err != nil {
		return nil, w.Wrapf(err, "cannot follow resource")
	}
	return follow, nil
}

// Unfollow revokes the caller's own follow. It deliberately runs no visibility
// check: withdrawing an intent the caller already holds reveals nothing, and
// someone who has lost access to a resource must still be able to stop hearing
// about it. Unfollowing what was never followed succeeds and reports nothing.
//
// It takes no organization: the follow is revoked wherever the caller holds it,
// so switching the active organization cannot strand a follow the caller can no
// longer reach.
func (s *Service) Unfollow(ctx context.Context, userID, resourceType, resourceID string) error {
	w := wool.Get(ctx).In("Unfollow")
	if err := s.store.WithUserTx(ctx, userID, func(ctx context.Context) error {
		return s.store.RevokeResourceFollow(ctx, userID, resourceType, resourceID)
	}); err != nil {
		return w.Wrapf(err, "cannot unfollow resource")
	}
	return nil
}

// resourceIsVisible resolves the target through the same oracle the fan-out will
// use. CheckAccess resolves the record's true scope from resource_id's own
// registered node, so a follower entitled somewhere else cannot reach a resource
// that lives elsewhere.
func (s *Service) resourceIsVisible(ctx context.Context, userID, orgID, resourceType, resourceID string) (bool, error) {
	var allowed bool
	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		a, _, err := s.store.CheckAccess(ctx, userID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, resourceType, resourceID, followVisibilityAction)
		allowed = a
		return err
	}); err != nil {
		return false, err
	}
	return allowed, nil
}
