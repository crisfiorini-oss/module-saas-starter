package business

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"accounts/pkg/events"
	gen "accounts/pkg/gen/saas/accounts/v1"
	jobsv1 "accounts/pkg/gen/saas/jobs/v1"
	"accounts/pkg/jobs"

	"github.com/codefly-dev/core/wool"
)

const (
	// FollowFanoutQueue is the host's own queue for the follow bridge. The queue
	// CHECK in migration 119 reserves only events.relay, so this is an ordinary
	// subscriber queue like any module's.
	FollowFanoutQueue = "follows.fanout"

	// followSubscriberPrefix names the principal the host's follow subscriptions
	// belong to. Migration 134's subscriber_kind CHECK requires a non-null
	// principal on every non-webhook subscription, and ModulePrincipalID derives
	// a stable UUIDv5 from this name, so every boot converges on the same rows
	// rather than accumulating new ones.
	followSubscriberPrefix = "follows"

	// followNotificationType is the presentation type of a follow item.
	// notifications.type is CHECK-constrained to six values at the database while
	// the proto field is a free string no Go-side code validates, so an invented
	// type would pass every check and then fail at the INSERT. A follow is
	// identified by the resource reference beside the row, never by this string.
	followNotificationType = "info"

	// The relay stamps the envelope's CloudEvents attributes onto the job it
	// enqueues (eventAttributes in pkg/infra). These are the two the bridge reads
	// back: the immutable event identity the delivery key is built on, and the
	// subject that carries the resource id for a declared followable type.
	followEventIDAttribute      = "id"
	followEventSubjectAttribute = "subject"
)

// FollowableResource is one declared followable noun and the committed changes
// worth notifying on. It is the host's port onto the events contribution's
// `follows:` block: the wiring site adapts the composed catalog onto it, so the
// bridge holds no owner-specific knowledge and two unrelated owning modules
// exercise identical code here.
type FollowableResource struct {
	ResourceType string
	Events       []string
}

// SetFollowables declares which resources are followable and which committed
// changes reach their followers. Compose guarantees an event type is claimed by
// at most one resource type, so the index is a function rather than a multimap.
// Declaring nothing leaves the bridge inert: every event resolves to no
// followable resource and is acknowledged without a read.
func (s *Service) SetFollowables(declarations []FollowableResource) {
	s.followables = append([]FollowableResource(nil), declarations...)
	s.followableByEvent = make(map[string]string, len(declarations))
	for _, declared := range declarations {
		for _, eventType := range declared.Events {
			s.followableByEvent[eventType] = declared.ResourceType
		}
	}
}

// FollowFanoutHandler is the host-internal consumer of the follows.fanout queue.
// Because it runs in-process it resolves access through the store directly and
// needs no module-facing RPC — CheckAccess is an internal PermissionService
// method a sibling module could not call even if it wanted to.
func (s *Service) FollowFanoutHandler() jobs.Handler {
	return func(ctx context.Context, envelope *jobsv1.JobEnvelope) error {
		return s.fanOutFollowNotifications(ctx, envelope)
	}
}

func (s *Service) fanOutFollowNotifications(ctx context.Context, envelope *jobsv1.JobEnvelope) error {
	eventType := envelope.GetTopic()
	resourceType, declared := s.followableByEvent[eventType]
	if !declared {
		return nil
	}
	eventID := envelope.GetAttributes()[followEventIDAttribute]
	resourceID := envelope.GetAttributes()[followEventSubjectAttribute]
	orgID := envelope.GetScope().GetOrganizationId()
	// A declared followable type is published with a subject or not at all, and
	// the relay carries both the identity and the tenant on every job. Missing
	// any of them is a defect upstream, not a transient condition, so it
	// dead-letters with a visible disposition instead of retrying five times.
	if eventID == "" || resourceID == "" || orgID == "" {
		return jobs.NewProcessingError(
			"follows.invalid_job", "follow fan-out job lacks event identity, subject, or tenant", false)
	}

	var followers []string
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		var err error
		followers, err = s.store.ListResourceFollowers(ctx, orgID, resourceType, resourceID)
		return err
	}); err != nil {
		return err
	}

	for _, userID := range followers {
		// A failure part-way through retries the whole job, re-delivering to the
		// followers already written. The delivery key is what makes that converge
		// on the rows that exist rather than duplicate them.
		if err := s.deliverFollowNotification(ctx, followDelivery{
			EventID:      eventID,
			EventType:    eventType,
			OrgID:        orgID,
			UserID:       userID,
			ResourceType: resourceType,
			ResourceID:   resourceID,
		}); err != nil {
			return err
		}
	}
	return nil
}

// followDelivery is one candidate delivery: one committed change, one resource,
// one recipient.
type followDelivery struct {
	EventID      string
	EventType    string
	OrgID        string
	UserID       string
	ResourceType string
	ResourceID   string
}

func (s *Service) deliverFollowNotification(ctx context.Context, delivery followDelivery) error {
	w := wool.Get(ctx).In("follows.fanout",
		wool.Field("event_id", delivery.EventID),
		wool.Field("resource_type", delivery.ResourceType))

	// Membership is insufficient: a person can lose access to one resource and
	// remain a member of the organization. CheckAccess resolves the record's true
	// scope from the resource id's own registered node, so a follower entitled
	// somewhere else cannot be told about a resource that lives elsewhere. The
	// action is the one Follow admitted the target under, so access can only have
	// been lost, never widened, between the two points.
	var allowed bool
	if err := s.store.WithOrgTx(ctx, delivery.OrgID, func(ctx context.Context) error {
		a, _, err := s.store.CheckAccess(ctx, delivery.UserID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL,
			delivery.ResourceType, delivery.ResourceID, followVisibilityAction)
		allowed = a
		return err
	}); err != nil {
		return w.Wrapf(err, "cannot resolve follower access")
	}
	if !allowed {
		return nil
	}

	// The follow and the delivery preference are read inside the same
	// user-scoped transaction that writes the notification. That is what makes
	// the documented ordering rule hold: a follow revoked, or an opt-out
	// recorded, before this read suppresses the item, and a replay re-reading a
	// revoked follow writes nothing rather than resurrecting it.
	return s.store.WithUserTx(ctx, delivery.UserID, func(ctx context.Context) error {
		live, err := s.store.ResourceFollowIsLive(ctx,
			delivery.OrgID, delivery.UserID, delivery.ResourceType, delivery.ResourceID)
		if err != nil {
			return err
		}
		if !live {
			return nil
		}
		settings, err := s.store.GetUserSettings(ctx, delivery.UserID)
		if err != nil {
			return err
		}
		_, err = s.createNotificationWithSettings(ctx, CreateNotificationInput{
			UserID: delivery.UserID,
			OrgID:  delivery.OrgID,
			// Title and body are a cache that outlives the grant, so they carry no
			// instance content — only catalog-declared vocabulary. What the item is
			// about lives in the resource reference, which a read-time recheck can
			// re-authorize; a stored title cannot.
			Title:        "A followed item changed",
			Body:         delivery.EventType,
			Type:         followNotificationType,
			Category:     NotificationCategoryProduct,
			ResourceType: delivery.ResourceType,
			ResourceID:   delivery.ResourceID,
			IdempotencyKey: followDeliveryKey(delivery.EventID, delivery.ResourceType,
				delivery.ResourceID, delivery.UserID, NotificationChannelInApp),
		}, settings)
		return err
	})
}

// followDeliveryKey is the identity of one logical inbox item per
// (event, target, recipient, channel).
//
// It deliberately does not derive from the relay's job key. The relay keys a
// fan-out job `event.id + ":" + subscription.ID`, but a replay mints a fresh one
// by appending a nonce, so a notification keyed off the job would create a
// second inbox item on every replay. Keying off the immutable envelope id makes
// a replay converge on the item that already exists.
//
// Hashing is what keeps the key in bounds: a resource id is an opaque
// module-chosen string with no length limit of its own, and idempotency_key is
// capped at 255 characters. The parts are joined on NUL, which a PostgreSQL TEXT
// value cannot contain, so two distinct tuples can never render to one input.
func followDeliveryKey(eventID, resourceType, resourceID, userID string, channel NotificationChannel) string {
	digest := sha256.Sum256([]byte(strings.Join(
		[]string{eventID, resourceType, resourceID, userID, string(channel)}, "\x00")))
	return "follow:" + hex.EncodeToString(digest[:])
}

// MaterializeFollowSubscriptions creates the host's own subscriptions over every
// declared followable type, the way MaterializeSubscriptionsFromCatalog already
// creates subscription rows for an installed solution. These are not created
// through ModuleSubscribe, which by design refuses the platform namespace and
// internal types; they are host subscriptions the composition declared.
//
// It runs on the control plane (event_subscriptions has no tenant RLS) and is
// idempotent: CreateEventSubscription collapses a re-materialization onto the
// existing live row, so a restart never doubles a subscription and only a
// genuinely new row is audited.
//
// Delivery is unordered by construction. An ordered subscription would take a
// per-partition advisory lock held until the producing mutation commits, and on
// the per-tenant partition a followable type declares that would serialize every
// producing mutation in the organization.
func (s *Service) MaterializeFollowSubscriptions(ctx context.Context) error {
	w := wool.Get(ctx).In("MaterializeFollowSubscriptions")
	principal := ModulePrincipalID(followSubscriberPrefix)
	for _, declared := range s.followables {
		for _, eventType := range declared.Events {
			if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
				sub, inserted, err := s.store.CreateEventSubscription(ctx, &EventSubscription{
					SubscriberPrincipalID: principal,
					TypePattern:           eventType,
					Queue:                 FollowFanoutQueue,
					Delivery:              string(events.DeliveryUnordered),
					CreatedBy:             principal,
				})
				if err != nil {
					return err
				}
				if !inserted {
					return nil
				}
				return s.emitTx(ctx, principal, "agent", EventEventSubscriptionCreated,
					"event_subscription", sub.ID, "", map[string]any{
						"subscription_id":         sub.ID,
						"subscriber_principal_id": sub.SubscriberPrincipalID,
						"type_pattern":            sub.TypePattern,
						"queue":                   sub.Queue,
					})
			}); err != nil {
				return w.Wrapf(err, "cannot materialize follow subscription for %q", eventType)
			}
		}
	}
	return nil
}
