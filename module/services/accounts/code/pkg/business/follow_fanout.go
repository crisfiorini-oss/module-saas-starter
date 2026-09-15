package business

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

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

	// followFanoutPageSize bounds one page of the follower scan. Nothing limits
	// how many people follow one instance, so the fan-out walks the set in pages:
	// one unbounded scan would hold every follower in memory and in one query,
	// and an attempt failing near the end would repeat every check behind it.
	followFanoutPageSize = 500
)

// FollowFanoutRetryDelay is the backoff between attempts at one event's fan-out.
// It is stated rather than left to the platform default because a fan-out walks
// a whole follower set: coming straight back at a queue whose unit of work is
// that large turns a transient database problem into sustained load.
func FollowFanoutRetryDelay(attempt uint32) time.Duration {
	schedule := [...]time.Duration{
		10 * time.Second,
		1 * time.Minute,
		5 * time.Minute,
		15 * time.Minute,
		1 * time.Hour,
	}
	if attempt == 0 {
		attempt = 1
	}
	if int(attempt) > len(schedule) {
		return schedule[len(schedule)-1]
	}
	return schedule[attempt-1]
}

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
	byEvent := make(map[string]string)
	for _, declared := range declarations {
		for _, eventType := range declared.Events {
			byEvent[eventType] = declared.ResourceType
		}
	}
	// The worker reads these on its own goroutines. Wiring calls this once before
	// the worker starts, but the setter is exported on the Service every request
	// handler holds, so the guard is what keeps a later caller from writing the
	// map out from under a fan-out in flight.
	s.followablesMu.Lock()
	defer s.followablesMu.Unlock()
	s.followables = append([]FollowableResource(nil), declarations...)
	s.followableByEvent = byEvent
}

// followableResourceType resolves a published event type to the followable
// resource it reports a change to.
func (s *Service) followableResourceType(eventType string) (string, bool) {
	s.followablesMu.RLock()
	defer s.followablesMu.RUnlock()
	resourceType, declared := s.followableByEvent[eventType]
	return resourceType, declared
}

// declaredFollowables returns a snapshot of the declarations, so materialization
// walks a stable list rather than the live one.
func (s *Service) declaredFollowables() []FollowableResource {
	s.followablesMu.RLock()
	defer s.followablesMu.RUnlock()
	return append([]FollowableResource(nil), s.followables...)
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
	resourceType, declared := s.followableResourceType(eventType)
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

	// The follower set is walked one bounded page at a time, keyed on the last
	// user id seen. A retry re-walks the pages, but the already-written
	// recipients are filtered out of each one, so the cost of an attempt is
	// proportional to the work left rather than to the whole set.
	cursor := ""
	for {
		var page []string
		if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
			var err error
			page, err = s.store.ListResourceFollowers(
				ctx, orgID, resourceType, resourceID, cursor, followFanoutPageSize)
			return err
		}); err != nil {
			return err
		}
		if len(page) == 0 {
			return nil
		}
		pending, err := s.undeliveredFollowers(ctx, eventID, resourceType, resourceID, page)
		if err != nil {
			return err
		}
		for _, userID := range pending {
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
		if len(page) < followFanoutPageSize {
			return nil
		}
		cursor = page[len(page)-1]
	}
}

// undeliveredFollowers drops the recipients an earlier attempt already wrote.
// The notification id is derived from the delivery key, so the row's presence is
// the durable record of that work — no separate progress state is needed, and
// the filter cannot disagree with what the write path would converge on.
//
// This skips work, and decides nothing. A follower whose item was suppressed by
// preference has no row to find, so a retry re-evaluates them and reaches the
// same decision; a follower who deleted the item has no row either, so a replay
// writes it again exactly as it did before this filter existed. Suppression
// remains the job of the follow and preference reads inside the writing
// transaction.
func (s *Service) undeliveredFollowers(
	ctx context.Context, eventID, resourceType, resourceID string, page []string,
) ([]string, error) {
	ids := make([]string, 0, len(page))
	userByID := make(map[string]string, len(page))
	for _, userID := range page {
		id := notificationIDForKey(followDeliveryKey(
			eventID, resourceType, resourceID, userID, NotificationChannelInApp))
		ids = append(ids, id)
		userByID[id] = userID
	}
	var existing map[string]struct{}
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		var err error
		existing, err = s.store.ExistingNotificationIDs(ctx, ids)
		return err
	}); err != nil {
		return nil, err
	}
	pending := make([]string, 0, len(page))
	for _, id := range ids {
		if _, delivered := existing[id]; !delivered {
			pending = append(pending, userByID[id])
		}
	}
	return pending, nil
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
// capped at 255 characters.
//
// Each part is length-prefixed rather than joined on a separator. resource_id is
// the envelope subject — an arbitrary module-supplied string that has never been
// through PostgreSQL — so no byte can be assumed absent from it, and a separator
// appearing inside a part would let two distinct tuples render to one preimage.
func followDeliveryKey(eventID, resourceType, resourceID, userID string, channel NotificationChannel) string {
	digest := sha256.New()
	for _, part := range []string{eventID, resourceType, resourceID, userID, string(channel)} {
		fmt.Fprintf(digest, "%d:%s", len(part), part)
	}
	return "follow:" + hex.EncodeToString(digest.Sum(nil))
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
	declaredTypes := map[string]struct{}{}
	for _, declared := range s.declaredFollowables() {
		for _, eventType := range declared.Events {
			declaredTypes[eventType] = struct{}{}
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
	return s.revokeUndeclaredFollowSubscriptions(ctx, principal, declaredTypes)
}

// revokeUndeclaredFollowSubscriptions retires the host's subscriptions whose
// type is no longer declared followable. Materialization would otherwise only
// ever insert: withdrawing a `follows:` entry, or renaming an event type, would
// leave the old row live and the relay would go on enqueueing a job per publish
// forever, each one acknowledged as a no-op because the type resolves to no
// followable resource. It only ever touches rows on the follow queue, so a
// subscription the host holds for any other reason is out of its reach.
func (s *Service) revokeUndeclaredFollowSubscriptions(
	ctx context.Context, principal string, declaredTypes map[string]struct{},
) error {
	w := wool.Get(ctx).In("revokeUndeclaredFollowSubscriptions")
	var live []*EventSubscription
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		var err error
		live, err = s.store.ListEventSubscriptions(ctx, principal)
		return err
	}); err != nil {
		return w.Wrapf(err, "cannot read host follow subscriptions")
	}
	for _, sub := range live {
		if sub.Queue != FollowFanoutQueue {
			continue
		}
		if _, declared := declaredTypes[sub.TypePattern]; declared {
			continue
		}
		if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
			revoked, err := s.store.RevokeEventSubscription(ctx, sub.ID, principal)
			if err != nil || !revoked {
				return err
			}
			return s.emitTx(ctx, principal, "agent", EventEventSubscriptionRevoked,
				"event_subscription", sub.ID, "", map[string]any{
					"subscription_id": sub.ID,
					"type_pattern":    sub.TypePattern,
					"queue":           sub.Queue,
				})
		}); err != nil {
			return w.Wrapf(err, "cannot revoke undeclared follow subscription for %q", sub.TypePattern)
		}
	}
	return nil
}
