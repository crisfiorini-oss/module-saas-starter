package business_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

	"accounts/pkg/business"
	"accounts/pkg/events"
	gen "accounts/pkg/gen/saas/accounts/v1"
	jobsv1 "accounts/pkg/gen/saas/jobs/v1"
	"accounts/pkg/jobs"
	"accounts/pkg/usersettings"

	"github.com/stretchr/testify/require"
)

// followFanoutStore is the seam the bridge runs against: the three transaction
// wrappers collapse to the caller's context, and every read the fan-out makes is
// answerable without a database. It mirrors the one property of the real write
// path the convergence tests depend on — CreateNotification is keyed on the
// derived row id, so an identical retry is a no-op rather than a second row.
type followFanoutStore struct {
	business.Store

	followers map[string][]string // "org|type|id" -> user ids
	revoked   map[string]bool     // "org|user|type|id" -> follow no longer live
	denied    map[string]bool     // "org|user|type|id" -> CheckAccess says no
	settings  map[string]*gen.UserSettings

	notifications  map[string]*business.Notification // row id -> row
	writes         int                               // every CreateNotification call, converged or not
	accessChecks   int
	followerReads  int
	existenceReads int
	ignoreExisting bool // simulate a concurrent attempt: the filter sees no prior row
	checkAccessErr error
}

func newFollowFanoutStore() *followFanoutStore {
	return &followFanoutStore{
		followers:     map[string][]string{},
		revoked:       map[string]bool{},
		denied:        map[string]bool{},
		settings:      map[string]*gen.UserSettings{},
		notifications: map[string]*business.Notification{},
	}
}

func followKey(parts ...string) string {
	key := ""
	for _, part := range parts {
		key += part + "|"
	}
	return key
}

func (s *followFanoutStore) WithControlPlane(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (s *followFanoutStore) WithOrgTx(ctx context.Context, _ string, fn func(context.Context) error) error {
	return fn(ctx)
}

func (s *followFanoutStore) WithUserTx(ctx context.Context, _ string, fn func(context.Context) error) error {
	return fn(ctx)
}

// ListResourceFollowers emulates the real keyset page: ordered by user id,
// strictly after the cursor, capped at limit. A fake that ignored the cursor
// would let a pagination bug pass.
func (s *followFanoutStore) ListResourceFollowers(
	_ context.Context, orgID, resourceType, resourceID, after string, limit int,
) ([]string, error) {
	s.followerReads++
	all := append([]string(nil), s.followers[followKey(orgID, resourceType, resourceID)]...)
	sort.Strings(all)
	page := make([]string, 0, limit)
	for _, userID := range all {
		if after != "" && userID <= after {
			continue
		}
		if len(page) == limit {
			break
		}
		page = append(page, userID)
	}
	return page, nil
}

func (s *followFanoutStore) ExistingNotificationIDs(_ context.Context, ids []string) (map[string]struct{}, error) {
	s.existenceReads++
	existing := map[string]struct{}{}
	if s.ignoreExisting {
		return existing, nil
	}
	for _, id := range ids {
		if _, ok := s.notifications[id]; ok {
			existing[id] = struct{}{}
		}
	}
	return existing, nil
}

func (s *followFanoutStore) ResourceFollowIsLive(_ context.Context, orgID, userID, resourceType, resourceID string) (bool, error) {
	return !s.revoked[followKey(orgID, userID, resourceType, resourceID)], nil
}

func (s *followFanoutStore) CheckAccess(
	_ context.Context, subjectID string, _ gen.SubjectKind, resourceType, resourceID, action string,
) (bool, string, error) {
	s.accessChecks++
	if s.checkAccessErr != nil {
		return false, "", s.checkAccessErr
	}
	// The fan-out recheck must ask the same question Follow admitted the target
	// under; a widened action here would notify on access the follow never had.
	if action != "read" {
		return false, "unexpected action", nil
	}
	return !s.denied[followKey("org", subjectID, resourceType, resourceID)], "", nil
}

func (s *followFanoutStore) GetUserSettings(_ context.Context, userID string) (*gen.UserSettings, error) {
	if settings, ok := s.settings[userID]; ok {
		return settings, nil
	}
	return &gen.UserSettings{}, nil
}

func (s *followFanoutStore) CreateNotification(_ context.Context, n *business.Notification) error {
	s.writes++
	if _, exists := s.notifications[n.ID]; exists {
		return nil
	}
	stored := *n
	s.notifications[n.ID] = &stored
	return nil
}

const (
	followOrg          = "org"
	followResourceType = "documents.entry"
	followResourceID   = "entry-1"
	followEventType    = "documents.entry.renamed"
)

func followService(t *testing.T, store business.Store) *business.Service {
	t.Helper()
	service, err := business.NewService(store)
	require.NoError(t, err)
	service.SetFollowables([]business.FollowableResource{
		{ResourceType: followResourceType, Events: []string{followEventType, "documents.entry.version_minted"}},
	})
	return service
}

// followJob is one relayed delivery. jobKey is the relay's own idempotency key,
// which a replay deliberately mints afresh; the tests vary it to prove the
// delivery identity does not follow it.
func followJob(eventID, jobKey string) *jobsv1.JobEnvelope {
	return &jobsv1.JobEnvelope{
		Topic:          followEventType,
		IdempotencyKey: jobKey,
		Scope:          &jobsv1.JobScope{Value: &jobsv1.JobScope_OrganizationId{OrganizationId: followOrg}},
		Attributes:     map[string]string{"id": eventID, "subject": followResourceID},
	}
}

func TestFollowFanoutWritesOneItemForAnAuthorizedFollower(t *testing.T) {
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = []string{"user-1"}
	service := followService(t, store)

	require.NoError(t, service.FollowFanoutHandler()(context.Background(), followJob("event-1", "event-1:sub-1")))

	require.Len(t, store.notifications, 1)
	for _, notification := range store.notifications {
		require.Equal(t, "user-1", notification.UserID)
		require.Equal(t, followOrg, notification.OrgID)
		require.Equal(t, followResourceType, notification.ResourceType)
		require.Equal(t, followResourceID, notification.ResourceID)
		// The six values notifications.type is CHECK-constrained to at the
		// database do not include a follow-specific one, and the proto field is
		// unvalidated — an invented type would pass here and fail at the INSERT.
		require.Equal(t, "info", notification.Type)
		// Title and body outlive the grant, so they carry no instance content.
		require.NotContains(t, notification.Title, followResourceID)
		require.NotContains(t, notification.Body, followResourceID)
	}
}

// TestFollowFanoutConvergesOnReplay is the acceptance the delivery key exists
// for. A replay re-fans the same event out under a freshly minted job key; an
// item keyed off that job would be a second row in the inbox every time.
func TestFollowFanoutConvergesOnReplay(t *testing.T) {
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = []string{"user-1"}
	service := followService(t, store)
	handler := service.FollowFanoutHandler()

	require.NoError(t, handler(context.Background(), followJob("event-1", "event-1:sub-1")))
	require.NoError(t, handler(context.Background(),
		followJob("event-1", "event-1:sub-1:replay:9f1c7c1e-0000-4000-8000-000000000001")))
	// A duplicate journal delivery on the original key lands on the same row too.
	require.NoError(t, handler(context.Background(), followJob("event-1", "event-1:sub-1")))

	require.Len(t, store.notifications, 1, "all three converge on one inbox item")
	require.Equal(t, 1, store.writes,
		"the later deliveries are filtered before the write path rather than deduplicated inside it")
}

// TestFollowFanoutConvergesWhenTwoAttemptsRace keeps the write path's own
// convergence honest. The already-delivered filter is an optimisation and cannot
// see a concurrent attempt: two workers on the same event both find no row and
// both write. The derived row id is what makes that land on one item.
func TestFollowFanoutConvergesWhenTwoAttemptsRace(t *testing.T) {
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = []string{"user-1"}
	store.ignoreExisting = true // both attempts observe an empty inbox, as a race would
	service := followService(t, store)
	handler := service.FollowFanoutHandler()

	require.NoError(t, handler(context.Background(), followJob("event-1", "k1")))
	require.NoError(t, handler(context.Background(), followJob("event-1", "k2")))

	require.Equal(t, 2, store.writes, "both attempts reach the write path")
	require.Len(t, store.notifications, 1, "and converge on one row by derived id")
}

// TestFollowFanoutDistinctEventsProduceDistinctItems is the other half of the
// key's contract: convergence must not collapse genuinely different changes.
func TestFollowFanoutDistinctEventsProduceDistinctItems(t *testing.T) {
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = []string{"user-1"}
	service := followService(t, store)
	handler := service.FollowFanoutHandler()

	require.NoError(t, handler(context.Background(), followJob("event-1", "k1")))
	require.NoError(t, handler(context.Background(), followJob("event-2", "k2")))

	require.Len(t, store.notifications, 2)
}

// TestFollowFanoutSuppressesARevokedFollow pins the ordering rule: the follow is
// re-read inside the transaction that writes, so a replay cannot resurrect a
// follow that was withdrawn after the original delivery.
func TestFollowFanoutSuppressesARevokedFollow(t *testing.T) {
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = []string{"user-1"}
	store.revoked[followKey(followOrg, "user-1", followResourceType, followResourceID)] = true
	service := followService(t, store)

	require.NoError(t, service.FollowFanoutHandler()(context.Background(), followJob("event-1", "k1")))

	require.Empty(t, store.notifications)
	require.Zero(t, store.writes)
}

func TestFollowFanoutSuppressesAFollowerWhoLostAccess(t *testing.T) {
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = []string{"user-1", "user-2"}
	store.denied[followKey(followOrg, "user-1", followResourceType, followResourceID)] = true
	service := followService(t, store)

	require.NoError(t, service.FollowFanoutHandler()(context.Background(), followJob("event-1", "k1")))

	require.Len(t, store.notifications, 1)
	for _, notification := range store.notifications {
		require.Equal(t, "user-2", notification.UserID)
	}
}

func TestFollowFanoutHonoursTheDeliveryPreference(t *testing.T) {
	optedOut := &gen.UserSettings{}
	require.NoError(t, usersettings.Fields.Notifications.InApp.Set(optedOut, false))
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = []string{"user-1"}
	store.settings["user-1"] = optedOut
	service := followService(t, store)

	require.NoError(t, service.FollowFanoutHandler()(context.Background(), followJob("event-1", "k1")))

	require.Empty(t, store.notifications, "an opt-out suppresses the item and is not an error")
}

// TestFollowFanoutIgnoresAnUndeclaredType proves the bridge is inert until a
// contribution declares a followable resource — the state the composed catalog
// is in today — and that it reads nothing before deciding.
func TestFollowFanoutIgnoresAnUndeclaredType(t *testing.T) {
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = []string{"user-1"}
	service, err := business.NewService(store)
	require.NoError(t, err)

	require.NoError(t, service.FollowFanoutHandler()(context.Background(), followJob("event-1", "k1")))

	require.Zero(t, store.followerReads)
	require.Zero(t, store.accessChecks)
	require.Empty(t, store.notifications)
}

// TestFollowFanoutDeadLettersAnIncompleteJob keeps uncertainty visible: a
// declared followable type is published with a subject or not at all, so a job
// without one is an upstream defect that retrying cannot fix.
func TestFollowFanoutDeadLettersAnIncompleteJob(t *testing.T) {
	for name, mutate := range map[string]func(*jobsv1.JobEnvelope){
		"no subject":  func(j *jobsv1.JobEnvelope) { delete(j.Attributes, "subject") },
		"no event id": func(j *jobsv1.JobEnvelope) { delete(j.Attributes, "id") },
		"no tenant":   func(j *jobsv1.JobEnvelope) { j.Scope = nil },
	} {
		t.Run(name, func(t *testing.T) {
			store := newFollowFanoutStore()
			service := followService(t, store)
			job := followJob("event-1", "k1")
			mutate(job)

			err := service.FollowFanoutHandler()(context.Background(), job)

			var processing *jobs.ProcessingError
			require.ErrorAs(t, err, &processing)
			require.False(t, processing.Retryable, "a malformed job must not burn the retry budget")
			require.Empty(t, store.notifications)
		})
	}
}

// TestFollowFanoutRetriesATransientFailure is the other disposition: a read that
// fails for an environmental reason must stay retryable rather than dead-letter,
// so the jobs platform can bound and surface it.
func TestFollowFanoutRetriesATransientFailure(t *testing.T) {
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = []string{"user-1"}
	store.checkAccessErr = errors.New("connection reset")
	service := followService(t, store)

	err := service.FollowFanoutHandler()(context.Background(), followJob("event-1", "k1"))

	require.Error(t, err)
	var processing *jobs.ProcessingError
	require.False(t, errors.As(err, &processing),
		"a transient failure must not be reported as a bounded permanent one")
}

// TestFollowFanoutIsOwnerNeutral is the reuse proof: two recipients and two
// unrelated owning modules run the same host code, with no branch on either
// resource type.
func TestFollowFanoutIsOwnerNeutral(t *testing.T) {
	const otherType, otherResource, otherEvent = "tickets.issue", "issue-7", "tickets.issue.closed"
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = []string{"user-1", "user-2"}
	store.followers[followKey(followOrg, otherType, otherResource)] = []string{"user-1", "user-2"}
	service, err := business.NewService(store)
	require.NoError(t, err)
	service.SetFollowables([]business.FollowableResource{
		{ResourceType: followResourceType, Events: []string{followEventType}},
		{ResourceType: otherType, Events: []string{otherEvent}},
	})
	handler := service.FollowFanoutHandler()

	require.NoError(t, handler(context.Background(), followJob("event-1", "k1")))
	other := followJob("event-2", "k2")
	other.Topic = otherEvent
	other.Attributes["subject"] = otherResource
	require.NoError(t, handler(context.Background(), other))

	require.Len(t, store.notifications, 4, "two recipients on each of two owners")
	byResource := map[string]int{}
	for _, notification := range store.notifications {
		byResource[notification.ResourceType]++
	}
	require.Equal(t, 2, byResource[followResourceType])
	require.Equal(t, 2, byResource[otherType])
}

// TestFollowFanoutSeparatesRecipients proves the recipient is part of the
// delivery identity: overlapping followers get one item each, never one shared.
func TestFollowFanoutSeparatesRecipients(t *testing.T) {
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = []string{"user-1", "user-2"}
	service := followService(t, store)

	require.NoError(t, service.FollowFanoutHandler()(context.Background(), followJob("event-1", "k1")))

	recipients := map[string]bool{}
	for _, notification := range store.notifications {
		recipients[notification.UserID] = true
	}
	require.Equal(t, map[string]bool{"user-1": true, "user-2": true}, recipients)
}

// TestFollowFanoutPagesAnUnboundedFollowerSet is the bound on the unit of work.
// Nothing limits how many people follow one instance, so a fan-out that read the
// whole set would hold it in memory and in one query; this proves it walks the
// set in bounded pages and still reaches the last follower.
func TestFollowFanoutPagesAnUnboundedFollowerSet(t *testing.T) {
	store := newFollowFanoutStore()
	followers := make([]string, 0, 1200)
	for i := 0; i < 1200; i++ {
		followers = append(followers, fmt.Sprintf("user-%04d", i))
	}
	store.followers[followKey(followOrg, followResourceType, followResourceID)] = followers
	service := followService(t, store)

	require.NoError(t, service.FollowFanoutHandler()(context.Background(), followJob("event-1", "k1")))

	require.Len(t, store.notifications, 1200, "every follower is reached across pages")
	require.Equal(t, 3, store.followerReads, "1200 followers is three pages of 500, not one unbounded read")
}

// TestFollowFanoutSkipsRecipientsAnEarlierAttemptWrote is the retry-cost bound: a
// job that failed near the end of a large follower set must not redo the access
// check and the write for everyone behind it.
func TestFollowFanoutSkipsRecipientsAnEarlierAttemptWrote(t *testing.T) {
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, followResourceID)] =
		[]string{"user-1", "user-2", "user-3"}
	service := followService(t, store)
	handler := service.FollowFanoutHandler()

	require.NoError(t, handler(context.Background(), followJob("event-1", "k1")))
	require.Equal(t, 3, store.writes)
	writesAfterFirst, checksAfterFirst := store.writes, store.accessChecks

	// The same event again — a relay redelivery or a replay under a fresh job key.
	require.NoError(t, handler(context.Background(), followJob("event-1", "k1:replay:abc")))

	require.Equal(t, writesAfterFirst, store.writes, "already-written recipients are not re-written")
	require.Equal(t, checksAfterFirst, store.accessChecks, "nor re-access-checked")
	require.Len(t, store.notifications, 3, "and the inbox still holds exactly one item each")
}

// TestFollowDeliveryKeyDoesNotCollideOnEmbeddedSeparators pins the delivery key's
// shape. resource_id is the envelope subject — an arbitrary module-supplied
// string — so a key that joined its parts on a separator would let these two
// distinct tuples hash to one preimage and collapse two people's items into one.
func TestFollowDeliveryKeyDoesNotCollideOnEmbeddedSeparators(t *testing.T) {
	store := newFollowFanoutStore()
	store.followers[followKey(followOrg, followResourceType, "a\x00b")] = []string{"c"}
	store.followers[followKey(followOrg, followResourceType, "a")] = []string{"b\x00c"}
	service := followService(t, store)
	handler := service.FollowFanoutHandler()

	first := followJob("event-1", "k1")
	first.Attributes["subject"] = "a\x00b"
	second := followJob("event-1", "k2")
	second.Attributes["subject"] = "a"

	require.NoError(t, handler(context.Background(), first))
	require.NoError(t, handler(context.Background(), second))

	require.Len(t, store.notifications, 2,
		"same event id, shifted split between resource id and user id: these are different deliveries")
}

// followSubscriptionStore is the seam for host subscription materialization.
type followSubscriptionStore struct {
	business.Store
	subs    []*business.EventSubscription
	revoked []string
	nextID  int
}

func (s *followSubscriptionStore) WithControlPlane(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (s *followSubscriptionStore) CreateEventSubscription(
	_ context.Context, sub *business.EventSubscription,
) (*business.EventSubscription, bool, error) {
	for _, existing := range s.subs {
		if existing.SubscriberPrincipalID == sub.SubscriberPrincipalID &&
			existing.TypePattern == sub.TypePattern && existing.Queue == sub.Queue {
			return existing, false, nil
		}
	}
	s.nextID++
	stored := *sub
	stored.ID = fmt.Sprintf("sub-%d", s.nextID)
	s.subs = append(s.subs, &stored)
	return &stored, true, nil
}

func (s *followSubscriptionStore) ListEventSubscriptions(
	_ context.Context, principal string,
) ([]*business.EventSubscription, error) {
	var live []*business.EventSubscription
	for _, sub := range s.subs {
		if sub.SubscriberPrincipalID == principal {
			live = append(live, sub)
		}
	}
	return live, nil
}

func (s *followSubscriptionStore) RevokeEventSubscription(
	_ context.Context, subscriptionID, principal string,
) (bool, error) {
	for i, sub := range s.subs {
		if sub.ID == subscriptionID && sub.SubscriberPrincipalID == principal {
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
			s.revoked = append(s.revoked, subscriptionID)
			return true, nil
		}
	}
	return false, nil
}

// TestMaterializeFollowSubscriptionsCreatesRowsTheRelayWouldMatch covers the
// path every fan-out test takes for granted. Those tests hand the handler a job
// directly; nothing else asserts that a subscription exists for the relay to
// enqueue through, so a wrong queue or a missing principal would leave the
// bridge silently inert with the whole suite green.
func TestMaterializeFollowSubscriptionsCreatesRowsTheRelayWouldMatch(t *testing.T) {
	const secondEvent = "documents.entry.version_minted"
	store := &followSubscriptionStore{}
	service, err := business.NewService(store)
	require.NoError(t, err)
	service.SetFollowables([]business.FollowableResource{
		{ResourceType: followResourceType, Events: []string{followEventType, secondEvent}},
	})

	require.NoError(t, service.MaterializeFollowSubscriptions(context.Background()))

	require.Len(t, store.subs, 2)
	for _, sub := range store.subs {
		// Migration 134's subscriber_kind CHECK refuses a non-webhook row with no
		// principal, and migration 119's queue CHECK reserves events.relay.
		require.Equal(t, business.ModulePrincipalID("follows"), sub.SubscriberPrincipalID)
		require.NotEqual(t, "events.relay", sub.Queue)
		// A partitioned followable type on an ordered subscription would serialize
		// every producing mutation in the organization.
		require.Equal(t, string(events.DeliveryUnordered), sub.Delivery)
	}
	// The queue the subscription routes to must be the queue the worker claims,
	// and the pattern must be one the relay's matcher actually selects.
	for _, eventType := range []string{followEventType, secondEvent} {
		matched := false
		for _, sub := range store.subs {
			if sub.Queue == business.FollowFanoutQueue && events.Matches(sub.TypePattern, eventType) {
				matched = true
			}
		}
		require.Truef(t, matched, "no subscription on %s matches %s; the relay would enqueue nowhere",
			business.FollowFanoutQueue, eventType)
	}

	require.NoError(t, service.MaterializeFollowSubscriptions(context.Background()))
	require.Len(t, store.subs, 2, "re-materializing converges on the rows that exist")
	require.Empty(t, store.revoked)
}

// TestMaterializeFollowSubscriptionsRevokesAWithdrawnDeclaration stops the host
// accumulating subscriptions forever. Without it, dropping a follows: entry
// leaves the row live and the relay keeps enqueueing a job per publish that the
// handler can only acknowledge as a no-op.
func TestMaterializeFollowSubscriptionsRevokesAWithdrawnDeclaration(t *testing.T) {
	const withdrawn = "documents.entry.version_minted"
	store := &followSubscriptionStore{}
	service, err := business.NewService(store)
	require.NoError(t, err)
	service.SetFollowables([]business.FollowableResource{
		{ResourceType: followResourceType, Events: []string{followEventType, withdrawn}},
	})
	require.NoError(t, service.MaterializeFollowSubscriptions(context.Background()))
	require.Len(t, store.subs, 2)

	service.SetFollowables([]business.FollowableResource{
		{ResourceType: followResourceType, Events: []string{followEventType}},
	})
	require.NoError(t, service.MaterializeFollowSubscriptions(context.Background()))

	require.Len(t, store.subs, 1)
	require.Equal(t, followEventType, store.subs[0].TypePattern)
	require.Len(t, store.revoked, 1, "the withdrawn declaration's subscription is retired, not left live")
}
