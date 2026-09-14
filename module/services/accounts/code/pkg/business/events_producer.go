package business

import (
	"context"
	"encoding/json"
	"time"

	"accounts/pkg/eventcatalog"
	"accounts/pkg/events"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// domainEventSource is the CloudEvents `source` stamped on every domain event
// accounts publishes about its own lifecycle facts. It names the emitting service
// (not a specific aggregate) so a consumer can attribute the fact to the accounts
// control plane. Producers in other namespaces publish through the ModulePublish
// RPC and carry their own source.
const domainEventSource = "saas.accounts"

// publishLifecycleEvent emits one accounts-owned domain event as a request
// producer (the #488 §5 rule): the envelope row is inserted inside the caller's
// WithOrgTx transaction — the transactional outbox — so the fact and its event
// commit together or not at all, and the asynchronous relay fans it out to
// subscribers after commit. Every accounts event partitions on {tenant_id}, so
// partition_key is the tenant; an ordered subscriber therefore sees one org's
// lifecycle in the order it happened.
//
// It is a deliberate no-op when no transport is wired (unit tests that exercise
// only the write path, and any deployment that has not yet enabled eventing), so
// a lifecycle write never gains a hard dependency on the events subsystem. When a
// transport IS wired the publish is inside the tx and its failure rolls the whole
// lifecycle change back — the correct outbox semantics.
func (s *Service) publishLifecycleEvent(ctx context.Context, eventType EventType, tenant, boundary, actor string, data map[string]any) error {
	if s.eventTransport == nil {
		return nil
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	envelope := &events.EventEnvelope{
		Id:               uuid.NewString(),
		Type:             string(eventType),
		Source:           domainEventSource,
		Specversion:      "1.0",
		Datacontenttype:  "application/json",
		Time:             timestamppb.New(time.Now().UTC()),
		Data:             payload,
		TenantId:         tenant,
		BoundaryId:       boundary,
		PartitionKey:     tenant,
		ActorPrincipalId: actor,
	}
	if err := requireFollowableSubject(envelope); err != nil {
		return err
	}
	return s.eventTransport.Publish(ctx, moduleTx(ctx), envelope)
}

// requireFollowableSubject enforces the exact-target rule for a type some
// contribution declared followable: the envelope subject carries the resource id
// the host matches a follow on. Publishing one without a subject would not fail
// anywhere downstream — it would match no follower and deliver nothing, which is
// indistinguishable from a resource nobody follows — so the omission is refused
// here instead. It binds both producers: a module publishing through
// ModulePublishEvent, and this one, which carries no subject of its own and so
// cannot publish a followable type until it is given one.
func requireFollowableSubject(envelope *events.EventEnvelope) error {
	if envelope.GetSubject() != "" {
		return nil
	}
	declared, followable := eventcatalog.LookupFollowable(envelope.GetType())
	if !followable {
		return nil
	}
	return status.Errorf(codes.InvalidArgument,
		"event type %q is declared followable for resource type %q, so its subject must carry the resource id",
		envelope.GetType(), declared.ResourceType)
}
