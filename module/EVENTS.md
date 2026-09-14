# Domain event contract

Status: pub/sub live (P2). This document is the authoritative standard for
asynchronous, fan-out communication between modules and solutions. The transport
is the durable jobs platform that already ships ([JOBS.md](./JOBS.md)); the
`saas.events.v1` envelope package, the generated event catalog, the
`domain_events` / `event_subscriptions` relations, the relay worker, the SDK
`events` package, and the `ModuleCapabilitiesService` publish/subscribe surface
are all in place — see [Phasing](#phasing) for what remains (P3 convergence).
Nothing here changes the behavior of an existing queue; a command stays a
command.

A **domain event** is an immutable fact that something happened in a tenant,
published once and delivered to every subscriber. This is distinct from a
**command** — work one named consumer must perform — which is today's
point-to-point inbox/outbox and stays exactly as it is. The contract is
product-neutral: any module or solution publishes and consumes through the same
envelope, catalog, and authority rules without inventing a private pub/sub
scheme.

The contract is defined so that adding an external broker later (a JetStream or
similar) is a **transport swap behind one port**, not a rewrite of producers,
consumers, schemas, or authority. The transactional outbox stays even with a
broker: producers write in their own transaction, a relay forwards, and nothing
above the [Transport port](#transport-port) changes.

## Sources of truth

1. This document owns the vocabulary, the envelope semantics, the catalog
   format, the fan-out model, the authority rules, and the consumer guarantees.
2. `services/accounts/proto/saas/events/v1/events.proto` (reserved, [Phasing](#phasing)
   P1) owns the versioned `EventEnvelope` wire vocabulary; its package is
   registered in [CONTRACT_VERSIONING.md](./CONTRACT_VERSIONING.md).
3. `events.codefly.yaml` (schema `codefly/saas/events-contribution/v1`) is the
   per-module declaration of published and consumed event types, a sibling of
   the `permissions-contribution` document under `contracts/`.
4. `deployment/generated/event-catalog.json` is the base-manifest-tracked merge
   of every contribution, produced by `module-compose` like
   `contributed-permissions.json`. Editing it by hand fails the base-integrity
   gate.
5. The durable Postgres representation reuses `job_messages` today; the
   `domain_events` and `event_subscriptions` relations ([Phasing](#phasing) P2)
   own the fan-out state and its tenant RLS boundary.
6. The SDK `events` package owns the `Transport` port, the `PostgresTransport`
   reference implementation, the `FakeTransport` for unit tests, and the
   conformance suite every transport must pass.
7. [JOBS.md](./JOBS.md) owns the durable message lifecycle the Postgres
   transport is built on; [WEBHOOKS.md](./WEBHOOKS.md) owns the outbound-webhook
   delivery path that becomes an `external`-visibility subscriber kind;
   [CONTRACT_VERSIONING.md](./CONTRACT_VERSIONING.md) owns the compatibility
   rules the catalog's breaking-change gate reuses.

## Vocabulary

| Term | Meaning |
| --- | --- |
| **Domain event** | An immutable fact that something happened in a tenant, e.g. `documents.entry.ingested`. Published once, delivered to every subscriber. |
| **Command / job** | Work one specific consumer must perform (today's inbox/outbox). Not fanned out. Unchanged by this contract. |
| **Audit record** | The compliance trail of an action ([the typed audit registry](./docs/adr/0003-typed-audit-event-registry.md)). An event *may* reference an audit id; the audit spine is never a delivery channel. |
| **Subscription** | A durable declaration that consumer `C` receives events matching a topic pattern on queue `Q`. |
| **Resource follow** | A *person's* durable intent to be notified about one resource instance ([FOLLOWS.md](./FOLLOWS.md)). Not a subscription: this row routes a service principal to a queue, and a person holds no queue grant. |
| **Transport** | The mechanism that stores and delivers envelopes. The Postgres outbox today; a broker later, behind the same port. |
| **Partition key** | The ordering domain of an event stream, e.g. `tenant/source`. FIFO is guaranteed only within one partition. |

## Envelope

Every event is carried by one **envelope** whose attributes are the
[CloudEvents 1.0](https://cloudevents.io/) core plus a fixed set of extension
attributes. The envelope is proto-first so producers and consumers share one
generated type across Go, TypeScript, and Python; each extension maps 1:1 to a
CloudEvents extension name so the standard JSON binding round-trips byte-for-byte.

```proto
// package saas.events.v1
message EventEnvelope {
  string id = 1;                  // UUIDv7; the idempotency key at every hop
  string type = 2;                // "<namespace>.<aggregate>.<event>", e.g. documents.entry.ingested
  string source = 3;              // "urn:codefly:<module>/<service>"
  string subject = 4;             // aggregate id, e.g. entry id
  google.protobuf.Timestamp time = 5;
  string specversion = 6;         // "1.0"
  string datacontenttype = 7;     // application/protobuf or application/json
  string dataschema = 8;          // catalog ref: "codefly/events/<type>@<major>"
  bytes  data = 9;                // <= 960 KiB; larger -> claim-check ref in data

  // Extension attributes (CloudEvents extensions; all string-valued on the wire).
  string tenant_id = 20;          // REQUIRED except platform-scope events
  string boundary_id = 21;        // scope node id when the fact belongs to a boundary
  string partition_key = 22;      // maps to JobOrderingKey
  string correlation_id = 23;     // the causal chain root (task id under a Work Context)
  string causation_id = 24;       // the event/command id that caused this one
  string actor_principal_id = 25; // effective actor (agent or human)
  string owner_principal_id = 26; // on-behalf-of, when delegated
  string traceparent = 27;        // W3C trace context
  uint32 schema_version = 28;     // minor within the dataschema major
}
```

Rules:

- `id` is a UUIDv7 and is the idempotency key everywhere — dedupe, `Nats-Msg-Id`,
  and the relay's per-subscription key all derive from it.
- `type` is immutable once published. A breaking change is a new `type` or a new
  major in `dataschema`; it is never a re-typed field under the same name.
- `tenant_id` is required except for platform-scope events published by a
  platform principal.
- `partition_key` is the only ordering knob a producer sets; it is the contract
  form of `JobOrderingKey`. Absent, the event is unordered.
- `data` is capped at 960 KiB — below the 1 MiB `job_messages.payload` cap
  ([JOBS.md](./JOBS.md)) on purpose, so the extension attributes stored beside it
  in the same job row cannot push the message over that limit. Larger payloads
  use a claim-check reference in `data`, never a raised cap.

The Postgres transport stores the envelope in the existing `job_messages` row
with no schema change:

| Job field | Envelope field |
| --- | --- |
| `topic` | `type` |
| `idempotency_key` | `id` |
| `ordering` | `partition_key` |
| `attributes` | the extension attributes (`tenant_id`, `boundary_id`, `correlation_id`, …) |
| `payload` | `data` |
| `source` | `source` |
| `scope` | `tenant_id` (or `global` for platform-scope events) |

## Event catalog

Each module and solution ships one `events.codefly.yaml`, shaped like a
`permissions-contribution` document:

```yaml
schema: codefly/saas/events-contribution/v1
namespace: documents
publishes:
  - type: documents.entry.ingested
    schema: proto/documents/events/v1/entry_ingested.proto#EntryIngested
    visibility: tenant        # internal | tenant | external
    partition: "{tenant_id}/{boundary_id}"
    retention: 30d
consumes:
  - type: datasource.source.changed
    queue: documents.ingest   # must be one of the principal's declared queues
    delivery: ordered         # ordered | unordered
```

`module-compose` merges the contributions named by its `--events` arguments into
`deployment/generated/event-catalog.json` (base-manifest-tracked) and validates:

- **Namespace ownership** — a module publishes only `<its namespace>.*`.
- **Schema resolvable** — every `publishes.schema` names a real proto message.
- **No duplicate types** — a `type` is published by exactly one namespace.
- **Consumes are registered** — every `consumes.type` names a published type,
  and its `queue` is one of the principal's declared queues ([JOBS.md](./JOBS.md)
  authority model).
- **Breaking-change gate** — removing or re-typing a field requires a major bump,
  reusing the [CONTRACT_VERSIONING.md](./CONTRACT_VERSIONING.md) compatibility
  rules. A removed field without a major bump fails compose.
- **Follows are the contribution's own tenant facts** — an optional `follows`
  block names a resource type of this module and the published events worth
  notifying a follower about. Every named event must be published by the *same*
  contribution and declared `visibility: tenant`; the `resource_type` is unique
  across contributions, and no event may be followable under two of them. The
  target is the envelope `subject`, so publishing one of these events with an
  empty `subject` is refused at publish time rather than silently matching
  nobody. See [FOLLOWS.md](./FOLLOWS.md).

Generated projections mirror the typed audit registry: Go typed constants
(`services/accounts/code/pkg/eventcatalog/catalog_gen.go`), an **AsyncAPI 3**
document for humans and tooling (generated, never hand-written), and a docs page
listing who publishes and who consumes each type. TS and Python projections are
[Phasing](#phasing) P3 and are not generated today.

**A solution's own contribution is not discovered automatically yet.**
`module-compose` merges exactly the documents its `--events` arguments name,
which today are this module's own contributions. The Core composition descriptor
has no `events` contribution kind — unlike `permissions`, which it does carry —
so a downstream solution's `events.codefly.yaml` is not collected the way its
permissions contribution is. Two consequences worth stating plainly, because the
platform behaves as if the catalog were complete:

- The catalog contains only this module's types, so `communication.md` and
  `asyncapi.json` describe the module's surface, not a whole deployment's.
- Visibility is classified from the catalog, and a type absent from it is treated
  as **not** internal. A solution-declared `internal` type is therefore fanned
  out to matching subscribers rather than suppressed. Until the descriptor
  carries events, a solution that needs an event kept off tenant queues must not
  rely on `visibility: internal` alone.

## Subscriptions and fan-out

Fan-out is pub/sub semantics implemented on Postgres, with the broker seam kept
behind the [Transport port](#transport-port).

- **Subscriptions are data.** `event_subscriptions(id, subscriber_principal_id,
  type_pattern, queue, delivery, filter jsonb, created_by, created_at,
  revoked_at)` is a control-plane-owned platform relation, materialized from each
  `consumes` entry at compose/install (the per-org install hook for solutions),
  plus runtime CRUD through `ModuleCapabilitiesService.Subscribe / Unsubscribe /
  ListSubscriptions` for dynamic cases. `type_pattern` is matched against the
  envelope `type`: a `consumes.type` from the catalog materializes as an exact
  `type_pattern`; a runtime subscription may instead use a single trailing `.*`
  to match a namespace or aggregate prefix (`documents.*`, `documents.entry.*`),
  which is never valid mid-string. Each matching subscription row is fanned out
  independently, so a subscriber holding two overlapping patterns receives two
  at-least-once deliveries of one event and relies on the `id` dedupe like any
  other duplicate.
- **Publish path (transactional outbox).** `Publish(envelope)` inserts one row
  into `domain_events` (envelope columns + `published_at`, tenant RLS) **in the
  producer's transaction** — the same rule as today's outbox: request producers
  must be inside `WithOrgTx`; modules go through the RPC. At-least-once, keyed on
  `id`.
- **Relay.** A worker on the reserved `events.relay` queue reads unpublished
  `domain_events` in `(partition_key, seq)` order, resolves matching non-revoked
  subscriptions, and enqueues **one inbox job per subscription** —
  `queue := subscription.queue`, `idempotency_key := event.id + ":" +
  subscription.id`, and `ordering := partition_key` when `delivery = ordered` —
  then marks the event relayed. Zero subscribers is legal: the event is still
  durable and replayable.
- **Consume path.** Unchanged `ClaimJobs / Ack / Nack`; the SDK decodes the
  envelope and dispatches by `type`. At-least-once; consumers must be idempotent
  on `event.id`.
- **Replay.** `ReplayEvents(type, tenant, since)` re-fans-out from `domain_events`
  so a consumer that attaches later gets history up to `retention`. It reuses the
  `replay_job_message` semantics and its MFA gate for operators. A webhook
  subscriber that already holds delivery history for an event is **not** sent a
  second copy: the delivery is deduplicated on (subscription, event), which is
  what makes a replay safe to run twice, and the relay reports how many were
  dropped that way. Re-sending to an endpoint that already received one is the
  `ReplayDelivery` RPC ([WEBHOOKS.md](./WEBHOOKS.md)), which mints a new delivery
  for the same event id — so replaying a window re-delivers to module queues and
  to endpoints that had never seen the event, and nothing else.
- **Webhooks are a subscriber kind.** An outbound webhook is an
  `event_subscriptions` row with `delivery = webhook` and the existing
  [WEBHOOKS.md](./WEBHOOKS.md) dispatcher as its consumer. `visibility: external`
  on the catalog is what makes a type eligible. One model instead of two.
  Such a row carries an `org_id` and the endpoint registration it belongs to
  instead of a subscriber principal, and it is derived from that registration
  rather than granted: registering an endpoint for a set of event names creates
  the rows in the same transaction, and deleting it cascades them away. The relay
  confines delivery to the subscription's own organization, because a type
  pattern says nothing about ownership and the relay resolves subscriptions with
  RLS bypassed. Every audit event type is declared `external` and published beside
  its audit record, which is what an endpoint subscribes to.

## Transport port

Every producer and consumer goes through the SDK `events` package over one
interface, so a broker never touches a call site:

```go
type Transport interface {
    Publish(ctx context.Context, tx TxHandle, e *EventEnvelope) error // transactional when tx != nil
    Claim(ctx context.Context, queue string, max int) ([]Leased, error)
    Heartbeat(ctx context.Context, token string) error
    Ack(ctx context.Context, token string) error
    Nack(ctx context.Context, token string, cause error, permanent bool) error
    Replay(ctx context.Context, sel ReplaySelector) (int, error)
}
```

- `PostgresTransport` is today's jobs platform plus the relay — the reference
  implementation.
- A future broker transport maps `type` to a subject, tenant to an account,
  `partition_key` to an ordered consumer, a subscription to a durable consumer
  bound to `queue`, `id` to the broker's message-id dedupe, and ack/nack/term to
  the same three verbs. The outbox stays: publish in the DB transaction, relay to
  the broker.
- A **conformance suite** every transport must pass covers at-least-once, `id`
  dedupe, FIFO per partition, out-of-order across partitions, ack/nack/heartbeat/
  lease expiry, permanent nack to dead-letter, replay, tenant isolation (a
  subscriber in tenant A never sees tenant B), and zero-subscriber publish. A
  consumer written against `FakeTransport` runs unchanged against Postgres.

## Authority

- **Publish** is allowed only for types in the caller principal's declared
  namespace(s) (from the catalog) and only for its bound tenant — or `platform`
  scope for a platform principal. Enforced in `Publish`.
- **Subscribe** is a **grant**. A subscription is created at compose/install from
  a `consumes` entry (admin-consented, like a permission) or at runtime by a
  caller holding `events:subscribe` on the type's namespace. A `visibility:
  internal` type can never be subscribed by a solution principal; only `external`
  types are eligible for webhook delivery. `external` is eligibility to leave the
  platform, not a licence for a module to read the stream: the platform's own
  `saas.*` namespace — the audit spine, published so an organization's endpoints
  can receive it — is refused to a module principal outright. That is the tenant's
  grant over its own records, made through an endpoint it configured, and a module
  does not inherit it by declaring a queue.
- **Deliver.** Every delivered job carries `tenant_id`, `boundary_id`, and
  `actor_principal_id`. A consumer that writes must mint its own authority (an
  installation Work Context at lease time) — the event is a trigger, never a
  capability.
- **Audit.** `event.published` is not audited per event (volume). Subscription
  create/revoke and replay are.

## Guarantees

The properties a consumer may rely on:

| Property | Guarantee |
| --- | --- |
| Delivery | at-least-once per subscription; dedupe on `id` |
| Ordering | FIFO within `partition_key` for `delivery = ordered`; none otherwise |
| Durability | published in the producer's transaction; retained `retention` (default 30d); replayable |
| Isolation | tenant-scoped by construction; RLS on `domain_events`; cross-tenant only for platform principals |
| Schema | additive changes are minor; breaking changes are a new major in `dataschema` (old major kept for at least one release) |
| Size | `data` <= 960 KiB; larger payloads use a claim-check reference |
| Latency | relay tick <= 1 s p50 on Postgres; not a hard real-time channel |

## Commands, events, and audit

Three notions of "event" now have one stated relationship:

- A **command** is inbox/outbox to one queue: work a single named consumer must
  perform. It stays exactly as [JOBS.md](./JOBS.md) defines it. Never hand-enqueue
  to another module's queue.
- A **domain event** is `Publish` plus subscriptions: a fact fanned out to every
  subscriber, governed by this contract.
- An **audit record** is the compliance trail. An event may carry an audit id in
  `causation_id`/`correlation_id`, but the audit spine is never used as a
  delivery channel.

The two systems now share one naming law. Audit event types are
`<namespace>.<aggregate>.<event>` exactly as the `type` attribute above is, and
this module mints only `saas.*` — `saas.auth.login`, `saas.user.created` (issue
#520, amending [ADR 0003](./docs/adr/0003-typed-audit-event-registry.md)). The
constraint is enforced in the database, not just by convention:
`audit_events.event_type` is a foreign key into the `audit_event_types` registry,
and a CHECK requires at least three segments, so a bare `<aggregate>.<event>`
cannot be written. Namespace ownership means the same thing on both sides — a
module publishes only under its own namespace, so two modules composed into one
workspace can never mint the same identifier.

## Migration

No big bang. The existing string topics are reclassified, not rewritten:

1. Register today's fan-out topics as event types, or classify them as commands
   and leave them: `documents.entry.ingested / version_minted / deleted`,
   `approval.decided` (today `documents.approval.resolved`),
   `installation.created / revoked`, `scope.granted / revoked`,
   `datasource.source.changed`. Per-file datasource operations stay commands on
   the `datasource` queue.
2. ~~Move the outbound webhook dispatcher onto subscriptions with
   `delivery = webhook`~~ ([WEBHOOKS.md](./WEBHOOKS.md)) — done.
3. The command-vs-event rule is recorded in [JOBS.md](./JOBS.md).

## Phasing

- **P1 (contract).** This document; the `saas.events.v1` envelope proto; the
  `events-contribution` schema plus `module-compose` validation; the SDK `events`
  package with the `PostgresTransport` mapping onto the existing jobs; the
  conformance suite. No behavior change for existing queues.
- **P2 (pub/sub) — live.** `domain_events` + `event_subscriptions` + the
  `events.relay` worker; `Subscribe / Unsubscribe / ListSubscriptions / Publish /
  ReplayEvents` on `ModuleCapabilitiesService`; the authority rules above.
  Accounts is the first producer (`installation.created / revoked`, `scope.granted
  / revoked`); the `reference` namespace is the first consumer, its `consumes`
  entry materialized into an `event_subscriptions` row at install.
- **P3 (convergence).** Webhooks as subscribers; the AsyncAPI projection
  published; an admin "Events" page (types, subscribers, lag, dead-letters).
- **Later, only if needed.** A broker transport behind the same port, chosen by
  deployment config. The outbox stays.
