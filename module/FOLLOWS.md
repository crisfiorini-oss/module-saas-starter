# Resource follow contract

Status: contract only. Nothing in this document is built. It defines how a
**person follows one resource** and receives in-app notice of a committed change
to it, entirely out of facilities that already ship — the domain event journal
and relay ([EVENTS.md](./EVENTS.md)), the durable jobs platform
([JOBS.md](./JOBS.md)), the notification inbox and its category policy
([SETTINGS.md](./SETTINGS.md)), and the host's own access oracles. It adds no
broker, no notification scheduler, no audit spine, and no approval system.

A **resource follow** is a person's durable intent to be told when a specific
resource instance changes. It is deliberately *not* any of the three
subscription concepts this repository already has, and the distinction is the
whole point of this contract:

| Existing concept | What it binds | Why it is not a follow |
| --- | --- | --- |
| Billing subscription | an organization to a plan | commercial, not notification |
| Webhook subscription ([WEBHOOKS.md](./WEBHOOKS.md)) | an org endpoint to event *types* | machine egress, no person, no instance |
| `event_subscriptions` ([EVENTS.md](./EVENTS.md)) | a service **principal** to a **queue** by type pattern | routing authority for a consumer process; a person is not a queue consumer |

Overloading any of them would be wrong on its own terms. `event_subscriptions`
is unique on `(subscriber_principal_id, type_pattern, queue) WHERE revoked_at IS
NULL` and its `queue` must be one the principal's grant declares
(`ModulePrincipalGrant.allowsQueue`, `pkg/business/module_capabilities.go:60`).
Neither key has room for a resource instance, and a human recipient holds no
queue grant.

## Sources of truth

1. This document owns the follow vocabulary, the match rule, the delivery
   identity, the recheck points, and the race semantics.
2. [EVENTS.md](./EVENTS.md) owns the envelope, the catalog, fan-out, and the
   relay this contract rides on. A followable change is an ordinary published
   domain event; this contract adds no new publish path.
3. [SETTINGS.md](./SETTINGS.md) owns the notification category/channel policy,
   including which categories are mandatory. This contract never widens it.
4. [JOBS.md](./JOBS.md) owns the durable delivery lifecycle — attempts, leases,
   backoff, dead-letter — that makes the bridge observable and bounded.
5. `services/accounts/proto/saas/accounts/v1/authorization.proto` and
   `accessible_scopes.proto` own the access oracles (`CheckAccess`,
   `ListAccessibleScopes`, `ListMyAccessibleScopes`) this contract resolves
   eligibility and current visibility through.
6. `services/accounts/proto/saas/accounts/v1/notifications.proto` owns the inbox
   surface; `module_capabilities.proto` owns `NotifyUser`.

## Vocabulary

Four things stay distinct. Collapsing any two is the failure mode this contract
exists to prevent.

| Term | Meaning | Where it lives |
| --- | --- | --- |
| **Resource type** | A module-owned noun (`resource_type`), opaque to the host | already the host's generic vocabulary in `CheckAccess`, `ShareRecord`, `ScopeNode` |
| **Resource instance** | The exact row (`resource_id`), an opaque string the host never joins on | same |
| **Committed event type** | A catalog-declared `type` in the owner's namespace, published only after the owning transaction commits | [EVENTS.md](./EVENTS.md) |
| **Follow preference** | One person's intent to hear about one instance | new, host-owned (below) |

The presentation string on a notification is a fifth, separate thing and is
**not** follow identity. `notifications.type` is constrained at the database to
exactly six values — `info|success|warning|error|billing|security` (migration
`15_platform_features.up.sql:47`, never altered since) — while
`ModuleNotifyUserRequest.type` is a free string of up to 64 characters that no
Go-side code validates (`pkg/business/notifications.go` defaults it to `"info"`
and passes it through). A caller that invents a type string to mark a follow
item passes proto validation and every authority check, then fails at the
`INSERT`. Follow items therefore use `info`; the follow is identified by the
resource reference carried beside the row, never by the presentation type.

## What already exists, and what it is not

This is the reuse review the contract is built on. Each row is verified against
the source named.

| Capability | Status today | What is missing for follows |
| --- | --- | --- |
| Committed owner journal | **Exists.** `domain_events` written inside the producer's transaction by `publish_domain_event` (migration 119), idempotent `ON CONFLICT (id) DO NOTHING`, with a `request_fingerprint` | nothing |
| Durable bridge | **Exists.** The relay (`pkg/infra/event_relay_worker.go`, `RelayOnce`) enqueues one inbox job per matching subscription, `FOR UPDATE SKIP LOCKED`, bounded at `eventDeliveryMaxAttempts = 5` with `relay_attempts` / `last_relay_error` / `dead_lettered_at` (migration 121) | a host-side consumer; see below |
| Event → inbox bridge | **Does not exist.** No code path turns a relayed event into a `notifications` row. Job consumption happens in sibling modules; nothing in this repo claims a queue | the whole bridge |
| Person follows a resource | **Does not exist** anywhere in the repository | the follow relation and its RPCs |
| Idempotent notification write | **Exists.** `pkg/business/notifications.go:95` derives the row id as `uuid.NewSHA1(uuid.NameSpaceURL, "saas-starter/notification/"+idempotency_key)`; `pkg/infra/postgres_notifications.go:11` upserts `ON CONFLICT (id)` with a full payload-equality guard, so an identical retry is a no-op and a same-key/different-payload call errors | a key derived from the right tuple |
| Opt-out suppression | **Exists.** `CreateNotification` returns `nil, nil` when policy suppresses, surfacing as `ModuleNotifyUserResponse.delivered = false` while the call succeeds | nothing |
| Recipient eligibility | **Partial.** `NotifyUser` checks only that the target is an org member (`requireTenantMember`, `module_capabilities.go:233`) | a resource-level check |
| Visibility at read | **Missing.** `GetUnreadCount` is `COUNT(*) WHERE user_id = $1 AND read_at IS NULL` and `ListNotifications` returns the stored `title`/`body`; RLS on `notifications` keys on `user_id` alone (migration 34) and `org_id` is descriptive, not authoritative | the recheck in §Access rechecks |

`saas.document.subscribed` and `saas.document.unsubscribed` exist in the audit
registry (`pkg/business/audit_registry.go:316`) but are emitted nowhere in this
host — they are vocabulary a sibling module writes through the audit surface.
They are an owner's own subscription concept and are **not** follow intent; this
contract neither reads nor duplicates them.

## Followable resources: the declaration

Installation contributes which resources are followable and which committed
changes are meaningful. The host learns this declaratively and never interprets
another module's row schema or imports its code.

The declaration extends the existing events contribution
(`contracts/events/v1/events-contribution.schema.json`), so it is validated at
compose time by the machinery that already validates `publishes`/`consumes`:

```yaml
schema: codefly/saas/events-contribution/v1
namespace: documents
follows:
  - resource_type: documents.entry     # the module's own noun
    events:                            # committed changes worth notifying on
      - documents.entry.version_minted
      - documents.entry.renamed
```

Compose validates, reusing the rules in `tools/composition/composition_events.go`:

- every `events` entry is a type **published by this same contribution** — a
  module cannot declare follows over another namespace's facts;
- the type's `visibility` is `tenant` (not `internal`, which the relay
  short-circuits before any subscriber, and not the platform `saas` namespace,
  which is refused to module principals);
- `resource_type` matches the existing logical-id pattern and is unique across
  contributions.

**The exact target is the envelope `subject`.** For a declared followable type,
`subject` must carry the `resource_id`. This needs no new field and no payload
parsing: `subject` is a CloudEvents core attribute already on `EventEnvelope`
(field 4), and it round-trips end to end — `eventAttributes` writes it at
`pkg/infra/postgres_events.go:988` and the consumer's envelope is rebuilt from
`attributes[attrSubject]` at `:1018`. The host matches on
`(resource_type, subject)` and never decodes `data`. A declared followable event
published with an empty `subject` is a publish-time error, not a silent
non-match.

## Follow intent: ownership

Follow intent is **host-owned**, in its own relation. It is not an
`event_subscriptions` row, for the reasons in the opening table.

```
resource_follows(
  id, org_id, user_id, resource_type, resource_id,
  created_at, revoked_at
)
```

- Unique on `(org_id, user_id, resource_type, resource_id) WHERE revoked_at IS
  NULL`, so following twice is idempotent and **overlapping follows cannot
  produce two deliveries**.
- RLS keyed on `user_id`, matching how `notifications` is already secured
  (migration 34) — a person reads only their own follows.
- `revoked_at` is a soft revoke: unfollow must be a fact with a time, because
  the ordering rule below is defined against it.

Follow and unfollow are authenticated, caller-scoped RPCs — the subject is the
bearer's own principal, never a request field, the way
`ListMyAccessibleScopesRequest` deliberately carries no `subject_id` so it can
never become an oracle about another principal. `Follow` admits only a resource
the caller can currently see; **a denied target is reported as missing**, never
as denied, so follow cannot be used to probe for the existence of resources the
caller cannot access. The inbox already takes this care — `MarkRead` and
`DeleteNotification` resolve the owner before comparing, precisely to avoid a
404-vs-403 oracle (`pkg/business/notifications.go:148`).

## The bridge

The bridge is **host-internal**, and that is what keeps it inside the boundary:

```
owner module                     host (accounts)
────────────                     ───────────────
commit + PublishEvent  ──▶  domain_events  ──▶  relay  ──▶  follows.fanout queue
   (owner's tx)              (the journal)      (durable)          │
                                                                   ▼
                                              match → recheck → CreateNotification
                                                                   │
                                                                   ▼
                                                          notifications (inbox)
```

- The **journal** is `domain_events`: a fact written in the producer's own
  transaction, so only committed owner facts are ever published. No cross-module
  shared transaction or table access is assumed anywhere in this path.
- The **durable bridge** is the existing relay. It already retains the original
  event identity across a lost acknowledgement: the envelope `id` travels in the
  job attributes and at-least-once delivery is the contract.
- The **consumer** is a worker in accounts on a reserved `follows.fanout` queue,
  registered host-side at install exactly as
  `MaterializeSubscriptionsFromCatalog` already creates subscription rows
  through `s.store.CreateEventSubscription`. It is not created through
  `ModuleSubscribe` (which by design refuses the platform namespace and internal
  types); it is a host subscription over the declared followable types. The
  queue name is legal — only `events.relay` is reserved by the `queue` CHECK in
  migration 119.

Because the worker runs in-process in accounts, it resolves access through the
store directly and needs **no new module-facing RPC**. This matters: `CheckAccess`
and `ListAccessibleScopes` live on `PermissionService` at `EXPOSURE_INTERNAL`,
and neither is on `ModuleCapabilitiesService`. A sibling module could not perform
these rechecks itself even if it wanted to.

The host holds no owner-specific branch anywhere in this path: matching is
driven by the declaration, the target by `subject`, and access by the generic
`(resource_type, resource_id)` oracles. Two recipients and two unrelated owning
modules exercise identical host code.

## Delivery identity

One logical inbox item per `(event, target, recipient, channel)`. The delivery
key is:

```
idempotency_key = "follow:" + sha256_hex(
    event_id ‖ resource_type ‖ resource_id ‖ user_id ‖ channel )
```

Two properties of the existing code force this shape, and neither is optional:

1. **It must not be the job's idempotency key.** The relay keys a fan-out job
   `event.id + ":" + subscription.ID` (`postgres_events.go:505`) but a **replay
   deliberately mints a fresh key**, appending `":replay:" + uuid.NewString()`
   (`:817`). A notification keyed off the job would therefore create a *second*
   inbox item on every replay — exactly the "replay silently re-notifies old
   events" failure the acceptance forbids. Keying off the immutable envelope
   `id` instead makes replay converge on the item that already exists.
2. **It must be hashed, to stay in bounds.** `ModuleNotifyUserRequest.idempotency_key`
   is capped at 255 characters; a resource id is an opaque module-chosen string
   with no length bound of its own. The digest is fixed-width, so a long
   resource id cannot silently truncate two distinct resources onto one key.

Given that key, the existing write path already delivers the convergence the
acceptance asks for — duplicate journal delivery, relay restart, overlapping
follows, and a lost `NotifyUser` response all resolve to the same deterministic
row id and hit the no-op branch of the upsert.

## Ordering and race semantics

The decision point is explicit: **the follow set and the delivery preference are
read inside the same user-scoped transaction that writes the notification**
(`WithUserTx`, as `CreateNotification` already does).

- A follow revoked, or an opt-out recorded, **before** that read suppresses the
  item. Nothing is written.
- A follow revoked **after** the row is written does not retract the row. The
  item stays in the inbox, subject to the read-time rechecks below.
- A replay re-reads the current follow set, so **replay never resurrects a
  removed follow**: a revoked follow yields no row, and the delivery key makes a
  still-live follow converge on the existing item rather than duplicate it.

## Access rechecks

Membership alone is insufficient — `NotifyUser` checks only org membership, and
a person can lose access to one resource while remaining a member. Access is
therefore rechecked at **three** points, all through host ports:

1. **Fan-out**, before writing: `CheckAccess(subject, resource_type,
   resource_id, action)`. The record's true scope is resolved from
   `resource_id`'s own registered node — `authorization.proto:298` states there
   is deliberately no caller-supplied scope path — so a follower entitled
   somewhere else cannot be notified about a resource that lives elsewhere.
2. **Inbox read**: `ListNotifications` and `GetUnreadCount` must filter follow
   items by current visibility. Today they do not: both key on `user_id` alone,
   so a revoked resource keeps leaking its **cached title and body** and keeps
   inflating the **unread badge**. The filter uses `ListAccessibleScopes` — the
   list-objects companion built for exactly this ("pre-filter before loading
   content"), one paged call rather than N point checks. It is capped at 1000
   per page, which bounds the read.
3. **Deep-link resolution**: the link is re-authorized when followed. Today
   `action_url` is validated only for shape — `notificationActionUrl`
   (`features/notifications/model/transforms.ts:7`) accepts only a same-origin
   absolute path and the panel simply calls `router.push(actionUrl)`. Shape is
   not authority.

A follow item's stored `title`/`body` must carry no resource-derived content
beyond what the recheck re-authorizes, because those columns are a cache that
outlives the grant.

## Preferences, categories, and what a caller may not claim

Follow notifications are the **`product`** category. `EvaluateNotificationDelivery`
(`pkg/business/notification_policy.go:46`) short-circuits `security` and
`billing` as mandatory *before* any settings read, and validates the category
string, so a consuming application **cannot** mark an ordinary follow item
mandatory merely because it considers it urgent. Reuse is total here: host
preferences, category rules, the inbox, the jobs platform, and the channel
providers are all unchanged.

Acknowledging a notification is **not** a human approval and not a domain
mutation. `MarkRead` sets `read_at` and nothing else. A follow item links to the
current typed interaction; admission of a reply, its application, and any owner
effect remain the owner's own surface — the approvals RPCs already exist
separately and are untouched.

## What this contract does not promise

- **No retraction of already-delivered external mail.** Profile 1 is in-app
  only. Any external channel is qualified independently, with its own content
  policy, and inherits none of this by default.
- **No ordering guarantee across resources.** A non-empty `partition` must
  contain `{tenant_id}` and buys FIFO with a per-partition advisory lock held
  until the producing mutation commits (migration 121) — which on a per-tenant
  partition serializes every producing mutation in the organization. The
  platform's own audit contribution declares no partition for exactly this
  reason. Follows must not declare one either.
- **No claim that a follow grants access.** A follow is an intent to be told,
  never a capability. The event is a trigger; authority is re-derived.

## Dependency this contract rests on

Eligibility and visibility resolve only for a resource that is **placed at a
scope node** (`RegisterScopeNode` with `resource_type`/`resource_id` set);
otherwise `CheckAccess` correctly denies and nothing is ever delivered — the
fail-closed direction, but inert.

`RegisterScopeNode` and `ShareRecord` are `EXPOSURE_AUTHENTICATED` with
`TENANT_REQUIREMENT_ORG_ADMIN`, so an org administrator places any record in the
tenant. A module places its **own** records through
`ModuleCapabilitiesService.PlaceRecord`, bounded by the resource types its
principal grant declares (#703; `services/accounts/AUTHZ.md` § Who may place a
record). Profile 1 therefore holds for module-owned resources as well as
admin-placed ones — but only once the resource is placed by one of the two, and
a module that declares no `resources` still places nothing.

`ShareRecord` remains org-admin only: a module makes its records *resolvable*,
never entitled. Who may read one stays a tenant decision, which is what keeps a
follow an intent to be told rather than a way to widen access.

## Profiles

Each profile is bounded and separately acceptable. Later profiles do not reopen
the increments they build on.

- **Profile 1 — exact follow, in-app.** Follow/unfollow one instance; one
  committed change reaches an authorized follower as one logical inbox item with
  an authorized deep link; the three rechecks; the delivery key above; bounded
  retry with visible disposition through the jobs platform.
- **Profile 2 — scoped type follows and selection filters.** Following a type or
  a filter rather than an instance. Must handle newly matching resources, exits,
  changed filters, and bounded fan-out, and must never expose an inaccessible
  resource. Versioned, because a changed filter changes what a past event would
  have matched.
- **Profile 3 — coalescing, digests, quiet hours.** Many changes to one logical
  item; requires its own acceptance for what a digest may reveal about a
  resource whose access changed inside the window.
- **Profile 4 — external channels.** Email and beyond, with the retraction
  limit stated above qualified independently.
