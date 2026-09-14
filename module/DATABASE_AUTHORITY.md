# Database authority

Status: runtime-role baseline, ownership separation, complete relation
inventory, exact request/control-plane/worker grants, and removal of the
application-settable RLS bypass are implemented. Physical credential isolation
remains open under `P2-DB-002` and `P2-DB-006`.

The Starter owns database roles, grants, RLS policy shape, and worker authority.
Installed products add tables through additive migration sources and must opt
each relation into a role explicitly. They do not widen the Starter's default
privileges or reuse a worker role for unrelated work.

## Managed PostgreSQL profile

The opt-in [managed baseline v1](services/store/baselines/managed-v1/CONTRACT.md)
installs the canonical schema through 135 followed by migration 136 using a
PostgreSQL 16+ CREATEROLE migration principal without SUPERUSER or BYPASSRLS.
All five runtime roles are NOBYPASSRLS. Explicit exact-role policies provide the
four background roles' existing row visibility; tenant policies, FORCE RLS and
relation/column ACLs remain intact. Three guarded function owners change, and
subscription sync retains its schema owner with one SELECT-only endpoint policy.
Missing/empty enqueue request scope now fails closed. Runtime ledger privileges
are revoked. Read the linked contract before selecting a fresh or upgrade plan.

The table below describes legacy installations. The normal source remains the
upgrade path: migration 136 does not claim to revoke existing BYPASSRLS role
attributes. Fresh and upgrade packages use the same normal migration ledger;
profile selection is explicit and bound to the reviewed source hashes.

## Request connection ownership

The authenticated request boundary uses the published service-postgres `Open`
constructor. That primitive owns the separate reader/writer pools, startup pings,
failure cleanup and repeated-close safety. Accounts supplies its verified identity
adapter and transaction-local `app.current_org_id` / `app.current_user_id` settings.
Its current request adapter issues Readers only; authentication alone does not
grant a Writer.

When `POSTGRES_TOKEN_FILE` is configured, `WithAccessTokenProvider` rereads that
bounded projected file for every new physical connection. The intentionally
separate legacy/control-plane pool adapts the same provider into its existing pgx
hook and retains explicit `app_tenant` / `app_control_plane` role selection. An
unset file preserves local URL credentials. Token projection and its atomic
replacement remain deployment responsibilities.

Accounts still validates its explicit verified-TLS/private-proxy transport policy
before construction, including distinct reader/writer proxy sockets. Shared
transport-policy parsing is a separate primitive extension; adopting the shared
pool constructor does not change connection-policy acceptance or grant new
control-plane authority.

## Roles

| Role | Login | RLS bypass | Intended authority |
|---|---:|---:|---|
| migration principal | yes | owner | Schema changes, role/grant reconciliation, migrations only |
| `app_tenant` | no | no | Tenant and user request transactions constrained by forced RLS |
| `app_control_plane` | no | yes | Audited pre-auth, bootstrap, platform administration, retention, and cross-tenant account operations |
| `app_billing_worker` | no | yes | Stripe subscription catalog reads and reconciliation writes only |
| `app_webhook_worker` | no | yes | Webhook subscription reads and delivery-history projection only |
| `app_job_worker` | no | yes | Product-neutral job messages, attempts, transitions, and scoped enqueue operation only |

All application roles are `NOLOGIN`, `NOINHERIT`, `NOSUPERUSER`,
`NOCREATEDB`, `NOCREATEROLE`, and `NOREPLICATION`. The tenant role cannot
assume the control-plane or any worker role. Roles use `BYPASSRLS` only for
operations that inherently span scopes; explicit grants remain the second
enforcement boundary. `app_control_plane` has DML on every non-worker,
non-job-platform application relation and no job relation or lifecycle
authority. Its only job-platform capability is the narrowly checked global
outbox enqueue operation described below.
The Codefly-managed runtime session is separately tested as non-superuser,
non-`BYPASSRLS`, unable to create roles/databases, and not the owner of any
application relation. Every application relation has the same owner as the
migration ledger, and application roles likewise own no relations.

## Fail-closed migration rule

Migration `61_runtime_role_baseline` removes tenant `TRUNCATE`, schema creation,
temporary-table authority, and all automatic future table/sequence grants.
`TRUNCATE` is forbidden to the tenant role because PostgreSQL does not apply RLS
to it.

Every new table migration must therefore:

1. classify the relation as tenant, user, global catalog, or worker-owned;
2. enable and force RLS for tenant/user relations;
3. create operation-specific policies without an application-settable bypass;
4. grant only the required operations to `app_tenant`, `app_control_plane`, or
   one named worker role;
5. add grant, policy, and cross-role tests in the accounts infrastructure suite.

There are no default application-role privileges to catch a forgotten grant.
A missing grant fails deployment tests or the first operation loudly instead of
making an unreviewed table writable.

## Global catalog grants

Migration `62_global_catalog_grants` removes the historical full-CRUD grant
from every relation that intentionally has no tenant RLS. Forward migration
`95_feature_flags_read_only` additionally removes all runtime write authority
from the retired feature-flag inventory.

| Relation | `app_tenant` authority | Other authority |
|---|---|---|
| `identity_providers` | select | migration principal writes |
| `plans`, `plan_entitlements` | select | migration principal writes; billing worker selects `plans` |
| `email_templates` | select | migration principal writes |
| `data_retention_policies` | select | migration principal writes |
| `bootstrap_state` | select, update | migration principal seeds |
| `feature_flags` | select | migration principal writes; runtime inventory is read-only |
| `platform_admins` | select, insert, update, delete | platform-super-admin/bootstrap application gates |

The infrastructure suite checks every operation in this matrix, including the
absence of `TRUNCATE`.

## Tenant and user relation grants

Migrations `63_request_relation_grants`, `64_delegation_grant_authority`,
`66_team_member_upsert_authority`, and `124_privacy_durable_execution`
replace historical full CRUD with the following exact `app_tenant` authority.
All tenant/user rows remain constrained by their forced RLS policies.

| Authority | Relations |
|---|---|
| select, insert | `audit_events`, `role_permissions`, `usage_events` |
| select, insert, update | `api_keys`, `delegation_grants`, `entitlement_overrides`, `invitations`, `org_settings`, `organizations`, `principals`, `subscriptions`, `usage_totals`, `webhook_deliveries` |
| select, insert, delete | `role_assignments`, `roles` |
| select, insert, update, delete | `audit_export_configs`, `organization_members`, `team_members`, `teams`, `webhook_subscriptions` |
| select, insert, update | `onboarding_progress`, `resource_follows`, `sessions`, `users`, `webauthn_ceremonies`, `webauthn_credentials` |
| select, insert | `gdpr_requests` (accepted by request traffic, transitioned only by the leased privacy worker under the control plane) |
| select, insert, update, delete | `mfa_backup_codes`, `mfa_devices`, `notifications`, `user_identities` |
| insert only | `mfa_login_transactions` |
| no tenant relation authority | `job_attempts`, `job_messages`, `job_state_transitions`, `magic_links`, `membership_integrity_findings` |

Retention deletes and token-based pre-auth reads/updates use the audited
control-plane boundary; they are intentionally not granted to `app_tenant`.
The infrastructure suite compares PostgreSQL's complete public-table inventory
to this executable matrix, so adding a table without classifying and granting
it fails the gate.

## Scope and RLS inventory

Every public application relation carries exactly one scope, and the scope
decides the required database boundary. This table is the documented copy of the
executable inventory `relationsByScope` in
`services/accounts/code/pkg/infra/postgres_role_hardening_test.go`; the two are
compared relation-by-relation by `TestDatabaseAuthorityScopeInventoryMatchesCode`
in `tools`, which fails on any drift in either direction. The third column is
held to the same source by `TestDatabaseAuthorityBoundaryMatchesCode`, which
reads the RLS verdict out of that suite's own per-scope predicate — so a row
cannot claim a boundary the database is not held to. Add a relation to the
executable inventory and this table in the same change.

| Scope | Relations | Required database boundary |
|---|---|---|
| `global` | `audit_event_types`, `bootstrap_state`, `data_retention_policies`, `email_templates`, `feature_flags`, `identity_providers`, `plan_entitlements`, `plans`, `platform_admins`, `solution_registrations` | No RLS; exact grants |
| `tenant` | `actor_chain_journal`, `actor_chain_revocations`, `api_keys`, `approval_decisions`, `approval_requests`, `audit_event_idempotency`, `audit_events`, `connector_credentials`, `dashboards`, `datasource_sources`, `delegation_grants`, `domain_events`, `entitlement_overrides`, `execution_custody`, `installations`, `invitations`, `membership_integrity_findings`, `org_generic_settings`, `org_identity_providers`, `org_settings`, `organization_activations`, `organization_authorization_revisions`, `organization_members`, `organizations`, `principal_authorization_revisions`, `principals`, `record_shares`, `role_assignments`, `role_permissions`, `roles`, `scope_grants`, `scope_nodes`, `source_read_revisions`, `subscriptions`, `team_members`, `team_membership_quarantine`, `teams`, `usage_events`, `usage_totals`, `webhook_deliveries`, `webhook_subscriptions`, `work_context_replay` | Enabled and forced RLS with at least one policy |
| `user` | `gdpr_requests`, `mfa_backup_codes`, `mfa_devices`, `mfa_login_transactions`, `notifications`, `onboarding_progress`, `resource_follows`, `sessions`, `user_consent_events`, `user_consent_preferences`, `user_identities`, `users`, `webauthn_ceremonies`, `webauthn_credentials` | Enabled and forced RLS with at least one policy |
| `pre_auth` | `magic_links`, `waitlist_entries` | Enabled and forced RLS; fail-closed request policy, accessed only by the control-plane role |
| `job` | `job_messages` | Enabled and forced RLS with at least one policy; no request relation grant — function-only scoped enqueue plus exact job-worker grants |
| `worker` | `analytics_deliveries`, `email_delivery_events`, `event_subscriptions`, `job_attempts`, `job_state_transitions` | No RLS; no request relation grant, exact grants to one named worker role |

The executable inventory checks scope, `ENABLE ROW LEVEL SECURITY`, `FORCE ROW
LEVEL SECURITY`, and policy presence for every public application table against
a live database. Migration `65_role_permissions_rls` closes the former
child-table gap: `role_permissions` reads follow parent-role visibility, while
inserts may target only a custom role owned by the current tenant.

## Team membership is a child of organization membership

Row security decides which team's rows a transaction may reach. It says nothing
about whether the person being added belongs to the team's organization, so
until migration `127_team_membership_parent_org` a caller authorized to
administer a team could install any user in the database as a team
administrator.

`team_members` now carries `org_id NOT NULL` under two composite foreign keys:
`(team_id, org_id)` references `teams (id, org_id)`, so the organization on a
membership row cannot disagree with the team's own and no writer can offer an
organization of its own choosing as proof; `(org_id, user_id)` references
`organization_members (org_id, user_id)` with `ON DELETE CASCADE`, so a team
membership cannot exist without a live parent membership and losing the parent
retires it in the same transaction. PostgreSQL performs referential checks with
row security bypassed, so both hold for `app_tenant`, `app_control_plane`, the
migration principal, and direct SQL alike.

The insert's `FOR KEY SHARE` lock on the `organization_members` row serializes a
team write against a concurrent organization removal, so neither commit order
leaves an orphan; `Store.LockOrgMembership` takes the matching advisory lock for
transactions that read a membership before acting on it. Memberships that
predate the invariant were never repaired by manufacturing the missing parent —
they were moved to `team_membership_quarantine`. That record carries no
request-relation grant and is read through the control plane; it still forces
row level security under a tenant policy, because a table with a tenant column
and no policy is indistinguishable from one whose isolation was forgotten. It
also outlives a rollback of the migration that filled it — the memberships it
describes are already deleted and no migration restores them, so dropping the
record with the schema would destroy the only evidence they existed.
## Organization administrative-continuity diagnostic

Migration `135_organization_administrator_diagnostic` inventories the
organizations whose administrative authority is *already* inconsistent, so that
work enforcing the invariant has a sized backlog rather than a guess. It changes
no existing relation and grants no new request authority.

`public.record_membership_integrity_findings()` records three findings into
`membership_integrity_findings`, all **reported and never repaired**:

| Finding | Meaning | Why it is not repaired |
|---|---|---|
| `organization_without_administrator` | No `owner`/`admin` membership row exists at all. | The only way to give an organization an administrator is to pick a user and grant them one. A deploy that does this performs a privilege escalation with no operator deciding who. |
| `organization_without_an_eligible_administrator` | Administrative membership rows exist, but every holder's identity is inactive. | Reactivating an identity hands authority back to whoever held it — equally an operator's decision, and usually the cheaper repair. Reported apart from the row above because it is a different decision, not a milder version of the same one. |
| `owner_of_record_is_not_an_administrator` | Somebody eligible can administer the organization, but the owner of record cannot — either they hold no administrative membership, or they hold one whose identity is not active. | `organizations.owner_id` is written only by `CreateOrganization` and there is no owner-transfer path, so it is immutable provenance rather than live authority. Writing either side to match the other moves authority silently. |

**Eligibility** is migration `130_organization_administrator_eligibility`'s
definition, reproduced rather than approximated: `role IN ('owner', 'admin')`
**and** `users.status = 'active'`. `findIdentity` admits only active identities
and `DeleteUser` is a soft delete that leaves the membership row standing, so
counting administrative rows regardless of identity status reports an
organization healthy when nobody holding one can sign in to administer it —
exactly the backlog this inventory exists to size. Migration 130's
`organization_eligible_administrators()` is not reused: it is `SECURITY DEFINER`
scoped to `app.current_org_id`, so it answers for a single tenant, and this is a
cross-tenant inventory.

The three are **mutually exclusive by construction** — one `CASE` over one row
per organization can only ever yield one of them — so the row count is an
organization count, and that is what the function returns. `detail` carries
`owner_id`, `membership_role` (`null` when the owner holds no membership at
all), `owner_status`, `administrative_members` and `eligible_administrators`, so
an operator can tell "three administrators, none of whom can sign in" from "no
administrators at all" without going back to the tables.

The natural key is `(org_id, finding)`; there is no surrogate id. A finding *is*
the fact that this organization is in this state, and migration 13 dropped
server-side `gen_random_uuid()` defaults on purpose.

### Running it

`membership-integrity-scan` is the operator's vehicle:

```
membership-integrity-scan -database-url "$DATABASE_URL" [-list-only]
```

The scan is a function, not inline migration DML, so it can be re-run after
repairs and watched shrinking. Re-running is non-destructive: a finding that
still holds keeps its original `found_at` (the conflict target is the
`(org_id, finding)` pair and the update refreshes only `detail`), and a finding
that has since been repaired is deleted, so the table always reads as the
current backlog rather than an append-only history.

**The connection principal must be a member of `app_control_plane`**, and that
is load-bearing rather than ceremonial. `organizations`, `organization_members`
and `membership_integrity_findings` all force RLS — which binds the table owner
too — with policies scoped to `app.current_org_id` and no bypass clause. A
principal that does not span organizations therefore reads zero rows through
all three: it would record an empty backlog and report a healthy platform. The
function refuses to run for such a principal instead, and the migration assumes
`app_control_plane` before its own initial scan for the same reason. The store
owner-connection alone is not sufficient, and reading the findings table
directly under it returns silently empty.

### Authority

It is a plain invoker-rights function. `app_control_plane` is the only role
granted `EXECUTE`, and it already spans organizations through `BYPASSRLS`, so
`SECURITY DEFINER` would add privilege without adding capability. `app_tenant`
holds no grant on either the function or the table: these are operator evidence
read through the control-plane boundary, not product data.

No role actually reaches these rows *through* the table's policy — request
traffic holds no grant, and `BYPASSRLS` is decided before any policy is
consulted for the one role that does. The policy is nobody's access-control
decision. It exists because a tenant-columned table without one is
indistinguishable from an unprotected one, and because the inventory above
requires every tenant relation to force RLS and carry a tenant-scoped policy.

Scope: organization-level findings only. A team membership with no parent
organization membership is a different relation with its own repair, and this
migration deliberately neither scans for it nor quarantines it.

## Generic job platform

Migration `72_job_platform_contract` gives `app_tenant` no direct relation
privileges on the common job tables. Request traffic may only execute the
`enqueue_job_message` security-definer operation, which accepts outbox work and
checks the actual caller role against the transaction-local organization or
subject scope before insertion. The table's forced insert policy remains a
second boundary. Migration `75_email_job_convergence` additionally permits
`app_control_plane` to execute that operation for global outbox work only, so a
pre-authentication product row and exact external-delivery command can share
one audited transaction. It still cannot enqueue inbox or tenant/subject work,
read payloads, mutate lifecycle, or replay. Billing and webhook projection
workers have neither relation nor operation authority.

`app_job_worker` has `SELECT`, `INSERT`, and `UPDATE` on messages and attempts,
`SELECT` on transition history, and execution of the enqueue operation for
privileged inbox/global producers. It alone may execute `replay_job_message`,
which accepts dead-lettered sources only and copies payload bytes without
returning them through the administration API. It has no delete authority and no product
relation grants. Executable tests pin the role attributes, exact table/function
ACLs, request denial, control-plane global-outbox-only authority, scope checks,
and product-table isolation. See `JOBS.md` for the generated producer and
lifecycle contract.

`app_webhook_worker` has `SELECT` on both webhook relations and column-level
`UPDATE` only for delivery status, HTTP outcome, attempts, and timestamps. It
cannot rewrite subscription/event identity or exact payload bytes and has no
insert, delete, truncate, schema, temporary-table, job-platform, or unrelated
product authority. The
generic `app_job_worker` owns the inverse execution boundary and cannot access
either webhook relation. Migration `73_outbound_webhook_job_convergence`
removes the former queue lifecycle columns for upgraded databases; migration
`74_webhook_projection_column_authority` pins the immutable-column boundary.

## User directory operations

Migration `69_user_directory_operations` replaces the historical
`users_select USING (true)` policy. Request traffic can read only the row whose
UUID matches `app.current_user_id`; pre-authentication, platform administration,
and workers use their separately named roles.

Tenant code does not receive co-member visibility over the full `users` row.
The `organization_member_primary_email(user_id)` operation returns exactly one
field, only when that user belongs to `app.current_org_id`. It is a
`SECURITY DEFINER` function owned by the NOLOGIN `app_control_plane` role,
revokes public execution, and grants only `EXECUTE` to `app_tenant`. Executable
tests pin its owner, security mode, ACL, cross-user isolation, and membership
filter. User-owned identity deletion is separately granted for atomic GDPR
deletion and remains constrained by `user_identities_user` RLS.

## Administrative continuity and eligible administrators

Migration `133_organization_administrator_eligibility` adds
`organization_eligible_administrators(org_id)`, the counter behind the
administrative-continuity invariant (see `AUTHZ.md`). An administrator counts
only when the membership carries an administrative role **and** the identity
behind it is still `active`: `findIdentity` refuses any other status, and user
deletion is a soft delete that leaves the membership row standing, so counting
those rows would let the last usable administrator be removed.

Eligibility therefore has to read `users`, which request traffic cannot do for a
co-member (migration `69`). The remedy is the same one that section describes: a
`SECURITY DEFINER` function owned by the NOLOGIN `app_control_plane` role,
public execution revoked, `EXECUTE` granted only to `app_tenant`, and the body
scoped to `app.current_org_id` so it answers only for the caller's own
organization. It returns membership ids that caller can already enumerate, and
no `users` column.

The failure mode this shape avoids is specific: a direct join under `app_tenant`
returns zero rows rather than an error, and zero administrators reads as "this
organization never had one" — which the invariant deliberately exempts so
historical data stays repairable. Getting the read wrong would therefore
silently disable the rule instead of tightening it. Control-plane transactions
set no tenant organization and hold `BYPASSRLS`, so they evaluate the same
predicate directly.

## Identity deactivation and administered organizations

Migration `137_identity_administered_organizations` adds
`identity_administered_organizations(user_id)`, the read behind the
deactivation half of the same invariant. Deactivating an identity — a soft
delete or a suspension — writes no `organization_members` row but withdraws
eligibility from every administrative membership the identity holds at once, so
the decision needs the organizations it administers and, for each, how many
eligible administrators that organization has and whether anybody else is still
in it. That last count separates an organization left unadministrable from one
left empty: `RegisterUser` gives every identity a personal organization it
solely owns, so a rule counting only administrators would refuse every deletion
on this platform.

A deactivating transaction is scoped to an identity and to no organization,
which is the one scope that can read neither input: `organization_members` is
scoped to `app.current_org_id` (migrations `29`/`68`) and `users` to the
caller's own row (migration `69`). Both return zero rows rather than an error,
and zero administered organizations reads as "this identity administers
nothing" — the answer that admits the deactivation. Same shape as the two
sections above: a `SECURITY DEFINER` function owned by the NOLOGIN
`app_control_plane` role, public execution revoked, `EXECUTE` granted only to
`app_tenant`, and the body scoped to `app.current_user_id` so it answers only
for the caller's own identity. It returns organization ids that caller is
already a member of, plus a count over them, and no `users` column.

The administrator count repeats migration `133`'s eligibility predicate rather than
calling `organization_eligible_administrators`, which scopes itself to
`app.current_org_id` — a value a deactivation has no single one of.
`PostgresStore.ListAdministeredOrganizations` branches on the transaction's
scope: the caller's own identity goes through the function, a transaction that
has assumed `app_control_plane` evaluates the predicate directly, and one that is
neither is refused rather than answered empty. It decides that on the assumed
role, not on `rolbypassrls` — the managed profile makes every runtime role
`NOBYPASSRLS` and grants the control plane its reach through explicit exact-role
policies, so an attribute test would refuse every platform-administered
deactivation there while passing everywhere else. Same predicate as migration
`136`'s guard on `record_membership_integrity_findings()`. Executable tests pin the function's owner,
security mode, and ACL, the eligibility filter, and that refusal.

## Session authorization invalidation

Migration `70_session_authorization_invalidation` makes refresh-session
invalidation a database invariant rather than a handler convention. Changes to
user status, organization membership or role, platform role, and verified MFA
enrollment revoke exactly the affected active refresh sessions in the same
transaction. Organization mutations target sessions selected into that tenant
plus org-less sessions; user-wide facts target every family.

The shared trigger function is `SECURITY DEFINER`, owned by the NOLOGIN,
`BYPASSRLS` `app_control_plane` role so tenant- and user-scoped mutations can
reach the narrowly selected session rows without widening request-role RLS.
Public and `app_tenant` execution are revoked. Executable tests pin the owner,
security mode, ACL, tenant scoping, user scoping, and transaction rollback.

## Session lifetime and device admission

Migration `71_session_lifetime_and_device_context` adds an explicit
`idle_expires_at` to
every refresh-session row and preserves bounded device display context across
the durable MFA handoff. The existing `expires_at` is the fixed absolute family
boundary; refresh successors inherit it and the original `created_at`, while
only `last_active_at` and `idle_expires_at` advance.

Initial session insertion locks the owning user row before evaluating active
families. This serializes concurrent logins across replicas, retires already
expired families, and revokes the least-recently active family before inserting
when the configured per-user device cap is full. Refresh rotation bypasses
admission because it replaces a row inside an existing family. Device metadata
is display/audit context only and never participates in authentication,
authorization, or tenant isolation.

Organization selection uses the same control-plane session boundary. Accounts
locks the exact active `sessions` row identified by the independently verified
user and access-token `sid`, verifies the target `organization_members` row,
resolves current tenant/platform/MFA authorization, and updates only `org_id`,
`org_role`, and `platform_role`. The refresh hash, family id, device context,
creation/activity timestamps, idle expiry, and absolute expiry are unchanged.
This lock order serializes switch-versus-refresh races without treating a stale
access-token session id as refresh replay.

## Control-plane boundary

Migrations `67_control_plane_role` and `68_remove_policy_guc_bypass` replace
the former custom-setting capability with `app_control_plane`. The authored
deployment topology lists that role under Postgres
`runtime-read-write-roles`, and `WithControlPlane` uses
`SET LOCAL ROLE app_control_plane`. Active policy expressions are tested to
contain no `app.bypass` reference; setting an arbitrary custom GUC can no
longer grant row visibility.

The role is `NOLOGIN`, owns no relations, receives no implicit future grants,
cannot create schema or temporary objects, cannot truncate, cannot assume a
worker role, and has no job relation, lifecycle, or replay access. Its exact
relation and function matrix and the managed session's non-owner/non-superuser
attributes are executable infrastructure tests.

The remaining boundary is physical credential separation. Today one
Codefly-managed read-write principal is a member of all application roles so
the accounts monolith can run request, pre-auth, and scheduled control-plane
paths. Codefly Postgres should expose role-specific connection secrets—and the
Starter should split the corresponding pools/processes—so a request-only
credential has no `SET ROLE` path to privileged roles. Track that PaaS work
under `P2-DB-002`; do not compensate with a public endpoint, superuser
credential, or application-settable policy flag.


## Private execution custody candidate

Migration `131_execution_custody` adds forced-RLS tenant-owned ciphertext with a
literal deny-all request policy. Only `app_control_plane` receives SELECT, INSERT,
DELETE and column-level UPDATE on `envelope` for expiry erasure. All original
registration fields are immutable to runtime SQL roles; no worker or tenant
custody grant is added. Ciphertext erasure retains non-authorizing admission
tombstones. See [the private broker contract](services/accounts/EXECUTION_CUSTODY.md)
for authentication, Vault projection, lifetime and qualification boundaries.
