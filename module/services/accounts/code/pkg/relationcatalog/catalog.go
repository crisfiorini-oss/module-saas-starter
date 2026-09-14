// Package relationcatalog classifies every relation in the store service's
// schema by the authority boundary it requires: which scope a runtime role may
// reach it under, and — for the relations behind row-level security — the shape
// of the policy that enforces that scope.
//
// One inventory serves two consumers. The api service projects the
// RLS-protected subset into its GetServiceInfo catalog, so a consumer asking
// "which relations are RLS-protected?" reads the same list the infrastructure
// hardening suite checks a live database against (relation grants, ENABLE /
// FORCE ROW LEVEL SECURITY, policy presence, and the scope column each policy
// actually references). Neither copy can drift from the other, and both drift
// loudly from the database rather than quietly.
package relationcatalog

// Scope is the authority boundary a relation requires.
type Scope string

const (
	// ScopeGlobal is a platform-wide catalog: no RLS, exact grants only.
	ScopeGlobal Scope = "global"
	// ScopeTenant is owned by one organization and scoped by its policy.
	ScopeTenant Scope = "tenant"
	// ScopeUser is owned by one user, independent of any organization.
	ScopeUser Scope = "user"
	// ScopePreAuth is reachable before a session exists, so its request
	// policy denies everything and the control-plane role mediates access.
	ScopePreAuth Scope = "pre_auth"
	// ScopeJob is the generic job platform's queue: request traffic holds no
	// relation grant and enqueues through a scoped SECURITY DEFINER operation.
	ScopeJob Scope = "job"
	// ScopeWorker belongs to a bypass-RLS worker role; request traffic has no
	// access at all, so no policy stands between them.
	ScopeWorker Scope = "worker"
)

// Policy shapes. These name how a relation's policy derives the scope it
// compares against the transaction-local organization or user setting.
const (
	// ShapeDirect compares a scope column on the relation itself.
	ShapeDirect = "direct"
	// ShapeJoin walks a foreign key to a parent that carries the scope.
	ShapeJoin = "join"
	// ShapePolymorphic admits platform-wide rows whose scope column is NULL
	// alongside scoped tenant rows.
	ShapePolymorphic = "polymorphic"
	// ShapeSelfReferential scopes a relation by its own primary key.
	ShapeSelfReferential = "self_referential"
	// ShapeUnion accepts several alternative scopes; the notes name them.
	ShapeUnion = "union"
	// ShapeControlPlane denies every row to request traffic; all access runs
	// under the audited control-plane role.
	ShapeControlPlane = "control_plane"
	// ShapeFunctionScoped has no read policy at all: a SECURITY DEFINER
	// operation checks the caller's scope before it writes.
	ShapeFunctionScoped = "function_scoped"
)

// Authority is one relation's classification. PolicyShape and ScopeColumn
// describe the row-level policy and are empty for scopes that carry none;
// ShapeControlPlane relations have a shape but no request-visible scope column.
type Authority struct {
	Scope       Scope
	PolicyShape string
	ScopeColumn string
	Notes       string
}

// RequiresRLS reports whether relations in this scope must carry enabled and
// forced row-level security with at least one policy.
func (s Scope) RequiresRLS() bool {
	switch s {
	case ScopeTenant, ScopeUser, ScopePreAuth, ScopeJob:
		return true
	default:
		return false
	}
}

// All returns the complete public-relation inventory, keyed by relation name.
// A relation missing from it fails the infrastructure completeness gate, which
// compares the inventory to PostgreSQL's own catalog.
//
// The returned map is a copy. The published catalog projects the inventory once
// at process start, so a mutation of the backing map would desynchronize what
// the service publishes from what the infrastructure suite validates, with
// neither failing.
func All() map[string]Authority {
	out := make(map[string]Authority, len(authorities))
	for relation, authority := range authorities {
		out[relation] = authority
	}
	return out
}

var authorities = map[string]Authority{
	// Platform-wide catalogs. Seeded and administered centrally, read by
	// request traffic under exact grants.
	"audit_event_types":       {Scope: ScopeGlobal},
	"bootstrap_state":         {Scope: ScopeGlobal},
	"data_retention_policies": {Scope: ScopeGlobal},
	"email_templates":         {Scope: ScopeGlobal},
	"feature_flags":           {Scope: ScopeGlobal},
	"identity_providers":      {Scope: ScopeGlobal},
	"plan_entitlements":       {Scope: ScopeGlobal},
	"plans":                   {Scope: ScopeGlobal},
	"platform_admins":         {Scope: ScopeGlobal},
	"solution_registrations":  {Scope: ScopeGlobal},

	// Tenant-scoped relations.
	"execution_custody": {Scope: ScopeTenant, PolicyShape: ShapeControlPlane, Notes: "Private Vault envelopes; tenant access denied. Expiry erases ciphertext and retains immutable registration tombstones."},
	"actor_chain_journal": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Append-only: an immutable trigger rejects updates and deletes.",
	},
	"actor_chain_revocations": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Append-only: an immutable trigger rejects updates and deletes.",
	},
	"api_keys": {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "organization_id"},
	"approval_decisions": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Append-only: an immutable trigger rejects updates and deletes.",
	},
	"approval_requests": {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"audit_event_idempotency": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Append-only emit-reservation guard; system emits reserve against the sentinel organization.",
	},
	"audit_events": {
		Scope: ScopeTenant, PolicyShape: ShapePolymorphic, ScopeColumn: "org_id",
		Notes: "NULL org_id rows (system events) are visible only under the control-plane role. Monthly partitions inherit the partitioned parent's policy.",
	},
	"connector_credentials": {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"dashboards":            {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"datasource_sources":    {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"delegation_grants":     {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"domain_events": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "tenant_id",
		Notes: "Read-only tenant policy; publication goes through the SECURITY DEFINER outbox operation.",
	},
	"entitlement_overrides": {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"installations":         {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"invitations":           {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"membership_integrity_findings": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Operator repair evidence for administrative continuity; request traffic holds no grant, so every read runs under the control-plane role.",
	},
	"org_generic_settings":     {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"org_identity_providers":   {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"org_settings":             {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"organization_activations": {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"organization_authorization_revisions": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Read-only tenant policy; the control plane bumps the revision that invalidates live sessions.",
	},
	"organization_members": {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"organizations":        {Scope: ScopeTenant, PolicyShape: ShapeSelfReferential, ScopeColumn: "id"},
	"principal_authorization_revisions": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Read-only tenant policy; the control plane bumps the revision that invalidates live sessions.",
	},
	"principals": {
		Scope: ScopeTenant, PolicyShape: ShapeUnion, ScopeColumn: "org_id",
		Notes: "Agent principals are tenant-owned; a user principal (org_id IS NULL) is visible to itself and to members of the caller's organization.",
	},
	"record_shares": {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"role_assignments": {
		Scope: ScopeTenant, PolicyShape: ShapePolymorphic, ScopeColumn: "org_id",
		Notes: "Platform assignments (org_id IS NULL) are readable; a write must name the caller's organization.",
	},
	"role_permissions": {
		Scope: ScopeTenant, PolicyShape: ShapeJoin, ScopeColumn: "role_id",
		Notes: "Reads follow roles.org_id, so built-in role rows stay visible; inserts may only target a custom role in the caller's organization.",
	},
	"roles": {
		Scope: ScopeTenant, PolicyShape: ShapePolymorphic, ScopeColumn: "org_id",
		Notes: "Built-in roles (org_id IS NULL) globally readable; tenant rows scoped.",
	},
	"scope_grants": {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"scope_nodes":  {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"source_read_revisions": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Read-only tenant cursor revision; source and grant mutation triggers advance it under the control-plane role.",
	},
	"subscriptions": {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"team_members": {
		Scope: ScopeTenant, PolicyShape: ShapeJoin, ScopeColumn: "team_id",
		Notes: "JOIN walks team_id → teams.org_id",
	},
	"team_membership_quarantine": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Forensic record of the team memberships the parent-organization invariant removed. Only the migration writes it; request traffic holds no grant and the control-plane role may only read, so the record cannot be edited away.",
	},
	"teams": {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"usage_events": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Immutable accepted/rejected usage attempt ledger.",
	},
	"usage_totals": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Transactionally maintained monthly meter aggregates.",
	},
	"webhook_deliveries": {
		Scope: ScopeTenant, PolicyShape: ShapeJoin, ScopeColumn: "subscription_id",
		Notes: "JOIN walks subscription_id → webhook_subscriptions.org_id",
	},
	"webhook_subscriptions": {Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id"},
	"work_context_replay": {
		Scope: ScopeTenant, PolicyShape: ShapeDirect, ScopeColumn: "org_id",
		Notes: "Claim-once marker; the expiry sweep deletes under the control-plane role.",
	},

	// User-scoped relations. Owned by one user and reachable in any of that
	// user's organizations, so the policy compares the session's user rather
	// than its organization.
	"gdpr_requests":    {Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id"},
	"mfa_backup_codes": {Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id"},
	"mfa_devices":      {Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id"},
	"mfa_login_transactions": {
		Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id",
		Notes: "Request traffic may only insert; completion resolves the row by exact opaque-token hash under the control-plane role.",
	},
	"notifications":       {Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id"},
	"onboarding_progress": {Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id"},
	"resource_follows": {
		Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id",
		Notes: "org_id is descriptive; the follower is the access key. Unfollow is an update of revoked_at, so request traffic never deletes.",
	},
	"sessions":                 {Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id"},
	"user_consent_events":      {Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id"},
	"user_consent_preferences": {Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id"},
	"user_identities":          {Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_uuid"},
	"users": {
		Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "uuid",
		Notes: "Per-command policies limit request traffic to the caller's own row; directory reads and administration run under the control-plane role.",
	},
	"webauthn_ceremonies": {
		Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id",
		Notes: "Short-lived server-side state; login ceremonies are bound to an MFA login transaction.",
	},
	"webauthn_credentials": {
		Scope: ScopeUser, PolicyShape: ShapeDirect, ScopeColumn: "user_id",
		Notes: "Complete credential record is Vault-encrypted; public credential ID is unique.",
	},

	// Pre-authentication relations. Read and written before any session
	// exists, so their request policy admits nothing at all.
	"magic_links": {
		Scope: ScopePreAuth, PolicyShape: ShapeControlPlane,
		Notes: "Minting and redemption run as bounded service operations under the control-plane role.",
	},
	"waitlist_entries": {
		Scope: ScopePreAuth, PolicyShape: ShapeControlPlane,
		Notes: "Public writes and platform administration use bounded service operations under the control-plane role.",
	},

	// Generic job platform.
	"job_messages": {
		Scope: ScopeJob, PolicyShape: ShapeFunctionScoped,
		Notes: "No single scope column: the insert-only policy keys on scope_kind, comparing organization_id for tenant work and subject_id for subject work. Request traffic holds no relation grant — it enqueues through the scoped SECURITY DEFINER operation and never reads payloads.",
	},

	// Worker-owned relations. Reached only by a bypass-RLS worker role, so
	// request traffic is denied by the absence of a grant rather than by a
	// policy.
	"analytics_deliveries":  {Scope: ScopeWorker},
	"email_delivery_events": {Scope: ScopeWorker},
	"event_subscriptions":   {Scope: ScopeWorker},
	"job_attempts":          {Scope: ScopeWorker},
	"job_state_transitions": {Scope: ScopeWorker},
}
