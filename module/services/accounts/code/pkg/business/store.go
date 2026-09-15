package business

import (
	"context"
	"time"

	gen "accounts/pkg/gen/saas/accounts/v1"
)

type Store interface {
	// Transactions
	RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error

	// WithOrgTx wraps fn in a transaction that has app.current_org_id
	// set, so RLS policies on per-tenant tables filter to that org.
	// Empty orgID is rejected (loud, fail-closed). Wrap every
	// per-tenant Service path in this — see AUTHZ.md.
	WithOrgTx(ctx context.Context, orgID string, fn func(ctx context.Context) error) error

	// WithUserTx wraps fn in a transaction that has app.current_user_id
	// set, so RLS policies on user-scoped tables (notifications,
	// mfa_devices, sessions) filter to that user. Empty userID is
	// rejected (loud, fail-closed). Same no-nesting rule as WithOrgTx.
	// See AUTHZ.md for the user-scope policy shape.
	WithUserTx(ctx context.Context, userID string, fn func(ctx context.Context) error) error

	// WithControlPlane wraps fn in a transaction that assumes the named
	// app_control_plane role. Use only for
	// background workers + platform-admin views; every call site is
	// deliberate.
	WithControlPlane(ctx context.Context, fn func(ctx context.Context) error) error

	// As returns a Store handle bound to an identity (see Scoped). It is the
	// identity-first entry point the With* wrappers collapse into: As(id).Within
	// sets the same RLS context, but the identity is explicit and carried by the
	// handle. As(System()) is the one named, audited bypass.
	As(id Identity) Scoped

	// Users
	RegisterUser(ctx context.Context, user *gen.User, identity *gen.UserIdentity) error
	GetUserByIdentity(ctx context.Context, id *gen.UserIdentity) (*gen.User, error)
	GetUser(ctx context.Context, id string) (*gen.User, error)
	// UserIDExists reports whether any users row already holds this uuid.
	// A deleted user keeps its row, so its primary key stays taken.
	UserIDExists(ctx context.Context, id string) (bool, error)
	GetUserByEmail(ctx context.Context, email string) (*gen.User, error)
	GetOrganizationMemberPrimaryEmail(ctx context.Context, userID string) (string, error)
	ListUsers(ctx context.Context, orgID string, statusFilter string, pageSize int32, pageToken string) ([]*gen.User, string, error)
	UpdateUser(ctx context.Context, userID string, updates map[string]any) (*gen.User, error)
	DeleteUser(ctx context.Context, userID string) error

	// Identities
	AddIdentity(ctx context.Context, identity *gen.UserIdentity) error
	FindUserByIdentity(ctx context.Context, provider, providerID string) (*gen.User, error)
	ListUserIdentities(ctx context.Context, userID string) ([]*gen.UserIdentity, error)
	DeleteUserIdentities(ctx context.Context, userID string) error

	// Org identity providers (per-org IdP registry — issue #107).
	//
	// These methods have two different transaction ownerships, so read the
	// contract before calling:
	//
	//   - Upsert/Get/SetStatus are org-scoped and MUST run inside the caller's
	//     WithOrgTx(orgID, …); called bare they hit RLS and see zero rows.
	//   - ResolveOrgProviderByEmailDomain/ByHost are UNAUTHENTICATED, cross-org
	//     pre-auth lookups that open their OWN control-plane transaction. Call
	//     them at the top level only — invoking them inside an existing
	//     WithOrgTx/WithControlPlane nests a second pooled connection, which the
	//     no-nesting rule on those helpers forbids. They return only an active,
	//     unambiguously-matched provider (nil on miss or ambiguity).
	UpsertOrgIdentityProvider(ctx context.Context, provider *OrgIdentityProvider) error
	GetOrgIdentityProvider(ctx context.Context, orgID string) (*OrgIdentityProvider, error)
	SetOrgIdentityProviderStatus(ctx context.Context, orgID, status string) error
	ResolveOrgProviderByEmailDomain(ctx context.Context, domain string) (*OrgIdentityProvider, error)
	ResolveOrgProviderByHost(ctx context.Context, host string) (*OrgIdentityProvider, error)

	// Datasource connector credentials (per-source encrypted secret store —
	// issue #274). All three run inside a transaction the caller opens; they do
	// not open their own. Source ids are globally unique, so the row is keyed by
	// source id alone and the surrounding transaction chooses the visibility:
	//
	//   - Under WithOrgTx(orgID, …) RLS restricts them to the org's own sources
	//     (request-scoped store/read/delete).
	//   - Under WithControlPlane RLS is bypassed, so GetConnectorCredential
	//     serves the unauthenticated, cross-tenant webhook-signing-secret lookup
	//     keyed by source id.
	UpsertConnectorCredential(ctx context.Context, credential *ConnectorCredential) error
	GetConnectorCredential(ctx context.Context, sourceID string) (*ConnectorCredential, error)
	DeleteConnectorCredential(ctx context.Context, sourceID string) error

	// Datasource sources (connected external datasources — issue #273/#274).
	//
	// Two transaction ownerships, same split as the identity-provider registry:
	//
	//   - Insert/List/Get/Delete are org-scoped and MUST run inside the caller's
	//     WithOrgTx(orgID, …); called bare they hit RLS and see zero rows.
	//   - GetDatasourceSourceByID is the UNAUTHENTICATED webhook-receipt lookup
	//     (no tenant context yet), so it opens its OWN control-plane transaction.
	//     Call it at the top level only — nesting it inside an existing
	//     WithOrgTx/WithControlPlane violates the no-nesting rule.
	InsertDatasourceSource(ctx context.Context, source *DatasourceSource) error
	WithSourceReadSnapshot(context.Context, string, func(context.Context) error) error
	SourceReadRevision(context.Context, string, []string) (string, time.Time, error)
	ListReadableSourcesPage(context.Context, string, []string, []string, string, int) ([]*gen.ReadableSourceCollection, error)
	ListDatasourceSources(ctx context.Context, orgID string) ([]*DatasourceSource, error)
	GetDatasourceSource(ctx context.Context, orgID, id string) (*DatasourceSource, error)
	DeleteDatasourceSource(ctx context.Context, orgID, id string) error
	SetDatasourceSourceSynced(ctx context.Context, orgID, id string, syncedAt time.Time) error
	// LockDatasourceSourceCredentialRef reads the source's current credential
	// envelope under a row lock (SELECT … FOR UPDATE) so a refresh-and-rotate
	// read-modify-write serializes against concurrent syncs of the same source.
	// MUST run inside the caller's WithOrgTx; the lock is held until that
	// transaction commits.
	LockDatasourceSourceCredentialRef(ctx context.Context, orgID, id string) (string, error)
	UpdateDatasourceSourceCredential(ctx context.Context, orgID, id, credentialRef string) error
	GetDatasourceSourceByID(ctx context.Context, id string) (*DatasourceSource, error)
	// AdvanceDatasourceCursor records the head commit fully enqueued as a change
	// set, its delivery provenance, and pushes next_reconcile_at out by the
	// source's reconcile interval (left NULL when reconcile is disabled). It runs
	// under the leased worker's control-plane role (no tenant context) and is only
	// ever called by the change-set compiler after every op of a delivery is
	// durably enqueued; monotonicity is guaranteed upstream by the worker's
	// ancestor check, which drops a delivery whose head is an ancestor of the
	// cursor before this is reached.
	AdvanceDatasourceCursor(ctx context.Context, sourceID, commit, deliveryID string) error
	// AllocateDatasourceOrdinal atomically hands out the next strictly-increasing
	// per-source delivery ordinal (UPDATE … next_ordinal = next_ordinal + 1
	// RETURNING the prior value; the first allocation returns 1). The compiler
	// stamps it on every emitted sync/snapshot payload so a consumer can order
	// deliveries per source and reject a stale or out-of-order replay. Runs
	// control-plane. The allocation commits on its own — the job enqueue that
	// follows is a separate transaction owned by the jobs platform — so a delivery
	// that fails after allocating leaves a gap, never a repeated or backward
	// ordinal. Strictly increasing is the guarantee, not density: a gap is expected
	// and is not a dropped payload.
	AllocateDatasourceOrdinal(ctx context.Context, sourceID string) (int64, error)
	// ListDatasourceSourcesDueForReconcile returns active sources whose
	// next_reconcile_at has elapsed, for the periodic reconcile sweep. Control-plane.
	ListDatasourceSourcesDueForReconcile(ctx context.Context, now time.Time, limit int) ([]*DatasourceSource, error)
	// BumpDatasourceReconcile pushes next_reconcile_at out by the source's
	// reconcile interval without touching the cursor, so a reconcile that finds
	// nothing to do still reschedules. Control-plane.
	BumpDatasourceReconcile(ctx context.Context, sourceID string) error
	// MarkDatasourceSourceDegraded parks a source the compiler cannot make
	// progress on (an oversized snapshot manifest), recording the reason and
	// clearing next_reconcile_at so the reconcile sweep stops re-selecting it
	// until an operator resets it to active. Control-plane.
	// The reason is a closed-set DatasourceDegradeReason rather than a string:
	// status_reason is tenant-readable, so raw provider error text must not be
	// able to reach it.
	MarkDatasourceSourceDegraded(ctx context.Context, sourceID string, reason DatasourceDegradeReason) error
	// ClearDatasourceSourceDegraded returns a degraded source to active once a
	// snapshot has succeeded again: it clears status_reason and restores
	// next_reconcile_at from the source's reconcile interval so the reconcile
	// sweep resumes selecting it. Scoped to status='degraded' so it cannot
	// resurrect a source an operator has since paused, and to reasons outside
	// excludeReasons so it cannot lift a degrade another path owns — a snapshot
	// fitting the ingest cap is no evidence that withdrawn GitHub App access has
	// returned. Control-plane.
	ClearDatasourceSourceDegraded(ctx context.Context, sourceID string, excludeReasons []string) error
	// MarkDatasourceSourceInstallationDegraded parks a source whose GitHub App
	// access was withdrawn, and re-labels one this path already parked when the
	// cause changes. The reconciler decides what to park from a read taken before
	// any GitHub call, so the predicate lives in the UPDATE: it writes only over
	// 'active' or over one of reasons, and only when the reason actually differs.
	// Without that, a webhook can overwrite an operator's pause or a degrade the
	// compiler recorded for its own fault; with an active-only predicate it would
	// instead no-op silently on a changed cause. Reports whether a row changed,
	// which is the transition the audit trail records. Control-plane.
	MarkDatasourceSourceInstallationDegraded(ctx context.Context, sourceID, reason string, reasons []string) (bool, error)
	// ClearDatasourceSourceInstallationDegraded is ClearDatasourceSourceDegraded
	// narrowed to sources parked for one of reasons. Matching the recorded reason
	// as well as the status is what keeps restored GitHub App access from
	// reviving a source degraded for an unrelated structural fault. Returns the
	// reason it cleared, or "" when no row matched: the audit record names the
	// cause the source recovered from, and reading it back from the UPDATE is the
	// only way to name the one that was actually there. Control-plane.
	ClearDatasourceSourceInstallationDegraded(ctx context.Context, sourceID string, reasons []string) (string, error)
	// ListDatasourceSourcesByGitHubInstallation returns one page of the GitHub
	// sources bound to an App installation, ordered by id and starting after
	// afterID. The read spans tenants — an App-level delivery names an
	// installation and nothing else, and its receiver is unauthenticated, so
	// there is no tenant to scope the lookup to. Control-plane.
	ListDatasourceSourcesByGitHubInstallation(ctx context.Context, installationID, afterID string, limit int) ([]*DatasourceSource, error)
	// ListGitHubInstallationsPendingRecheck returns one page of the distinct
	// installations still holding a source parked for one of reasons, so
	// restoration does not depend on a single webhook delivery arriving. offset
	// rotates that page: a deleted installation parks its sources permanently, so
	// a fixed first page would eventually be filled by installations that can
	// never recover and would starve every live one behind them. Control-plane.
	ListGitHubInstallationsPendingRecheck(ctx context.Context, reasons []string, offset, limit int) ([]string, error)
	// CountGitHubInstallationsPendingRecheck sizes that set, which is what lets
	// the sweep rotate across all of it rather than re-reading one page.
	// Control-plane.
	CountGitHubInstallationsPendingRecheck(ctx context.Context, reasons []string) (int, error)
	// SetDatasourceSourceGitHubInstallation stamps the routing index an App-level
	// delivery resolves sources through, recording which installation the
	// source's credential envelope binds it to. The envelope stays the only thing
	// a token is minted from. Runs under the caller's WithOrgTx.
	SetDatasourceSourceGitHubInstallation(ctx context.Context, orgID, id, installationID string) error

	// Organizations
	CreateOrganization(ctx context.Context, org *gen.Organization) error
	// OrganizationIDExists reports whether any organizations row already holds
	// this id, so a fixture declaring one can tell a reusable row from a
	// primary key another organization has claimed.
	OrganizationIDExists(ctx context.Context, id string) (bool, error)
	// GetOrganizationBySlug resolves the organization holding a slug, or nil
	// when the slug is free. The slug is globally unique (idx_organizations_slug
	// is UNIQUE on LOWER(slug)), so this answers "would creating an
	// organization of this name collide, and with which id" without needing to
	// know who owns it — which is what the fixture seeder must decide before it
	// writes anything.
	GetOrganizationBySlug(ctx context.Context, slug string) (*gen.Organization, error)
	GetOrganization(ctx context.Context, id string) (*gen.Organization, error)
	ListOrganizationsForUser(ctx context.Context, userID string) ([]*gen.Organization, error)
	AddOrgMember(ctx context.Context, orgID string, userID string, role string) error
	OrgMemberExists(ctx context.Context, orgID string, userID string) (bool, error)
	RemoveOrgMember(ctx context.Context, orgID string, userID string) error
	// CountOrgAdministrators returns how many eligible administrative
	// memberships the organization has, and how many of those are held by
	// somebody other than excludeUserID. Eligible means the membership carries
	// an administrative role AND the identity behind it can still authenticate:
	// a soft-deleted or suspended user administers nothing, so counting their
	// membership would let the last usable administrator be removed.
	//
	// Call it under LockOrgAdministration — on its own it is only a read.
	CountOrgAdministrators(ctx context.Context, orgID string, excludeUserID string) (int, int, error)
	// ListAdministeredOrganizations returns every organization the identity is
	// an eligible administrator of, each carrying that organization's total
	// count of eligible administrators and how many of its other members can
	// still authenticate. Ordered by organization id, because deactivating an
	// identity locks all of them and the order they are taken in is what keeps
	// two concurrent deactivations off each other's backs.
	//
	// Same eligibility as CountOrgAdministrators, applied to the identity as
	// well: an identity that cannot authenticate administers nothing, so it
	// administers no organization either.
	ListAdministeredOrganizations(ctx context.Context, userID string) ([]OrgAdministration, error)
	// LockOrgAdministration serializes every change to one organization's
	// administrative standing, whichever member it names: a role upsert, a
	// demotion, or a removal. Callers take it before reading the roster the
	// decision depends on and hold it for the rest of the transaction, so two
	// requests cannot each observe the same two administrators and each
	// remove one.
	//
	// Deliberately coarser than LockOrgMembership: the invariant is a property
	// of the organization, not of one member, so a per-pair lock does not
	// serialize the contenders that violate it. Lock order when a path takes
	// more than one: LockOrgAdministration -> LockOrgMembership ->
	// LockEntitlementQuota.
	LockOrgAdministration(ctx context.Context, orgID string) error
	// LockOrgMembership serializes every mutation of one (organization, user)
	// authority pair. Callers hold it for the whole transaction that writes
	// the membership row and the team memberships that depend on it, so an
	// organization removal and a concurrent team insert cannot interleave.
	LockOrgMembership(ctx context.Context, orgID string, userID string) error
	// GetOrgMembership is the authorization hot path. It must be an indexed
	// point lookup, never an org-roster scan. Nil means the user is not a member.
	GetOrgMembership(ctx context.Context, orgID string, userID string) (*gen.OrgMembership, error)
	ListOrgMembers(ctx context.Context, orgID string) ([]*gen.OrgMembership, error)

	// Dashboards
	// CreateDashboard inserts the record and returns the stored row (with its
	// server-assigned timestamps) in the same statement, so callers never need a
	// second read that a concurrent delete could race.
	CreateDashboard(ctx context.Context, dashboard *Dashboard) (*Dashboard, error)
	// GetDashboard returns the row by id within the RLS-scoped org, or nil when
	// no such row is visible (a cross-tenant id reads as absent, not another
	// org's row).
	GetDashboard(ctx context.Context, id string) (*Dashboard, error)
	// ListDashboards returns at most limit rows ordered by (updated_at, id)
	// descending, starting strictly after the cursor when one is given. A limit
	// of zero means no bound (callers pass a bounded limit).
	ListDashboards(ctx context.Context, orgID, ownerID string, scope DashboardListScope, limit int, after *DashboardCursor) ([]*Dashboard, error)
	// UpdateDashboard applies a partial change (a nil name or spec is left
	// unchanged), advances updated_at, and returns the updated row, or nil when
	// no row has the id.
	UpdateDashboard(ctx context.Context, id string, name *string, spec []byte) (*Dashboard, error)
	DeleteDashboard(ctx context.Context, id string) error
	// SetDashboardVisibility sets visibility, advances updated_at, and returns
	// the updated row, or nil when no row has the id.
	SetDashboardVisibility(ctx context.Context, id string, visibility DashboardVisibility) (*Dashboard, error)

	// Teams
	CreateTeam(ctx context.Context, team *gen.Team) error
	ListTeams(ctx context.Context, orgID string) ([]*gen.Team, error)
	UpdateTeam(ctx context.Context, teamID, name, description string) (*gen.Team, error)
	DeleteTeam(ctx context.Context, teamID string) error
	AddTeamMember(ctx context.Context, teamID string, userID string, role string) error
	RemoveTeamMember(ctx context.Context, teamID string, userID string) error
	// RemoveOrgTeamMemberships deletes, in one statement on the caller's
	// transaction, every team membership the user holds in the organization,
	// and returns the number of rows removed. This is the dependent-access
	// half of removing an organization member: it commits with the membership
	// deletion or not at all.
	RemoveOrgTeamMemberships(ctx context.Context, orgID string, userID string) (int64, error)
	// GetTeamMembership is the authorization hot path. Nil means the user is
	// not a member; list access remains a separate, explicitly authorized API.
	GetTeamMembership(ctx context.Context, orgID string, teamID string, userID string) (*gen.TeamMembership, error)
	ListTeamMembers(ctx context.Context, teamID string) ([]*gen.TeamMembership, error)
	// GetTeamOrgID resolves a team's owning org. Used by callers that
	// only have a team_id (e.g. AddTeamMember handlers) so they can
	// enter WithOrgTx with the right scope. Implementations bypass RLS
	// internally — the result is then handed to WithOrgTx for the
	// real op, which IS scoped.
	GetTeamOrgID(ctx context.Context, teamID string) (string, error)
	// GetTeamPath returns (orgID, path) — the parent lookup CreateTeam uses
	// to derive a child team's path. ("", "") with no error when not found.
	GetTeamPath(ctx context.Context, teamID string) (string, string, error)

	// Identity Claims v1 (the validate-key read surface — see postgres_claims.go)
	ListTeamPathsForUser(ctx context.Context, userID string, orgID string) ([]string, error)
	ListRoleNamesForUser(ctx context.Context, userID string, orgID string) ([]string, error)
	GetUserAttributes(ctx context.Context, userID string) (map[string]string, error)
	// GetAPIKeyAuthentication is the narrow pre-authentication projection. It
	// resolves a presented key and its current owner policy facts atomically,
	// without exposing a raw pool or general control-plane capability.
	GetAPIKeyAuthentication(ctx context.Context, keyHash string) (*APIKeyAuthentication, error)

	// Roles
	CreateRole(ctx context.Context, role *gen.Role) error
	ListRoles(ctx context.Context, orgID string) ([]*gen.Role, error)
	DeleteRole(ctx context.Context, roleID string) error

	// Role assignments
	AssignRole(ctx context.Context, assignment *gen.RoleAssignment) error
	RevokeRole(ctx context.Context, subjectID string, roleID string, orgID string, scope string) error
	// ListRoleAssignments returns assignments in an org. When subjectID is
	// empty, every assignment in that org is returned. subjectKind ==
	// SUBJECT_KIND_UNSPECIFIED returns both direct principals and teams.
	ListRoleAssignments(ctx context.Context, orgID string, subjectID string, subjectKind gen.SubjectKind) ([]*gen.RoleAssignment, error)

	// Permission checking
	CheckPermission(ctx context.Context, subjectID string, subjectKind gen.SubjectKind, resource string, action string, orgID string, scope string) (bool, string, error)

	// Layered access — hierarchical scope grants + per-record shares (#178).
	// CheckAccess resolves the record's scope from resource_id itself, never a
	// caller-supplied path.
	CheckAccess(ctx context.Context, subjectID string, subjectKind gen.SubjectKind, resourceType, resourceID, action string) (bool, string, error)
	// ListAccessibleScopes is the list-objects companion to CheckAccess: the scope
	// nodes the subject may act on with (resourceType, action), resolved through
	// the same grant + share union so the two never disagree. Ordered by scope_path
	// and cursor-paginated on it (afterPath ""=first page); at most limit rows.
	// Confined to orgID with an explicit predicate on top of the RLS tenant floor.
	ListAccessibleScopes(ctx context.Context, orgID, subjectID string, subjectKind gen.SubjectKind, resourceType, action, afterPath string, limit int) ([]*gen.AccessibleScope, error)
	// ListAccessibleResourceIDs narrows candidates to the placed records the
	// subject may currently act on, through the same grant + share union as
	// ListAccessibleScopes — one call for a set of ids a reader already holds,
	// rather than a point check each. Run under WithOrgTx.
	ListAccessibleResourceIDs(ctx context.Context, orgID, subjectID string, subjectKind gen.SubjectKind, resourceType, action string, candidates []string) ([]string, error)
	CanReadScopeNode(ctx context.Context, orgID, subjectID string, subjectKind gen.SubjectKind, resourceType, action, nodeID string) (bool, error)
	RegisterScopeNode(ctx context.Context, node *gen.ScopeNode) error
	// GetOrCreateCollectionNode reuses an existing collection node with node.Label
	// in the tenant, or registers node and returns its id — one boundary per
	// collection name. Run under WithOrgTx.
	GetOrCreateCollectionNode(ctx context.Context, node *gen.ScopeNode) (string, error)
	// ScopeNodeExists reports whether a scope node id is visible in the caller's
	// tenant (run under WithOrgTx so RLS confines the probe to the org).
	ScopeNodeExists(ctx context.Context, nodeID string) (bool, error)
	ListCollectionAccess(ctx context.Context, orgID, afterPath string, limit int, readResources []string) ([]*gen.CollectionAccess, error)
	GrantScope(ctx context.Context, grant *gen.ScopeGrant) error
	RevokeScope(ctx context.Context, orgID, subjectID string, subjectKind gen.SubjectKind, scopePath, roleID string) error
	ShareRecord(ctx context.Context, share *gen.RecordShare) error
	RevokeShare(ctx context.Context, orgID, resourceType, resourceID, subjectID string, subjectKind gen.SubjectKind, roleID string) error
	ListShares(ctx context.Context, orgID, resourceType, resourceID string) ([]*gen.RecordShare, error)

	// Identity resolution
	ResolveIdentity(ctx context.Context, provider string, providerID string) (*ResolvedIdentity, error)

	// Platform admin
	GetPlatformRole(ctx context.Context, userID string) (string, error)
	GrantPlatformRole(ctx context.Context, userID, role, grantedBy string) error
	RevokePlatformRole(ctx context.Context, userID string) error
	ListPlatformAdmins(ctx context.Context) ([]PlatformAdmin, error)

	// API Keys
	CreateAPIKey(ctx context.Context, key *gen.APIKey, keyHash string) error
	CountActiveAPIKeys(ctx context.Context, orgID string) (int64, error)
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*gen.APIKey, error)
	ListAPIKeys(ctx context.Context, orgID string, pageSize int32, pageToken string) ([]*gen.APIKey, string, error)
	RevokeAPIKey(ctx context.Context, keyID string, orgID string) error
	TouchAPIKeyUsage(ctx context.Context, keyID string, ip string) error

	// Audit
	InsertAuditEvent(ctx context.Context, entry AuditEntry) error
	// ReserveAuditIdempotency records a (org_id, event_type, idempotency_key)
	// guard row so a retried emit collapses to one event. It returns true when the
	// row was newly inserted (write the event) and false when it already existed (a
	// duplicate; skip the write). It MUST run in the emitter's ambient transaction
	// so the guard row and the audit row commit or roll back together. An empty
	// orgID (system-scoped emit) maps to a sentinel org so system events still
	// dedup. See audit_event_idempotency (migration 118).
	ReserveAuditIdempotency(ctx context.Context, orgID, eventType, idempotencyKey string) (bool, error)
	QueryAuditLog(ctx context.Context, q AuditQuery) ([]AuditEntry, string, int32, error)
	AggregateAuditLog(ctx context.Context, q AuditQuery, spec AuditAggregationSpec) ([]AuditAggregateBucket, error)
	SyncAuditEventTypes(ctx context.Context, defs []AuditEventDefinition) error
	ListAuditEventTypes(ctx context.Context) ([]AuditEventTypeRow, error)
	EnsureAuditPartitions(ctx context.Context, months int) error
	DropAuditPartitionsBefore(ctx context.Context, before time.Time) (int64, error)

	// Invitations
	CreateInvitation(ctx context.Context, inv *Invitation) error
	ExpirePendingInvitations(ctx context.Context, orgID string) error
	GetInvitationByTokenHash(ctx context.Context, hash string) (*Invitation, error)
	GetInvitationByID(ctx context.Context, id string) (*Invitation, error)
	GetInvitationOrgID(ctx context.Context, id string) (string, error)
	ListInvitations(ctx context.Context, orgID string, status string) ([]*Invitation, error)
	RotateInvitationToken(ctx context.Context, inv *Invitation) error
	UpdateInvitationStatus(ctx context.Context, id string, status string, acceptedBy string) (bool, error)
	CountPendingInvitations(ctx context.Context, orgID string) (int32, error)
	HasPendingInvitationForEmail(ctx context.Context, email string) (bool, error)

	// Waitlist
	GetWaitlistReferralID(ctx context.Context, code string) (string, error)
	UpsertWaitlistEntry(ctx context.Context, entry *WaitlistEntry, cooldown time.Duration) (*WaitlistUpsertResult, error)
	VerifyWaitlistEntry(ctx context.Context, tokenHash string, now time.Time) (*WaitlistVerificationResult, error)
	ListWaitlistEntries(ctx context.Context, state, query, source, campaign string, pageSize int32, pageToken string) ([]*WaitlistEntry, string, error)
	UpdateWaitlistState(ctx context.Context, id, state, notes string, tags []string, now time.Time) (*WaitlistEntry, error)
	InviteWaitlistEntry(ctx context.Context, id string, now time.Time) (*WaitlistEntry, error)
	GetWaitlistStateByEmail(ctx context.Context, email string) (string, error)
	ConvertWaitlistEntry(ctx context.Context, email, userID, orgID string, now time.Time) (*WaitlistEntry, error)

	// SSO
	GetOrgSSO(ctx context.Context, orgID string) (*OrgSSOConfig, error)
	UpsertOrgSSO(ctx context.Context, cfg *OrgSSOConfig) error

	// User settings. The Store boundary is protobuf-typed; only the Postgres
	// implementation sees the ProtoJSON representation stored in JSONB.
	GetUserSettings(ctx context.Context, userID string) (*gen.UserSettings, error)
	UpdateUserSettings(ctx context.Context, userID string, patch *gen.UserSettings, resetPaths []string) error

	// Entitlements
	GetOrgPlanID(ctx context.Context, orgID string) (string, error)
	GetPlanByID(ctx context.Context, planID string) (*Plan, error)
	GetPlanEntitlement(ctx context.Context, planID string, feature string) (int64, error)
	ListPlanEntitlements(ctx context.Context, planID string) ([]PlanFeatureLimit, error)
	GetEntitlementOverride(ctx context.Context, orgID string, feature string) (*EntitlementOverride, error)
	ListEntitlementOverrides(ctx context.Context, orgID string) ([]*EntitlementOverride, error)
	CreateEntitlementOverride(ctx context.Context, override *EntitlementOverride) error
	LockEntitlementQuota(ctx context.Context, orgID string, feature string) error
	GetUsageTotal(ctx context.Context, orgID string, meter string, periodStart time.Time) (int64, error)
	GetUsageBuckets(ctx context.Context, orgID string, meter string, from, to time.Time, bucket UsageBucketInterval) ([]UsageBucketValue, error)
	ConsumeUsage(ctx context.Context, consumption UsageConsumption) (*UsageReceipt, error)
	GetSubscription(ctx context.Context, orgID string) (*Subscription, error)
	CreateSubscription(ctx context.Context, sub *Subscription) error
	UpdateSubscription(ctx context.Context, sub *Subscription) error

	// Billing — Stripe customer + plan-by-name lookups used by the
	// StartCheckout / OpenBillingPortal flows.
	GetOrgStripeCustomerID(ctx context.Context, orgID string) (string, error)
	SetOrgStripeCustomerID(ctx context.Context, orgID, stripeCustomerID string) error
	GetPlanByName(ctx context.Context, name string) (*PlanFull, error)
	ListPublicPlans(ctx context.Context) ([]PublicPlan, error)

	// Legacy feature-flag migration inventory
	ListFeatureFlags(ctx context.Context) ([]*FeatureFlag, error)

	// Platform admin - user operations
	SearchUsers(ctx context.Context, query string, pageSize int32, pageToken string) ([]*gen.User, string, error)
	UpdateUserStatus(ctx context.Context, userID string, status string) error
	ListActiveSessions(ctx context.Context, userID string, pageSize int32) ([]*Session, error)

	// Sessions
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByRefreshTokenHash(ctx context.Context, hash string) (*Session, error)
	// RevokeSession revokes every live row in the device family and returns the
	// ids of the rows it revoked. Those ids are the `sid` claim carried by the
	// family's outstanding access tokens, so the caller can write a
	// session-revocation marker per id and kill the access half immediately.
	RevokeSession(ctx context.Context, deviceSessionID string, reason string) ([]string, error)
	RevokeSessionFamily(ctx context.Context, familyID string, reason string) error
	RevokeAllUserSessions(ctx context.Context, userID string, reason string) error
	UpdateSessionActivity(ctx context.Context, sessionID string) error

	// Webhooks
	CreateWebhookSubscription(ctx context.Context, sub *WebhookSubscription) error
	GetWebhookSubscription(ctx context.Context, id string) (*WebhookSubscription, error)
	UpdateWebhookSubscription(ctx context.Context, sub *WebhookSubscription) error
	DeleteWebhookSubscription(ctx context.Context, id string) error
	ListWebhookSubscriptions(ctx context.Context, orgID string) ([]*WebhookSubscription, error)
	// SyncWebhookEventSubscriptions makes an endpoint registration's subscription
	// rows match the event names it is registered for. Delivery is driven by
	// those rows, so the relay fans an event out to an endpoint only through a
	// subscription this created.
	SyncWebhookEventSubscriptions(ctx context.Context, orgID, webhookSubscriptionID string, eventNames []string) error
	CreateWebhookDelivery(ctx context.Context, delivery *WebhookDelivery) error
	GetWebhookDelivery(ctx context.Context, id string) (*WebhookDelivery, error)
	ListWebhookDeliveries(ctx context.Context, subscriptionID string, pageSize int) ([]*WebhookDelivery, error)

	// Domain event subscriptions (pub/sub control plane — issue #493).
	// event_subscriptions is a control-plane-owned platform relation (no RLS),
	// so all three run under WithControlPlane; request traffic never writes it.
	//
	//   - CreateEventSubscription is idempotent on the active-unique index
	//     (subscriber_principal_id, type_pattern, queue) WHERE revoked_at IS NULL:
	//     re-subscribing the same shape returns the existing live row instead of a
	//     second row. The returned bool reports whether a new row was inserted.
	//   - RevokeEventSubscription is scoped by subscriber_principal_id so a caller
	//     can only revoke a subscription it owns; the bool reports whether a live
	//     row was revoked (false = not found or already revoked / not owned).
	//   - ListEventSubscriptions returns the principal's live (non-revoked) rows.
	//   - CountLiveEventSubscriptions counts every live (non-revoked) subscription
	//     across all principals. Startup uses it to assert that a module which has
	//     accepted subscriptions also has a delivery transport wired, so events are
	//     never silently dropped on the floor.
	CreateEventSubscription(ctx context.Context, sub *EventSubscription) (*EventSubscription, bool, error)
	RevokeEventSubscription(ctx context.Context, subscriptionID, subscriberPrincipalID string) (bool, error)
	ListEventSubscriptions(ctx context.Context, subscriberPrincipalID string) ([]*EventSubscription, error)
	CountLiveEventSubscriptions(ctx context.Context) (int, error)

	// Solution registry (issue #534). solution_registrations is a control-plane
	// -owned platform relation with no tenant column, so all four run under
	// WithControlPlane; request traffic has no access to it at all.
	//
	//   - GetSolutionRegistrationForUpdate returns nil when no record exists and
	//     row-locks the record when one does, so the read-decide-write that
	//     implements compare-and-swap cannot interleave with a concurrent write.
	//   - NextSolutionRegistryRevision draws the next registry-wide revision.
	//   - SaveSolutionRegistration persists the whole record at the revision it
	//     carries; a tombstoned record is written with both halves cleared.
	//   - ListSolutionRegistrations returns the snapshot plus the highest
	//     revision in the registry, tombstones included.
	GetSolutionRegistrationForUpdate(ctx context.Context, solutionID string) (*SolutionRegistration, error)
	NextSolutionRegistryRevision(ctx context.Context) (int64, error)
	SaveSolutionRegistration(ctx context.Context, record *SolutionRegistration) error
	ListSolutionRegistrations(ctx context.Context, includeTombstoned bool) ([]*SolutionRegistration, int64, error)

	// Organization Settings (branding)
	GetOrgSettings(ctx context.Context, orgID string) (*OrgSettings, error)
	UpsertOrgSettings(ctx context.Context, settings *OrgSettings) error

	// Organization Settings (generic, typed). Mirrors the per-user surface:
	// the Store boundary is protobuf-typed and only the Postgres implementation
	// sees the sparse ProtoJSON stored in JSONB.
	GetOrgGenericSettings(ctx context.Context, orgID string) (*gen.OrganizationSettings, error)
	UpdateOrgGenericSettings(ctx context.Context, orgID string, patch *gen.OrganizationSettings, resetPaths []string) error

	// Notifications
	CreateNotification(ctx context.Context, n *Notification) error
	ListNotifications(ctx context.Context, userID string, pageSize int, pageToken string) ([]*Notification, string, error)
	GetUnreadCount(ctx context.Context, userID string) (int, error)
	// ListUnreadResourceReferences groups the user's unread follow items by the
	// resource they refer to, so the caller can recheck visibility per resource
	// and discount what is no longer readable. Run under WithUserTx.
	ListUnreadResourceReferences(ctx context.Context, userID string) ([]UnreadResourceReference, error)
	MarkNotificationRead(ctx context.Context, id string) error
	MarkAllNotificationsRead(ctx context.Context, userID string) error
	DeleteNotification(ctx context.Context, id string) error
	// GetNotificationUserID resolves notification.id → user_id.
	// Called under WithControlPlane by Service methods that only have an
	// id (MarkRead / DeleteNotification) and need to enter the
	// user's WithUserTx for the actual mutation. Returns "" on miss.
	GetNotificationUserID(ctx context.Context, id string) (string, error)

	// Resource follows. Both run under the follower's WithUserTx, so the RLS
	// policy on resource_follows confines them to that user's own rows.
	CreateResourceFollow(ctx context.Context, follow *ResourceFollow) error
	RevokeResourceFollow(ctx context.Context, userID, resourceType, resourceID string) error

	// ListResourceFollowers answers who currently follows one resource, one
	// bounded page at a time. It reads across users, so it runs under
	// WithControlPlane rather than any one follower's transaction; the result is
	// only a candidate set, and each candidate's access and follow are rechecked
	// before anything is written. Nothing bounds how many people follow one
	// instance, so the caller pages with `after` (the last user id it saw) rather
	// than materializing the whole set.
	ListResourceFollowers(ctx context.Context, orgID, resourceType, resourceID, after string, limit int) ([]string, error)
	// ExistingNotificationIDs reports which of the given notification ids already
	// exist. Notification ids are derived from the delivery key, so a fan-out
	// retry uses this to skip the followers it already wrote instead of redoing
	// the access check and the write for every one of them.
	ExistingNotificationIDs(ctx context.Context, ids []string) (map[string]struct{}, error)
	// ResourceFollowIsLive re-reads one follower's own follow. It runs inside the
	// follower's WithUserTx alongside the notification write, which is what makes
	// a follow revoked before that read suppress the item and stops a replay
	// resurrecting a removed follow.
	ResourceFollowIsLive(ctx context.Context, orgID, userID, resourceType, resourceID string) (bool, error)

	// MFA — exposed on the main Store interface so the auth layer's
	// requireMFA gate can check enrollment without casting to MFAStore.
	HasVerifiedMFA(ctx context.Context, userID string) (bool, error)

	// Onboarding
	GetOnboardingProgress(ctx context.Context, userID, orgID, flowID string, flowVersion uint32) ([]*OnboardingStep, error)
	EnsureOnboardingStep(ctx context.Context, userID, orgID, flowID string, flowVersion uint32, step *OnboardingStep) (*OnboardingStep, error)
	TransitionOnboardingStep(ctx context.Context, userID, orgID, flowID string, flowVersion uint32, fromStatus string, step *OnboardingStep) (*OnboardingStep, bool, error)
	GetOrganizationActivation(ctx context.Context, orgID, flowID string, flowVersion uint32, milestone string) (*time.Time, error)
	RecordOrganizationActivation(ctx context.Context, orgID, flowID string, flowVersion uint32, milestone, actorID string) error

	// Magic Links
	CreateMagicLink(ctx context.Context, ml *MagicLink) error
	GetMagicLinkByTokenHash(ctx context.Context, tokenHash string) (*MagicLink, error)
	MarkMagicLinkUsed(ctx context.Context, id string) error

	// User consent — server-side TOS/privacy acceptance trail.
	GetUserConsent(ctx context.Context, userID string) (version string, acceptedAt *time.Time, err error)
	SetUserConsent(ctx context.Context, userID, version, consentContext string, acceptedAt time.Time) error
	GetUserConsentPreferences(ctx context.Context, userID string) ([]*ConsentPreference, error)
	SetUserConsentPreferences(ctx context.Context, userID string, preferences []*ConsentPreference, region, consentContext string) error

	// Data Retention. audit_events retention is not a row DELETE — the
	// append-only trigger blocks that — but a partition drop; see
	// DropAuditPartitionsBefore above.
	GetRetentionPolicies(ctx context.Context) ([]*RetentionPolicy, error)
	DeleteOldSessions(ctx context.Context, before time.Time) (int64, error)
	DeleteOldWebhookDeliveries(ctx context.Context, before time.Time) (int64, error)
	DeleteOldNotifications(ctx context.Context, before time.Time) (int64, error)
}

type StoreErrorType string

const (
	ErrTypeNotFound   StoreErrorType = "not_found"
	ErrTypeConflict   StoreErrorType = "conflict"
	ErrTypePermission StoreErrorType = "permission"
	ErrTypeInternal   StoreErrorType = "internal"
	// ErrTypeValidation marks a caller-input error (bad request), so a transport
	// adapter can distinguish it from an internal fault and return the right code
	// instead of blaming the client for a server-side failure.
	ErrTypeValidation StoreErrorType = "validation"
)

type StoreError struct {
	Err error
	StoreErrorType
}

func (e *StoreError) Error() string {
	return e.Err.Error()
}

func NewStoreError(err error, t StoreErrorType) *StoreError {
	return &StoreError{
		Err:            err,
		StoreErrorType: t,
	}
}

// ResolvedIdentity is the result of mapping an auth provider identity to internal user/org/roles.
type ResolvedIdentity struct {
	UserID       string
	OrgID        string
	OrgRole      string // "owner"|"admin"|"member"
	PlatformRole string // "super_admin"|"support"|"billing"|""
	Roles        []string
	Found        bool
}

type APIKeyIdentityClaims struct {
	Member       bool
	OrgRole      string
	PlatformRole string
	Workspaces   []string
	Roles        []string
	Attributes   map[string]string
}

type APIKeyAuthentication struct {
	Key    *gen.APIKey
	Claims APIKeyIdentityClaims
}

// PlatformAdmin represents a user with platform-level privileges.
type PlatformAdmin struct {
	UserID       string
	PlatformRole string
	GrantedBy    string
	GrantedAt    time.Time
}

// RetentionPolicy defines how long records of a given type should be kept.
type RetentionPolicy struct {
	ID            string
	ResourceType  string
	RetentionDays int
	CreatedAt     time.Time
}

// Session represents a refresh token session.
type Session struct {
	ID               string
	UserID           string
	RefreshTokenHash string
	FamilyID         string
	DeviceInfo       map[string]string
	IPAddress        string
	CreatedAt        time.Time
	LastActiveAt     time.Time
	IdleExpiresAt    time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	RevokedReason    string
}
