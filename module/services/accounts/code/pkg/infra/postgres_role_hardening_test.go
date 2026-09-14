//go:build !pure

package infra_test

import (
	"context"
	"regexp"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"accounts/pkg/relationcatalog"
)

type relationPrivileges struct {
	selectRows bool
	insertRows bool
	updateRows bool
	deleteRows bool
}

// externalRelationAuthorities is an additive test seam for product services
// that share the physical Postgres service but own their own migrations. A
// consumer must register every such public relation explicitly; otherwise the
// complete inventory test still fails closed. Accounts' request role must not
// acquire DML authority over a relation merely because it shares a database.
type externalRelationAuthority struct {
	owner               string
	appTenantPrivileges relationPrivileges
}

var externalRelationAuthorities = map[string]externalRelationAuthority{}

var appTenantRelationPrivileges = map[string]relationPrivileges{
	// Global catalogs and worker-owned job relations.
	"identity_providers":      {selectRows: true},
	"plans":                   {selectRows: true},
	"plan_entitlements":       {selectRows: true},
	"email_templates":         {selectRows: true},
	"data_retention_policies": {selectRows: true},
	"bootstrap_state":         {selectRows: true, updateRows: true},
	"feature_flags":           {selectRows: true},
	"audit_event_types":       {selectRows: true},
	"platform_admins":         {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"analytics_deliveries":    {},
	"email_delivery_events":   {},
	"event_subscriptions":     {}, // platform relation; request traffic has no direct access
	"solution_registrations":  {}, // platform relation; request traffic has no direct access
	"job_attempts":            {},
	"job_messages":            {},
	"job_state_transitions":   {},

	// Tenant-scoped relations.
	"execution_custody":                    {},
	"actor_chain_journal":                  {selectRows: true, insertRows: true},
	"actor_chain_revocations":              {selectRows: true, insertRows: true},
	"api_keys":                             {selectRows: true, insertRows: true, updateRows: true},
	"approval_decisions":                   {selectRows: true, insertRows: true}, // append-only, like actor_chain_journal
	"approval_requests":                    {selectRows: true, insertRows: true, updateRows: true},
	"audit_event_idempotency":              {selectRows: true, insertRows: true}, // append-only guard, like audit_events
	"audit_events":                         {selectRows: true, insertRows: true},
	"connector_credentials":                {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"dashboards":                           {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"installations":                        {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"datasource_sources":                   {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"delegation_grants":                    {selectRows: true, insertRows: true, updateRows: true},
	"domain_events":                        {selectRows: true}, // request traffic reads its own tenant's events; publishes via SECURITY DEFINER
	"entitlement_overrides":                {selectRows: true, insertRows: true, updateRows: true},
	"invitations":                          {selectRows: true, insertRows: true, updateRows: true},
	"membership_integrity_findings":        {}, // operator repair evidence; no request-traffic authority at all
	"org_generic_settings":                 {selectRows: true, insertRows: true, updateRows: true},
	"org_identity_providers":               {selectRows: true, insertRows: true, updateRows: true},
	"org_settings":                         {selectRows: true, insertRows: true, updateRows: true},
	"organization_activations":             {selectRows: true, insertRows: true, updateRows: true},
	"organization_authorization_revisions": {selectRows: true},
	"source_read_revisions":                {selectRows: true},
	"organization_members":                 {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"organizations":                        {selectRows: true, insertRows: true, updateRows: true},
	"principal_authorization_revisions":    {selectRows: true},
	"principals":                           {selectRows: true, insertRows: true, updateRows: true},
	"record_shares":                        {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"role_assignments":                     {selectRows: true, insertRows: true, deleteRows: true},
	"role_permissions":                     {selectRows: true, insertRows: true},
	"roles":                                {selectRows: true, insertRows: true, deleteRows: true},
	"scope_grants":                         {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"scope_nodes":                          {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"subscriptions":                        {selectRows: true, insertRows: true, updateRows: true},
	"team_members":                         {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"team_membership_quarantine":           {},
	"teams":                                {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"usage_events":                         {selectRows: true, insertRows: true},
	"usage_totals":                         {selectRows: true, insertRows: true, updateRows: true},
	"webhook_deliveries":                   {selectRows: true, insertRows: true, updateRows: true},
	"webhook_subscriptions":                {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"work_context_replay":                  {selectRows: true, insertRows: true}, // claim-once; GC deletes run under app_control_plane

	// User-scoped and pre-auth relations.
	// A privacy request is accepted and read by request traffic; only the leased
	// worker transitions it, under the control plane.
	"gdpr_requests":          {selectRows: true, insertRows: true},
	"magic_links":            {},
	"mfa_backup_codes":       {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"mfa_devices":            {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"mfa_login_transactions": {insertRows: true},
	"notifications":          {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"onboarding_progress":    {selectRows: true, insertRows: true, updateRows: true},
	"resource_follows":       {selectRows: true, insertRows: true, updateRows: true},
	"sessions":               {selectRows: true, insertRows: true, updateRows: true},
	"user_consent_events":    {selectRows: true, insertRows: true},
	"user_consent_preferences": {
		selectRows: true, insertRows: true, updateRows: true,
	},
	"user_identities":      {selectRows: true, insertRows: true, updateRows: true, deleteRows: true},
	"users":                {selectRows: true, insertRows: true, updateRows: true},
	"webauthn_ceremonies":  {selectRows: true, insertRows: true, updateRows: true},
	"webauthn_credentials": {selectRows: true, insertRows: true, updateRows: true},
	"waitlist_entries":     {},
}

func TestRuntimeDatabaseRolesHavePinnedAuthority(t *testing.T) {
	expected := map[string]struct {
		bypassRLS bool
	}{
		"app_tenant":         {bypassRLS: false},
		"app_control_plane":  {bypassRLS: true},
		"app_billing_worker": {bypassRLS: true},
		"app_webhook_worker": {bypassRLS: true},
		"app_job_worker":     {bypassRLS: true},
	}

	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		for role, want := range expected {
			var canLogin, superuser, bypassRLS, createDB, createRole, inherit, replication bool
			err := tx.QueryRow(ctx, `
				SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreatedb,
				       rolcreaterole, rolinherit, rolreplication
				FROM pg_roles
				WHERE rolname = $1`, role,
			).Scan(&canLogin, &superuser, &bypassRLS, &createDB, &createRole, &inherit, &replication)
			require.NoError(t, err, role)
			require.False(t, canLogin, role)
			require.False(t, superuser, role)
			require.Equal(t, want.bypassRLS, bypassRLS, role)
			require.False(t, createDB, role)
			require.False(t, createRole, role)
			require.False(t, inherit, role)
			require.False(t, replication, role)
		}
		return nil
	}))
}

func TestRuntimeSessionAndRelationOwnershipAreSeparated(t *testing.T) {
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		var sessionRole, currentRole string
		var superuser, bypassRLS, createDB, createRole, replication bool
		err := tx.QueryRow(ctx, `
			SELECT session_user, current_user, role.rolsuper, role.rolbypassrls,
			       role.rolcreatedb, role.rolcreaterole, role.rolreplication
			FROM pg_roles role
			WHERE role.rolname = session_user`,
		).Scan(&sessionRole, &currentRole, &superuser, &bypassRLS, &createDB, &createRole, &replication)
		require.NoError(t, err)
		require.Equal(t, "app_control_plane", currentRole)
		require.NotEqual(t, sessionRole, currentRole, "control-plane work must use a named role")
		require.False(t, superuser, sessionRole)
		require.False(t, bypassRLS, sessionRole)
		require.False(t, createDB, sessionRole)
		require.False(t, createRole, sessionRole)
		require.False(t, replication, sessionRole)

		var migrationOwner string
		require.NoError(t, tx.QueryRow(ctx, `
			SELECT tableowner
			FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'schema_migrations'`,
		).Scan(&migrationOwner))
		require.NotEqual(t, sessionRole, migrationOwner)

		rows, err := tx.Query(ctx, `
			SELECT DISTINCT tableowner
			FROM pg_tables
			WHERE schemaname = 'public'
			  AND tablename <> 'schema_migrations'`)
		require.NoError(t, err)
		defer rows.Close()
		for rows.Next() {
			var owner string
			require.NoError(t, rows.Scan(&owner))
			require.Equal(t, migrationOwner, owner, "all application relations must be migration-owned")
			require.NotEqual(t, sessionRole, owner, "runtime session must not own application relations")
			require.NotContains(t, []string{
				"app_tenant", "app_control_plane", "app_billing_worker", "app_webhook_worker", "app_job_worker",
			}, owner, "application roles must not own relations")
		}
		return rows.Err()
	}))
}

func TestTenantRoleCannotBypassRLSOrGrowSchemaAuthority(t *testing.T) {
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		var canTruncate, canCreate, canUseTemporary, controlPlaneMember, billingMember, webhookMember, jobMember bool
		err := tx.QueryRow(ctx, `
			SELECT has_table_privilege('app_tenant', 'organizations', 'TRUNCATE'),
			       has_schema_privilege('app_tenant', 'public', 'CREATE'),
			       has_database_privilege('app_tenant', current_database(), 'TEMPORARY'),
			       pg_has_role('app_tenant', 'app_control_plane', 'MEMBER'),
			       pg_has_role('app_tenant', 'app_billing_worker', 'MEMBER'),
			       pg_has_role('app_tenant', 'app_webhook_worker', 'MEMBER'),
			       pg_has_role('app_tenant', 'app_job_worker', 'MEMBER')`,
		).Scan(&canTruncate, &canCreate, &canUseTemporary, &controlPlaneMember, &billingMember, &webhookMember, &jobMember)
		require.NoError(t, err)
		require.False(t, canTruncate, "TRUNCATE bypasses tenant RLS")
		require.False(t, canCreate, "tenant runtime must not create schema objects")
		require.False(t, canUseTemporary, "tenant runtime must not create temporary relations")
		require.False(t, controlPlaneMember, "tenant runtime must not assume the control-plane role")
		require.False(t, billingMember, "tenant runtime must not assume the billing worker role")
		require.False(t, webhookMember, "tenant runtime must not assume the webhook projection role")
		require.False(t, jobMember, "tenant runtime must not assume the job worker role")
		return nil
	}))
}

func TestTenantRoleHasNoImplicitFutureTablePrivileges(t *testing.T) {
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		var unsafeDefault bool
		err := tx.QueryRow(ctx, `
			SELECT COALESCE(bool_or(
				grantee.rolname = 'app_tenant'
				AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
			), false)
			FROM pg_default_acl defaults
			CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl
			LEFT JOIN pg_roles grantee ON grantee.oid = acl.grantee
			WHERE defaults.defaclnamespace = 'public'::regnamespace
			  AND defaults.defaclobjtype = 'r'`,
		).Scan(&unsafeDefault)
		require.NoError(t, err)
		require.False(t, unsafeDefault, "new tables require explicit migration-owned grants")
		return nil
	}))
}

func TestTenantRoleRelationGrantsAreExact(t *testing.T) {
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		for relation, want := range appTenantRelationPrivileges {
			var got relationPrivileges
			var truncateRows bool
			err := tx.QueryRow(ctx, `
				SELECT has_table_privilege('app_tenant', $1, 'SELECT'),
				       has_table_privilege('app_tenant', $1, 'INSERT'),
				       has_table_privilege('app_tenant', $1, 'UPDATE'),
				       has_table_privilege('app_tenant', $1, 'DELETE'),
				       has_table_privilege('app_tenant', $1, 'TRUNCATE')`, relation,
			).Scan(&got.selectRows, &got.insertRows, &got.updateRows, &got.deleteRows, &truncateRows)
			require.NoError(t, err, relation)
			require.Equal(t, want, got, relation)
			require.False(t, truncateRows, relation)
		}
		return nil
	}))
}

func TestControlPlaneRelationGrantsAreExact(t *testing.T) {
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		for relation, authority := range relationcatalog.All() {
			want := relationPrivileges{
				selectRows: true,
				insertRows: true,
				updateRows: true,
				deleteRows: true,
			}
			if authority.Scope == relationcatalog.ScopeWorker || authority.Scope == relationcatalog.ScopeJob {
				want = relationPrivileges{}
			}
			if relation == "feature_flags" {
				want = relationPrivileges{selectRows: true}
			}
			// audit_events is append-only: the control plane reads and inserts
			// (system NULL-org events) but never updates or deletes rows.
			// Retention drops whole partitions via a SECURITY DEFINER function,
			// not a row DELETE, so no DELETE grant is needed.
			if relation == "audit_events" {
				want = relationPrivileges{selectRows: true, insertRows: true}
			}
			// audit_event_idempotency is an append-only guard like audit_events:
			// the control plane reads and inserts reservations (system NULL-org
			// emits land on the sentinel org) but never updates or deletes them.
			if relation == "audit_event_idempotency" {
				want = relationPrivileges{selectRows: true, insertRows: true}
			}
			// actor_chain_journal / actor_chain_revocations are append-only
			// like audit_events: the control plane reads and inserts but never
			// updates or deletes (an immutable trigger rejects those anyway).
			if relation == "actor_chain_journal" || relation == "actor_chain_revocations" {
				want = relationPrivileges{selectRows: true, insertRows: true}
			}
			// approval_requests is the mutable head; source_read_revisions is
			// a monotonic cursor revision. The control plane reads, inserts,
			// and updates both; organization deletion uses the FK cascade.
			if relation == "approval_requests" || relation == "source_read_revisions" {
				want = relationPrivileges{selectRows: true, insertRows: true, updateRows: true}
			}
			// approval_decisions is append-only like actor_chain_journal: read and
			// insert, never update or delete (an immutable trigger rejects those).
			if relation == "approval_decisions" {
				want = relationPrivileges{selectRows: true, insertRows: true}
			}
			// work_context_replay is claim-once: the control plane reads, inserts,
			// and deletes (the expiry sweep) but never updates a consumed marker.
			if relation == "work_context_replay" || relation == "execution_custody" {
				want = relationPrivileges{selectRows: true, insertRows: true, deleteRows: true}
			}
			// domain_events and event_subscriptions: the control plane publishes
			// platform events and maintains subscriptions (materialize / subscribe /
			// unsubscribe marks revoked_at), so it reads, inserts, and updates but
			// never row-deletes — retention and revocation are soft.
			if relation == "domain_events" || relation == "event_subscriptions" {
				want = relationPrivileges{selectRows: true, insertRows: true, updateRows: true}
			}
			// team_membership_quarantine records what migration 127 removed. Only
			// the migration writes it, and it is evidence of a repair — the
			// runtime reads it and must not be able to edit the record away.
			if relation == "team_membership_quarantine" {
				want = relationPrivileges{selectRows: true}
			}

			var got relationPrivileges
			var truncateRows bool
			err := tx.QueryRow(ctx, `
				SELECT has_table_privilege('app_control_plane', $1, 'SELECT'),
				       has_table_privilege('app_control_plane', $1, 'INSERT'),
				       has_table_privilege('app_control_plane', $1, 'UPDATE'),
				       has_table_privilege('app_control_plane', $1, 'DELETE'),
				       has_table_privilege('app_control_plane', $1, 'TRUNCATE')`, relation,
			).Scan(&got.selectRows, &got.insertRows, &got.updateRows, &got.deleteRows, &truncateRows)
			require.NoError(t, err, relation)
			require.Equal(t, want, got, relation)
			require.False(t, truncateRows, relation)
		}

		var canCreate, canUseTemporary, billingMember, webhookMember, jobMember, unsafeDefault bool
		require.NoError(t, tx.QueryRow(ctx, `
			SELECT has_schema_privilege('app_control_plane', 'public', 'CREATE'),
			       has_database_privilege('app_control_plane', current_database(), 'TEMPORARY'),
			       pg_has_role('app_control_plane', 'app_billing_worker', 'MEMBER'),
			       pg_has_role('app_control_plane', 'app_webhook_worker', 'MEMBER'),
			       pg_has_role('app_control_plane', 'app_job_worker', 'MEMBER'),
			       (
			           SELECT COALESCE(bool_or(
			               grantee.rolname = 'app_control_plane'
			               AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
			           ), false)
			           FROM pg_default_acl defaults
			           CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl
			           LEFT JOIN pg_roles grantee ON grantee.oid = acl.grantee
			           WHERE defaults.defaclnamespace = 'public'::regnamespace
			             AND defaults.defaclobjtype = 'r'
			       )`,
		).Scan(&canCreate, &canUseTemporary, &billingMember, &webhookMember, &jobMember, &unsafeDefault))
		require.False(t, canCreate)
		require.False(t, canUseTemporary)
		require.False(t, billingMember)
		require.False(t, webhookMember)
		require.False(t, jobMember)
		require.False(t, unsafeDefault, "new tables require explicit control-plane grants")
		return nil
	}))
}

func TestBillingWorkerRoleHasProjectionOnlyAuthority(t *testing.T) {
	expected := map[string]relationPrivileges{
		"plans":                 {selectRows: true},
		"organizations":         {selectRows: true},
		"users":                 {selectRows: true},
		"subscriptions":         {selectRows: true, insertRows: true, updateRows: true},
		"job_messages":          {},
		"job_attempts":          {},
		"job_state_transitions": {},
	}
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		for relation, want := range expected {
			var got relationPrivileges
			var truncateRows bool
			require.NoError(t, tx.QueryRow(ctx, `
				SELECT has_table_privilege('app_billing_worker', $1, 'SELECT'),
				       has_table_privilege('app_billing_worker', $1, 'INSERT'),
				       has_table_privilege('app_billing_worker', $1, 'UPDATE'),
				       has_table_privilege('app_billing_worker', $1, 'DELETE'),
				       has_table_privilege('app_billing_worker', $1, 'TRUNCATE')`, relation,
			).Scan(
				&got.selectRows, &got.insertRows, &got.updateRows, &got.deleteRows, &truncateRows,
			), relation)
			require.Equal(t, want, got, relation)
			require.False(t, truncateRows, relation)
		}
		return nil
	}))
}

func TestWebhookProjectionRoleHasProjectionOnlyAuthority(t *testing.T) {
	expected := map[string]relationPrivileges{
		"webhook_subscriptions": {selectRows: true},
		"webhook_deliveries":    {selectRows: true},
	}
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		for relation := range relationcatalog.All() {
			var got relationPrivileges
			var truncateRows bool
			require.NoError(t, tx.QueryRow(ctx, `
				SELECT has_table_privilege('app_webhook_worker', $1, 'SELECT'),
				       has_table_privilege('app_webhook_worker', $1, 'INSERT'),
				       has_table_privilege('app_webhook_worker', $1, 'UPDATE'),
				       has_table_privilege('app_webhook_worker', $1, 'DELETE'),
				       has_table_privilege('app_webhook_worker', $1, 'TRUNCATE')`, relation,
			).Scan(
				&got.selectRows, &got.insertRows, &got.updateRows, &got.deleteRows, &truncateRows,
			), relation)
			require.Equal(t, expected[relation], got, relation)
			require.False(t, truncateRows, relation)
		}
		var canCreate, canUseTemporary bool
		require.NoError(t, tx.QueryRow(ctx, `
			SELECT has_schema_privilege('app_webhook_worker', 'public', 'CREATE'),
			       has_database_privilege('app_webhook_worker', current_database(), 'TEMPORARY')`,
		).Scan(&canCreate, &canUseTemporary))
		require.False(t, canCreate)
		require.False(t, canUseTemporary)

		mutableColumns := map[string]bool{
			"status": true, "http_status": true, "response_body": true,
			"attempts": true, "last_attempt_at": true,
			"delivered_at": true, "updated_at": true,
		}
		rows, err := tx.Query(ctx, `
			SELECT column_name,
			       has_column_privilege(
			           'app_webhook_worker', 'webhook_deliveries', column_name, 'UPDATE'
			       )
			FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'webhook_deliveries'`)
		require.NoError(t, err)
		defer rows.Close()
		for rows.Next() {
			var column string
			var canUpdate bool
			require.NoError(t, rows.Scan(&column, &canUpdate))
			require.Equal(t, mutableColumns[column], canUpdate, column)
		}
		require.NoError(t, rows.Err())
		return nil
	}))
}

func TestAnalyticsDeliveryRoleHasProjectionOnlyAuthority(t *testing.T) {
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		var canSelect, canInsert, canUpdate, canDelete, canTruncate bool
		require.NoError(t, tx.QueryRow(ctx, `
			SELECT has_table_privilege('app_job_worker', 'analytics_deliveries', 'SELECT'),
			       has_table_privilege('app_job_worker', 'analytics_deliveries', 'INSERT'),
			       has_table_privilege('app_job_worker', 'analytics_deliveries', 'UPDATE'),
			       has_table_privilege('app_job_worker', 'analytics_deliveries', 'DELETE'),
			       has_table_privilege('app_job_worker', 'analytics_deliveries', 'TRUNCATE')`,
		).Scan(&canSelect, &canInsert, &canUpdate, &canDelete, &canTruncate))
		require.True(t, canSelect)
		require.True(t, canInsert)
		require.False(t, canUpdate)
		require.False(t, canDelete)
		require.False(t, canTruncate)

		mutableColumns := map[string]bool{
			"provider_reference": true,
			"duplicate":          true,
			"delivered_at":       true,
		}
		rows, err := tx.Query(ctx, `
			SELECT column_name,
			       has_column_privilege(
			           'app_job_worker', 'analytics_deliveries', column_name, 'UPDATE'
			       )
			FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'analytics_deliveries'`)
		require.NoError(t, err)
		defer rows.Close()
		for rows.Next() {
			var column string
			var canUpdateColumn bool
			require.NoError(t, rows.Scan(&column, &canUpdateColumn))
			require.Equal(t, mutableColumns[column], canUpdateColumn, column)
		}
		return rows.Err()
	}))
}

func TestDatabaseRelationAuthorityInventoryIsComplete(t *testing.T) {
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		// relispartition excludes the audit_events monthly partition children:
		// they are dynamically named and inherit access through the partitioned
		// parent, so they carry no independent authority to classify.
		rows, err := tx.Query(ctx, `
			SELECT c.relname
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public'
			  AND c.relkind IN ('r', 'p')
			  AND NOT c.relispartition
			  AND c.relname <> 'schema_migrations'
			ORDER BY c.relname`)
		require.NoError(t, err)
		defer rows.Close()

		var actual []string
		for rows.Next() {
			var relation string
			require.NoError(t, rows.Scan(&relation))
			actual = append(actual, relation)
		}
		require.NoError(t, rows.Err())

		expected := make([]string, 0, len(relationcatalog.All())+len(externalRelationAuthorities))
		for relation := range relationcatalog.All() {
			expected = append(expected, relation)
		}
		for relation, authority := range externalRelationAuthorities {
			_, baseRelation := relationcatalog.All()[relation]
			require.False(t, baseRelation, "%s cannot be both Accounts-owned and externally owned by %s", relation, authority.owner)
			expected = append(expected, relation)

			var actualPrivileges relationPrivileges
			require.NoError(t, tx.QueryRow(ctx, `
				SELECT has_table_privilege('app_tenant', $1, 'SELECT'),
				       has_table_privilege('app_tenant', $1, 'INSERT'),
				       has_table_privilege('app_tenant', $1, 'UPDATE'),
				       has_table_privilege('app_tenant', $1, 'DELETE')`, relation,
			).Scan(
				&actualPrivileges.selectRows,
				&actualPrivileges.insertRows,
				&actualPrivileges.updateRows,
				&actualPrivileges.deleteRows,
			), relation)
			assert.Equal(t, authority.appTenantPrivileges, actualPrivileges,
				"%s-owned relation %s has unclassified app_tenant authority", authority.owner, relation)

			var controlPlanePrivileges relationPrivileges
			require.NoError(t, tx.QueryRow(ctx, `
				SELECT has_table_privilege('app_control_plane', $1, 'SELECT'),
				       has_table_privilege('app_control_plane', $1, 'INSERT'),
				       has_table_privilege('app_control_plane', $1, 'UPDATE'),
				       has_table_privilege('app_control_plane', $1, 'DELETE')`, relation,
			).Scan(
				&controlPlanePrivileges.selectRows,
				&controlPlanePrivileges.insertRows,
				&controlPlanePrivileges.updateRows,
				&controlPlanePrivileges.deleteRows,
			), relation)
			assert.Equal(t, relationPrivileges{}, controlPlanePrivileges,
				"%s-owned relation %s leaked authority to app_control_plane", authority.owner, relation)
		}
		sort.Strings(expected)
		require.Equal(t, expected, actual, "every public table needs an explicit authority classification")
		require.Len(t, appTenantRelationPrivileges, len(relationcatalog.All()),
			"scope and privilege inventories must cover the same relations")
		for relation := range relationcatalog.All() {
			_, ok := appTenantRelationPrivileges[relation]
			require.True(t, ok, relation)
		}
		return nil
	}))
}

func TestDatabaseRelationRLSMatchesAuthorityScope(t *testing.T) {
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		for relation, authority := range relationcatalog.All() {
			var enabled, forced bool
			var policyCount int
			err := tx.QueryRow(ctx, `
				SELECT class.relrowsecurity,
				       class.relforcerowsecurity,
				       COUNT(policy.polname)
				FROM pg_class class
				LEFT JOIN pg_policy policy ON policy.polrelid = class.oid
				WHERE class.oid = $1::regclass
				GROUP BY class.oid, class.relrowsecurity, class.relforcerowsecurity`, relation,
			).Scan(&enabled, &forced, &policyCount)
			require.NoError(t, err, relation)

			requiresRLS := authority.Scope.RequiresRLS()
			require.Equal(t, requiresRLS, enabled, relation)
			require.Equal(t, requiresRLS, forced, relation)
			if requiresRLS {
				require.Positive(t, policyCount, relation)
			} else {
				require.Zero(t, policyCount, relation)
			}
		}
		return nil
	}))
}

func TestActivePoliciesDoNotTrustSessionBypassSettings(t *testing.T) {
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		var count int
		require.NoError(t, tx.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM pg_policy policy
			JOIN pg_class class ON class.oid = policy.polrelid
			JOIN pg_namespace namespace ON namespace.oid = class.relnamespace
			WHERE namespace.nspname = 'public'
			  AND (
			      COALESCE(pg_get_expr(policy.polqual, policy.polrelid), '') LIKE '%app.bypass%'
			      OR COALESCE(pg_get_expr(policy.polwithcheck, policy.polrelid), '') LIKE '%app.bypass%'
			  )`,
		).Scan(&count))
		require.Zero(t, count, "custom session settings must never grant RLS authority")
		return nil
	}))
}

// TestPublishedRLSPolicyDetailMatchesLivePolicies gates the per-relation
// editorial detail the api service publishes through GetServiceInfo, which
// claims fail_closed for every relation it lists.
//
// Scope inventory and policy presence alone cannot support that claim: a
// relation keeps forced RLS and a non-zero policy count when a migration adds a
// permissive USING (true) policy beside the scoped one. So this checks EVERY
// policy expression individually — each must compare the published scope column
// or admit nothing — rather than asking whether the column appears somewhere in
// the relation's policies.
func TestPublishedRLSPolicyDetailMatchesLivePolicies(t *testing.T) {
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared transaction context key
		for relation, authority := range relationcatalog.All() {
			if !authority.Scope.RequiresRLS() {
				require.Empty(t, authority.PolicyShape, relation)
				require.Empty(t, authority.ScopeColumn, relation)
				continue
			}
			require.NotEmpty(t, authority.PolicyShape, relation)

			policies := livePolicies(ctx, t, tx, relation)
			// Explicit background policies replace BYPASSRLS only for the exact
			// active SQL role. Keep checking every request-visible predicate.
			requestPolicies := policies[:0]
			for _, policy := range policies {
				if policy.migrationOwner != "" {
					require.Equal(t, "webhook_subscriptions", relation)
					require.Equal(t, "r", policy.command, relation)
					require.Equal(t, []string{"(CURRENT_USER = '" + policy.migrationOwner + "'::name)"}, policy.expressions, relation)
					continue
				}
				if policy.backgroundRole != "" {
					require.Equal(t, "*", policy.command, relation)
					require.Equal(t, []string{"(CURRENT_USER = '" + policy.backgroundRole + "'::name)", "(CURRENT_USER = '" + policy.backgroundRole + "'::name)"}, policy.expressions, relation)
					continue
				}
				requestPolicies = append(requestPolicies, policy)
			}
			policies = requestPolicies
			require.NotEmpty(t, policies, relation)

			switch authority.PolicyShape {
			case relationcatalog.ShapeControlPlane:
				require.Empty(t, authority.ScopeColumn, relation)
				for _, policy := range policies {
					for _, expression := range policy.expressions {
						require.Equal(t, "false", expression,
							"%s is published as control-plane-only but a policy admits rows", relation)
					}
				}
			case relationcatalog.ShapeFunctionScoped:
				require.Empty(t, authority.ScopeColumn, relation)
				for _, policy := range policies {
					require.NotContains(t, []string{"r", "*"}, policy.command,
						"%s is published as function-scoped but a policy grants request traffic reads", relation)
				}
			default:
				require.NotEmpty(t, authority.ScopeColumn, relation)
				// pg_attribute rather than information_schema.columns: the latter
				// hides relations the current role holds no privilege on, and the
				// job platform grants the control plane none.
				var columnExists bool
				require.NoError(t, tx.QueryRow(ctx, `
					SELECT EXISTS (
					    SELECT 1 FROM pg_attribute
					    WHERE attrelid = $1::regclass
					      AND attname = $2
					      AND attnum > 0
					      AND NOT attisdropped
					)`, relation, authority.ScopeColumn,
				).Scan(&columnExists), relation)
				require.True(t, columnExists,
					"%s publishes scope column %q, which the relation does not have", relation, authority.ScopeColumn)

				reference := regexp.MustCompile(
					`(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(authority.ScopeColumn) + `([^A-Za-z0-9_]|$)`)
				for _, policy := range policies {
					for _, expression := range policy.expressions {
						require.True(t, expression == "false" || reference.MatchString(expression),
							"%s publishes scope column %q, but one of its policies neither compares it nor denies: %s",
							relation, authority.ScopeColumn, expression)
					}
				}
			}
		}
		return nil
	}))
}

type livePolicy struct {
	backgroundRole string
	migrationOwner string
	command        string
	expressions    []string
}

func livePolicies(ctx context.Context, t *testing.T, tx pgx.Tx, relation string) []livePolicy {
	t.Helper()
	rows, err := tx.Query(ctx, `
		SELECT policy.polcmd::text,
		       COALESCE(pg_get_expr(policy.polqual, policy.polrelid), ''),
		       COALESCE(pg_get_expr(policy.polwithcheck, policy.polrelid), ''),
 CASE WHEN cardinality(policy.polroles)=1 AND policy.polname=role.rolname || '_explicit_rows'
 AND role.rolname IN ('app_control_plane','app_billing_worker','app_webhook_worker','app_job_worker')
 THEN role.rolname ELSE '' END,
 CASE WHEN cardinality(policy.polroles)=1
 AND policy.polname='webhook_subscriptions_migration_owner_read'
 AND relation.relname='webhook_subscriptions' AND role.oid=relation.relowner
 THEN role.rolname ELSE '' END
		FROM pg_policy policy
 JOIN pg_class relation ON relation.oid=policy.polrelid
 LEFT JOIN pg_roles role ON role.oid=policy.polroles[1]
		WHERE policy.polrelid = $1::regclass`, relation)
	require.NoError(t, err, relation)
	defer rows.Close()

	var policies []livePolicy
	for rows.Next() {
		var command, using, check, backgroundRole, migrationOwner string
		require.NoError(t, rows.Scan(&command, &using, &check, &backgroundRole, &migrationOwner), relation)
		policy := livePolicy{command: command, backgroundRole: backgroundRole, migrationOwner: migrationOwner}
		for _, expression := range []string{using, check} {
			if expression != "" {
				policy.expressions = append(policy.expressions, expression)
			}
		}
		policies = append(policies, policy)
	}
	require.NoError(t, rows.Err(), relation)
	return policies
}
