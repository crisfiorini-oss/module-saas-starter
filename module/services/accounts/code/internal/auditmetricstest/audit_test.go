package auditmetricstest

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"accounts/pkg/business"
	gen "accounts/pkg/gen/saas/accounts/v1"
	"accounts/pkg/infra"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type readerStore struct {
	business.Store
	allowed bool
	called  bool
	org     string
	query   business.AuditQuery
}

func (s *readerStore) WithOrgTx(ctx context.Context, org string, fn func(context.Context) error) error {
	s.org = org
	return fn(ctx)
}
func (s *readerStore) CheckAccess(_ context.Context, reader string, kind gen.SubjectKind, resource, id, action string) (bool, string, error) {
	return s.allowed && reader == "reader" && kind == gen.SubjectKind_SUBJECT_KIND_PRINCIPAL && s.org == "org-a" && resource == "collection" && id == "source-a" && action == "read", "", nil
}
func (s *readerStore) AggregateAuditLog(_ context.Context, q business.AuditQuery, _ business.AuditAggregationSpec) ([]business.AuditAggregateBucket, error) {
	s.called = true
	s.query = q
	return nil, nil
}
func TestResourceReadRechecked(t *testing.T) {
	store := &readerStore{allowed: true}
	svc, err := business.NewService(store)
	require.NoError(t, err)
	q := business.AuditQuery{OrgID: "org-a", Resource: "collection", ResourceID: "source-a", EventType: "saas.document.ingested", PayloadContains: map[string]any{"run_id": "run-a"}}
	_, err = svc.AggregateAuditLogForReader(context.Background(), "reader", q, business.AuditAggregationSpec{})
	require.NoError(t, err)
	require.Equal(t, q, store.query)
	for _, variant := range []string{"revoked", "other-org", "other-resource", "other-reader"} {
		t.Run(variant, func(t *testing.T) {
			store.allowed = true
			store.called = false
			other := q
			reader := "reader"
			switch variant {
			case "revoked":
				store.allowed = false
			case "other-org":
				other.OrgID = "org-b"
			case "other-resource":
				other.ResourceID = "source-b"
			case "other-reader":
				reader = "other"
			}
			_, err = svc.AggregateAuditLogForReader(context.Background(), reader, other, business.AuditAggregationSpec{})
			require.Equal(t, codes.PermissionDenied, status.Code(err))
			require.False(t, store.called)
		})
	}
	q.OrgID = ""
	_, err = svc.AggregateAuditLogForReader(context.Background(), "reader", q, business.AuditAggregationSpec{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// The DSN must point to an independent disposable database. No service harness,
// shared ports, credentials or installed application schema are used.
func TestPostgresIsolationDedupeAndUnknownTelemetry(t *testing.T) {
	dsn := os.Getenv("AUDIT_METRICS_TEST_DSN")
	if dsn == "" {
		if os.Getenv("AUDIT_METRICS_REQUIRE_DB") == "1" {
			t.Fatal("database gate requires AUDIT_METRICS_TEST_DSN")
		}
		t.Skip("set AUDIT_METRICS_TEST_DSN to a disposable PostgreSQL database")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close(ctx)) }()
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, tx.Rollback(ctx)) }()
	_, err = tx.Exec(ctx, `CREATE TEMP TABLE audit_events (org_id text, resource text, resource_id text, event_type text, actor_id text, created_at timestamptz, payload jsonb);
 INSERT INTO audit_events VALUES
 ('org-a','collection','source-a','saas.document.ingested','reader','2026-01-02','{"run_id":"run-a","logical_job_id":"job-a","documents":2}'),
 ('org-a','collection','source-a','saas.document.ingested','reader','2026-01-02','{"run_id":"run-a","logical_job_id":"job-a"}'),
 ('org-b','collection','source-a','saas.document.ingested','reader','2026-01-02','{"run_id":"run-a","logical_job_id":"job-b","documents":90}'),
 ('org-a','collection','source-b','saas.document.ingested','reader','2026-01-02','{"run_id":"run-a","logical_job_id":"job-c","documents":90}'),
 ('org-a','collection','source-a','saas.document.ingested','reader','2025-01-02','{"run_id":"run-a","logical_job_id":"job-d","documents":90}'),
 ('org-a','collection','source-a','saas.datasource.sync.completed','reader','2026-01-02','{"run_id":"run-a","logical_job_id":"job-e","documents":90}'),
 ('org-a','collection','source-a','saas.document.ingested','reader','2026-01-02','{"run_id":"run-b","logical_job_id":"job-f","documents":90}');`)
	require.NoError(t, err)
	// Production store explicitly reuses this transaction.
	ctx = context.WithValue(ctx, "tx", tx) //nolint:staticcheck // production transaction key
	store := &infra.PostgresStore{}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(48 * time.Hour)
	q := business.AuditQuery{OrgID: "org-a", Resource: "collection", ResourceID: "source-a", EventType: "saas.document.ingested", PayloadContains: map[string]any{"run_id": "run-a"}, From: &from, To: &to}
	spec := business.AuditAggregationSpec{Metrics: []business.AuditMetric{{Op: "count_distinct", Field: "payload:logical_job_id", Alias: "jobs"}, {Op: "sum", Field: "payload:documents", Alias: "documents"}, {Op: "sum", Field: "payload:usage", Alias: "usage"}, {Op: "sum", Field: "payload:zero", Alias: "zero"}}, Derived: []business.AuditDerivedMetric{{Alias: "rate", Numerator: "documents", Denominator: "usage"}}}
	rows, err := store.AggregateAuditLog(ctx, q, spec)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	b := rows[0]
	require.EqualValues(t, 2, b.Count)
	require.Equal(t, 1.0, b.Metrics["jobs"])
	require.Equal(t, 2.0, b.Metrics["documents"])
	require.EqualValues(t, 1, b.Samples["documents"])
	require.EqualValues(t, 2, b.Samples["jobs"])
	require.NotContains(t, b.Metrics, "usage")
	require.NotContains(t, b.Metrics, "rate")
	_, err = tx.Exec(ctx, `UPDATE audit_events SET payload = payload || '{"zero":0}'::jsonb`)
	require.NoError(t, err)
	spec.Derived[0].Denominator = "zero"
	rows, err = store.AggregateAuditLog(ctx, q, spec)
	require.NoError(t, err)
	require.Equal(t, 0.0, rows[0].Metrics["zero"])
	require.NotContains(t, rows[0].Metrics, "rate")
	q.PayloadContains = map[string]any{"run_id": "missing' OR true --"}
	rows, err = store.AggregateAuditLog(ctx, q, spec)
	require.NoError(t, err)
	require.Empty(t, rows)
}

type datasourceStore struct {
	readerStore
	boundary string
}

func (s *datasourceStore) GetDatasourceSource(_ context.Context, org, id string) (*business.DatasourceSource, error) {
	if org != "org-a" || id != "source-a" {
		return nil, nil
	}
	return &business.DatasourceSource{ID: id, OrgID: org, BoundaryNodeID: "boundary-a"}, nil
}
func (s *datasourceStore) CanReadScopeNode(_ context.Context, org, reader string, kind gen.SubjectKind, resource, action, nodeID string) (bool, error) {
	return reader == "reader" && resource == "documents" && action == "read" && org == "org-a" && kind == gen.SubjectKind_SUBJECT_KIND_PRINCIPAL && nodeID == s.boundary, nil
}

func TestConnectedSourceUsesCurrentCollectionGrant(t *testing.T) {
	store := &datasourceStore{boundary: "boundary-a"}
	svc, err := business.NewService(store)
	require.NoError(t, err)
	q := business.AuditQuery{OrgID: "org-a", Resource: "datasource", ResourceID: "source-a", EventType: "saas.datasource.sync.completed"}
	_, err = svc.AggregateAuditLogForReader(context.Background(), "reader", q, business.AuditAggregationSpec{})
	require.NoError(t, err)
	require.True(t, store.called)
	for _, boundary := range []string{"", "boundary-b"} {
		store.boundary = boundary
		store.called = false
		_, err = svc.AggregateAuditLogForReader(context.Background(), "reader", q, business.AuditAggregationSpec{})
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.False(t, store.called)
	}
}

func TestDocumentCollectionFilterAndRevocation(t *testing.T) {
	store := &datasourceStore{boundary: "boundary-a"}
	svc, err := business.NewService(store)
	require.NoError(t, err)
	q := business.AuditQuery{OrgID: "org-a", CollectionID: "boundary-a", EventType: "saas.document.ingested", PayloadContains: map[string]any{"version": "v1"}}
	_, err = svc.AggregateAuditLogForReader(context.Background(), "reader", q, business.AuditAggregationSpec{})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"version": "v1", "boundary": "boundary-a"}, store.query.PayloadContains)
	require.NotContains(t, q.PayloadContains, "boundary")
	require.Empty(t, store.query.CollectionID)
	store.boundary = "boundary-b"
	store.called = false
	_, err = svc.AggregateAuditLogForReader(context.Background(), "reader", q, business.AuditAggregationSpec{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.False(t, store.called)
	store.boundary = "boundary-a"
	q.PayloadContains["boundary"] = "boundary-b"
	_, err = svc.AggregateAuditLogForReader(context.Background(), "reader", q, business.AuditAggregationSpec{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	q.PayloadContains = nil
	q.EventType = "saas.datasource.sync.completed"
	_, err = svc.AggregateAuditLogForReader(context.Background(), "reader", q, business.AuditAggregationSpec{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// A collection named through payload_contains is the same read as one named
// through collection_id — accounts compiles the first into the second — so it
// must take the same grant check. Before this was promoted, a reader denied on
// collection_id got identical rows by moving the filter into payload_contains,
// which made the check on the adjacent field worth nothing.
func TestPayloadBoundarySpellingTakesTheCollectionGrant(t *testing.T) {
	store := &datasourceStore{boundary: "boundary-a"}
	svc, err := business.NewService(store)
	require.NoError(t, err)

	// Reader holds no grant on boundary-b, and names it only in the payload.
	denied := business.AuditQuery{
		OrgID:           "org-a",
		EventType:       "saas.document.ingested",
		PayloadContains: map[string]any{"boundary": "boundary-b"},
	}
	_, err = svc.AggregateAuditLogForReader(context.Background(), "reader", denied, business.AuditAggregationSpec{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.False(t, store.called, "a denied collection read must not reach the store")

	// The same spelling still works where the grant does hold.
	store.called = false
	allowed := business.AuditQuery{
		OrgID:           "org-a",
		EventType:       "saas.document.ingested",
		PayloadContains: map[string]any{"boundary": "boundary-a"},
	}
	_, err = svc.AggregateAuditLogForReader(context.Background(), "reader", allowed, business.AuditAggregationSpec{})
	require.NoError(t, err)
	require.True(t, store.called)
	require.Equal(t, map[string]any{"boundary": "boundary-a"}, store.query.PayloadContains)
	require.Empty(t, store.query.CollectionID, "the filter is compiled, never handed to the store uncompiled")

	// A boundary key on an event that carries no registered boundary field is
	// not a collection reference, so the organization-wide contract is unchanged
	// and no collection check is imposed on it.
	store.called = false
	unrelated := business.AuditQuery{
		OrgID:           "org-a",
		EventType:       "saas.datasource.sync.completed",
		PayloadContains: map[string]any{"boundary": "boundary-b"},
	}
	_, err = svc.AggregateAuditLogForReader(context.Background(), "reader", unrelated, business.AuditAggregationSpec{})
	require.NoError(t, err)
	require.True(t, store.called)
}

// Bind production store methods to the independently owned fixture transaction.
type transactionStore struct {
	*infra.PostgresStore
	tx pgx.Tx
}

func (s *transactionStore) WithOrgTx(ctx context.Context, org string, fn func(context.Context) error) error {
	_, err := s.tx.Exec(ctx, "SELECT set_config('app.current_org_id', $1, true)", org)
	if err != nil {
		return err
	}
	return fn(context.WithValue(ctx, "tx", s.tx)) //nolint:staticcheck // production transaction key
}
func TestPostgresExistingAndNewSourceBindingRevocation(t *testing.T) {
	dsn := os.Getenv("AUDIT_METRICS_TEST_DSN")
	if dsn == "" {
		if os.Getenv("AUDIT_METRICS_REQUIRE_DB") == "1" {
			t.Fatal("database gate requires AUDIT_METRICS_TEST_DSN")
		}
		t.Skip("set AUDIT_METRICS_TEST_DSN to a disposable PostgreSQL database")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close(ctx)) }()
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, tx.Rollback(ctx)) }()
	_, err = tx.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS ltree;
 CREATE TEMP TABLE scope_nodes(id text,org_id text,scope_path ltree,kind text,label text,resource_type text,resource_id text);
 CREATE TEMP TABLE scope_grants(org_id text,subject_kind text,subject_id text,role_id text,scope_path ltree,expires_at timestamptz);
 CREATE TEMP TABLE role_permissions(role_id text,resource text,action text);
 CREATE TEMP TABLE record_shares(org_id text,subject_kind text,subject_id text,role_id text,resource_type text,resource_id text,expires_at timestamptz);
 CREATE TEMP TABLE team_members(team_id text,user_id text);
 CREATE TEMP TABLE datasource_sources(id text,org_id text,provider text DEFAULT 'github',repo text,paths text[] DEFAULT '{}',branch text,boundary_node_id text,credential_secret_ref text DEFAULT '',webhook_secret_ref text,status text DEFAULT 'connected',status_reason text,last_synced_at timestamptz,created_at timestamptz DEFAULT now(),updated_at timestamptz DEFAULT now(),config jsonb,last_ingested_commit text,last_ingested_at timestamptz,last_delivery_id text,reconcile_interval interval DEFAULT '30 minutes',next_reconcile_at timestamptz,github_installation_id text);
 CREATE TEMP TABLE audit_events(org_id text,resource text,resource_id text,event_type text,actor_id text,created_at timestamptz,payload jsonb);
 INSERT INTO scope_nodes VALUES ('boundary-a','org-a','a','collection','Example collection',NULL,NULL),('boundary-b','org-a','b','collection','Other collection',NULL,NULL),('boundary-other-org','org-b','a','collection','Other org',NULL,NULL);
 INSERT INTO role_permissions VALUES ('reader-role','documents','read');
 INSERT INTO scope_grants VALUES ('org-a','principal','reader','reader-role','a',NULL);
 INSERT INTO datasource_sources(id,org_id,boundary_node_id) VALUES ('existing','org-a','boundary-a');
 INSERT INTO audit_events VALUES ('org-a','datasource','existing','saas.datasource.sync.completed','reader',now(),'{"job_id":"job-a"}');`)
	require.NoError(t, err)
	svc, err := business.NewService(&transactionStore{PostgresStore: &infra.PostgresStore{}, tx: tx})
	require.NoError(t, err)

	// Exact membership and scope listing must agree for every authorization path.
	queryCtx := context.WithValue(ctx, "tx", tx) //nolint:staticcheck // production transaction key
	raw := &infra.PostgresStore{}
	parity := func(expected []string) {
		t.Helper()
		nodes, err := raw.ListAccessibleScopes(queryCtx, "org-a", "reader", gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "documents", "read", "", 1000)
		require.NoError(t, err)
		ids := []string{}
		for _, node := range nodes {
			ids = append(ids, node.NodeId)
		}
		require.ElementsMatch(t, expected, ids)
		for _, id := range []string{"boundary-a", "boundary-b", "boundary-other-org", "placed", "missing"} {
			allowed, err := raw.CanReadScopeNode(queryCtx, "org-a", "reader", gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "documents", "read", id)
			require.NoError(t, err)
			want := false
			for _, match := range expected {
				want = want || match == id
			}
			require.Equal(t, want, allowed, id)
		}
	}
	parity([]string{"boundary-a"})
	_, err = tx.Exec(ctx, `UPDATE scope_grants SET expires_at=now()-interval '1 second'`)
	require.NoError(t, err)
	parity(nil)
	_, err = tx.Exec(ctx, `UPDATE scope_grants SET expires_at=NULL, subject_kind='team', subject_id='team-a'; INSERT INTO team_members VALUES ('team-a','reader')`)
	require.NoError(t, err)
	parity([]string{"boundary-a"})
	_, err = tx.Exec(ctx, `DELETE FROM team_members; INSERT INTO scope_nodes VALUES ('placed','org-a','c','record','Example document','documents','record-a'); INSERT INTO record_shares VALUES ('org-a','principal','reader','reader-role','documents','record-a',NULL)`)
	require.NoError(t, err)
	parity([]string{"placed"})
	_, err = tx.Exec(ctx, `UPDATE record_shares SET expires_at=now()-interval '1 second'`)
	require.NoError(t, err)
	parity(nil)
	_, err = tx.Exec(ctx, `UPDATE record_shares SET expires_at=NULL, org_id='org-b'`)
	require.NoError(t, err)
	parity(nil)
	_, err = tx.Exec(ctx, `DELETE FROM record_shares; UPDATE scope_grants SET subject_kind='principal',subject_id='reader'; UPDATE role_permissions SET resource='*',action='*'`)
	require.NoError(t, err)
	parity([]string{"boundary-a"})
	q := business.AuditQuery{OrgID: "org-a", Resource: "datasource", ResourceID: "existing", EventType: "saas.datasource.sync.completed"}
	check := func(want codes.Code) {
		t.Helper()
		_, err = svc.AggregateAuditLogForReader(ctx, "reader", q, business.AuditAggregationSpec{})
		require.Equal(t, want, status.Code(err))
	}
	check(codes.OK)
	_, err = tx.Exec(ctx, `INSERT INTO datasource_sources(id,org_id,boundary_node_id) VALUES ('new','org-a','boundary-a')`)
	require.NoError(t, err)
	q.ResourceID = "new"
	check(codes.OK)
	_, err = tx.Exec(ctx, `UPDATE datasource_sources SET boundary_node_id='boundary-b' WHERE id='existing'`)
	require.NoError(t, err)
	q.ResourceID = "existing"
	check(codes.PermissionDenied)
	q.ResourceID = "new"
	check(codes.OK)
	_, err = tx.Exec(ctx, `DELETE FROM scope_grants`)
	require.NoError(t, err)
	check(codes.PermissionDenied)
	_, err = tx.Exec(ctx, `INSERT INTO scope_grants VALUES ('org-b','principal','reader','reader-role','a',NULL)`)
	require.NoError(t, err)
	check(codes.PermissionDenied)
}

func TestReadEventPayloadContract(t *testing.T) {
	for _, event := range []business.EventType{business.EventDocumentRead, business.EventDocumentSearch} {
		payload := map[string]any{"solution": "documents", "boundary": "boundary-a", "correlation_id": "request-a", "outcome": "returned", "result_count": float64(2), "duration_ms": float64(10)}
		require.NoError(t, business.ValidatePayload(event, payload))
		payload["query"] = "must not be accepted"
		require.Error(t, business.ValidatePayload(event, payload))
		delete(payload, "query")
		payload["outcome"] = "answered"
		require.Error(t, business.ValidatePayload(event, payload))
	}
}

func TestUncompiledCollectionFilterRejected(t *testing.T) {
	ctx := context.Background()
	q := business.AuditQuery{CollectionID: "boundary-a"}
	store := &readerStore{}
	svc, err := business.NewService(store)
	require.NoError(t, err)
	_, err = svc.AggregateAuditLog(ctx, q, business.AuditAggregationSpec{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.False(t, store.called)
	_, _, _, err = svc.QueryAuditLog(ctx, q)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	raw := &infra.PostgresStore{}
	_, err = raw.AggregateAuditLog(ctx, q, business.AuditAggregationSpec{})
	require.ErrorContains(t, err, "uncompiled collection")
	_, _, _, err = raw.QueryAuditLog(ctx, q)
	require.ErrorContains(t, err, "uncompiled collection")
}

func TestReadEventRequiresCountableIdentity(t *testing.T) {
	for _, event := range []business.EventType{business.EventDocumentRead, business.EventDocumentSearch} {
		for _, field := range []string{"boundary", "correlation_id", "outcome"} {
			for _, value := range []any{nil, "", "  ", 12} {
				payload := map[string]any{"boundary": "boundary-a", "correlation_id": "request-a", "outcome": "empty"}
				require.NoError(t, business.ValidatePayload(event, payload)) // Measurements may be absent.
				if value == nil {
					delete(payload, field)
				} else {
					payload[field] = value
				}
				require.Error(t, business.ValidatePayload(event, payload), "%s %s=%v", event, field, value)
			}
		}
	}
}

// Read the shipped policies verbatim; a non-owner role must enforce them even
// when the application query omits its explicit organization predicate.
// scope_nodes.id is UUID. The point check compares against n.id::text — the
// same projection ListAccessibleScopes returns as node_id — so an id that is not
// a UUID matches nothing instead of aborting the transaction with "invalid input
// syntax for type uuid", and the two paths cannot disagree about a node.
//
// A UUID has several accepted spellings but only one text form, so the id is
// canonicalized first: a caller naming a node it may read is not denied over
// punctuation or case.
func TestCanReadScopeNodeMatchesIDSpellingsAndRefusesGarbage(t *testing.T) {
	dsn := os.Getenv("AUDIT_METRICS_TEST_DSN")
	if dsn == "" {
		if os.Getenv("AUDIT_METRICS_REQUIRE_DB") == "1" {
			t.Fatal("database gate requires AUDIT_METRICS_TEST_DSN")
		}
		t.Skip("set AUDIT_METRICS_TEST_DSN to a disposable PostgreSQL database")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close(ctx)) }()
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, tx.Rollback(ctx)) }()

	// id is UUID here, as it is in production (migration 98), so the cast this
	// query avoids is the one that would actually fail.
	_, err = tx.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS ltree;
 CREATE TEMP TABLE scope_nodes(id uuid,org_id text,scope_path ltree,kind text,label text,resource_type text,resource_id text);
 CREATE TEMP TABLE scope_grants(org_id text,subject_kind text,subject_id text,role_id text,scope_path ltree,expires_at timestamptz);
 CREATE TEMP TABLE role_permissions(role_id text,resource text,action text);
 CREATE TEMP TABLE record_shares(org_id text,subject_kind text,subject_id text,role_id text,resource_type text,resource_id text,expires_at timestamptz);
 CREATE TEMP TABLE team_members(team_id text,user_id text);
 INSERT INTO scope_nodes VALUES ('a1b2c3d4-1111-4111-8111-abcdefabcdef','org-a','a','collection','Example collection',NULL,NULL);
 INSERT INTO role_permissions VALUES ('reader-role','documents','read');
 INSERT INTO scope_grants VALUES ('org-a','principal','reader','reader-role','a',NULL);`)
	require.NoError(t, err)

	raw := &infra.PostgresStore{}
	queryCtx := context.WithValue(ctx, "tx", tx) //nolint:staticcheck // production transaction key
	check := func(nodeID string) (bool, error) {
		return raw.CanReadScopeNode(queryCtx, "org-a", "reader",
			gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "documents", "read", nodeID)
	}

	// Every accepted spelling of the same UUID denotes the same node. The id
	// carries hex letters so the uppercase case is a real one.
	for _, spelling := range []string{
		"a1b2c3d4-1111-4111-8111-abcdefabcdef",
		"A1B2C3D4-1111-4111-8111-ABCDEFABCDEF",
		"{a1b2c3d4-1111-4111-8111-abcdefabcdef}",
		"urn:uuid:a1b2c3d4-1111-4111-8111-abcdefabcdef",
		"a1b2c3d4111141118111abcdefabcdef",
	} {
		allowed, err := check(spelling)
		require.NoErrorf(t, err, "spelling %q", spelling)
		require.Truef(t, allowed, "spelling %q names a readable node", spelling)
	}

	// Not a UUID at all: a denial, never an error, and never a transaction abort.
	for _, garbage := range []string{"collection-node-id", "", "not a uuid", "'; DROP TABLE scope_nodes--"} {
		allowed, err := check(garbage)
		require.NoErrorf(t, err, "garbage %q must deny, not error", garbage)
		require.Falsef(t, allowed, "garbage %q must not be readable", garbage)
	}

	// A real UUID that names no node stays a denial.
	allowed, err := check("22222222-2222-4222-8222-222222222222")
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestPostgresAuditPolicyAsNonOwner(t *testing.T) {
	dsn := os.Getenv("AUDIT_METRICS_TEST_DSN")
	if dsn == "" {
		if os.Getenv("AUDIT_METRICS_REQUIRE_DB") == "1" {
			t.Fatal("database gate requires AUDIT_METRICS_TEST_DSN")
		}
		t.Skip("set AUDIT_METRICS_TEST_DSN to a disposable PostgreSQL database")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close(ctx)) }()
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, tx.Rollback(ctx)) }()
	name := fmt.Sprintf("audit_test_%d", time.Now().UnixNano())
	ident := pgx.Identifier{name}.Sanitize()
	_, err = tx.Exec(ctx, "CREATE ROLE "+ident+" NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE SCHEMA "+ident+"; SET LOCAL search_path TO "+ident+"; CREATE TABLE audit_events(org_id text, actor_id text, event_type text, payload jsonb); INSERT INTO audit_events VALUES ('org-a','reader','saas.document.read','{}'),('org-b','reader','saas.document.read','{}'),(NULL,'reader','saas.document.read','{}')")
	require.NoError(t, err)
	for _, migration := range []string{"31_rls_audit_events.up.sql", "122_audit_events_user_scoped_insert.up.sql"} {
		sql, err := os.ReadFile("../../../../store/migrations/" + migration)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, string(sql))
		require.NoError(t, err)
	}
	_, err = tx.Exec(ctx, "GRANT USAGE ON SCHEMA "+ident+" TO "+ident+"; GRANT SELECT ON audit_events TO "+ident+"; SET LOCAL ROLE "+ident)
	require.NoError(t, err)
	ctx = context.WithValue(ctx, "tx", tx) //nolint:staticcheck // production transaction key
	store := &infra.PostgresStore{}
	for _, org := range []string{"org-a", "org-b", ""} {
		_, err = tx.Exec(ctx, "SELECT set_config('app.current_org_id', $1, true)", org)
		require.NoError(t, err)
		rows, err := store.AggregateAuditLog(ctx, business.AuditQuery{}, business.AuditAggregationSpec{})
		require.NoError(t, err)
		if org == "" {
			require.Empty(t, rows)
		} else {
			require.Len(t, rows, 1)
			require.EqualValues(t, 1, rows[0].Count)
		}
		rows, err = store.AggregateAuditLog(ctx, business.AuditQuery{OrgID: "org-other"}, business.AuditAggregationSpec{})
		require.NoError(t, err)
		require.Empty(t, rows)
	}
}
