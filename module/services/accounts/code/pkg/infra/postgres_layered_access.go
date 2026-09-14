package infra

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	gen "accounts/pkg/gen/saas/accounts/v1"

	"github.com/codefly-dev/core/wool"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// scopePathPattern mirrors the scope_nodes_label_charset CHECK: ltree labels are
// the lowercase set [a-z0-9_] joined by dots. Raw UUIDs (hyphens) are not valid
// labels and must be encoded (lowercase, '-' -> '_') before use as a path.
// Validating here turns an opaque 23514 CHECK violation into a clean
// InvalidArgument at the boundary.
var scopePathPattern = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)

func validateScopePath(path string) error {
	if !scopePathPattern.MatchString(path) {
		return status.Errorf(codes.InvalidArgument,
			"scope_path %q is not a valid ltree path of [a-z0-9_] labels", path)
	}
	return nil
}

// subjectKindColumn maps the proto enum to the stored subject_kind text, shared
// by every layered-access write path.
func subjectKindColumn(kind gen.SubjectKind) (string, error) {
	switch kind {
	case gen.SubjectKind_SUBJECT_KIND_PRINCIPAL:
		return "principal", nil
	case gen.SubjectKind_SUBJECT_KIND_TEAM:
		return "team", nil
	default:
		return "", status.Errorf(codes.InvalidArgument, "unsupported subject kind %s", kind)
	}
}

// layeredSubjectPredicate builds the subject-match SQL for a given table alias,
// identical in shape to CheckPermission: a human principal also inherits grants
// assigned to teams they belong to. The alias is interpolated via %[1]s so the
// same predicate can guard both the scope-grant and record-share branches.
func layeredSubjectPredicate(kind gen.SubjectKind, alias string) (string, error) {
	switch kind {
	case gen.SubjectKind_SUBJECT_KIND_PRINCIPAL:
		return fmt.Sprintf(`(
			(%[1]s.subject_kind = 'principal' AND %[1]s.subject_id = $1)
			OR (%[1]s.subject_kind = 'team' AND %[1]s.subject_id IN (
				SELECT team_id FROM team_members WHERE user_id = $1))
		)`, alias), nil
	case gen.SubjectKind_SUBJECT_KIND_TEAM:
		return fmt.Sprintf(`(%[1]s.subject_kind = 'team' AND %[1]s.subject_id = $1)`, alias), nil
	default:
		return "", status.Errorf(codes.InvalidArgument, "unsupported subject kind %s", kind)
	}
}

// CheckAccess reports whether subject may perform (resourceType, action) on a
// specific record, via either a hierarchical scope grant at any ancestor of the
// record's scope path, or a direct per-record share. It is the hierarchical +
// per-record companion to CheckPermission; org-wide/flat capability still comes
// from CheckPermission, which is untouched.
//
// SECURITY: the record's scope path is resolved HERE, from the record's own
// registered scope_nodes row (keyed by resource_type + resource_id under the RLS
// tenant floor) — never from a caller-supplied path. A caller entitled at one
// scope therefore cannot authorize a resource that actually lives under a
// different scope (RFC-0001 open-question 2).
//
// Runs inside WithOrgTx: app.current_org_id is set, so RLS confines every table
// below to the caller's tenant.
func (s *PostgresStore) CheckAccess(ctx context.Context, subjectID string, subjectKind gen.SubjectKind, resourceType, resourceID, action string) (bool, string, error) {
	w := wool.Get(ctx).In("CheckAccess")
	executor := s.getQueryExecutor(ctx)

	scopePred, err := layeredSubjectPredicate(subjectKind, "g")
	if err != nil {
		return false, "", err
	}
	sharePred, err := layeredSubjectPredicate(subjectKind, "sh")
	if err != nil {
		return false, "", err
	}

	// $1 subject, $2 resource_type, $3 resource_id, $4 action.
	// Scope branch: a grant whose scope_path is an ancestor-or-equal of the
	// record's resolved path (g.scope_path @> record.scope_path). If the record
	// has no registered node the CTE is empty and the CROSS JOIN yields no rows,
	// so the scope branch fails closed while the share branch can still grant.
	// A NULL-safe wildcard role_permissions ('*') matches, as in CheckPermission.
	query := `
		WITH record AS (
			SELECT scope_path FROM scope_nodes
			WHERE resource_type = $2 AND resource_id = $3
			LIMIT 1
		)
		SELECT 'scope' AS via
		FROM scope_grants g
		JOIN role_permissions rp ON rp.role_id = g.role_id
		CROSS JOIN record
		WHERE ` + scopePred + `
		  AND g.scope_path @> record.scope_path
		  AND (g.expires_at IS NULL OR g.expires_at > now())
		  AND (rp.resource = '*' OR rp.resource = $2)
		  AND (rp.action   = '*' OR rp.action   = $4)
		UNION ALL
		SELECT 'share' AS via
		FROM record_shares sh
		JOIN role_permissions rp ON rp.role_id = sh.role_id
		WHERE ` + sharePred + `
		  AND sh.resource_type = $2
		  AND sh.resource_id   = $3
		  AND (sh.expires_at IS NULL OR sh.expires_at > now())
		  AND (rp.resource = '*' OR rp.resource = $2)
		  AND (rp.action   = '*' OR rp.action   = $4)
		LIMIT 1`

	var via string
	err = executor.QueryRow(ctx, query, subjectID, resourceType, resourceID, action).Scan(&via)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "no scope grant or record share", nil
		}
		return false, "", w.Wrapf(err, "failed to check access")
	}
	return true, "granted via " + via, nil
}

func accessibleScopesQuery(subjectKind gen.SubjectKind, nodePredicate string) (string, error) {
	scopePred, err := layeredSubjectPredicate(subjectKind, "g")
	if err != nil {
		return "", err
	}
	sharePred, err := layeredSubjectPredicate(subjectKind, "sh")
	if err != nil {
		return "", err
	}

	// $1 subject, $2 resource_type, $3 action, $4 org; the caller binds
	// $5 to a node or cursor and, for listing, $6 to the limit. scope_path is UNIQUE per org, so it is a total keyset cursor.
	// UNION dedupes a node reachable through both a grant and a share. The share
	// branch's ancestor join is on the placed-record identity, so only nodes of the
	// queried resource_type appear there — structural nodes (NULL resource columns)
	// never match. The explicit org_id predicate is a second gate on top of the RLS
	// floor, not RLS alone: it pins the RETURNED node (n.org_id) as well as the
	// authorizing grant/share (g.org_id / sh.org_id), so an ltree ancestor match or
	// a colliding (resource_type, resource_id) across tenants can never surface
	// another org's node even if the RLS floor is ever bypassed.
	return `
		SELECT node_id, scope_path, kind, label FROM (
			SELECT n.id::text AS node_id, n.scope_path::text AS scope_path, n.kind AS kind, n.label AS label, n.scope_path AS path
			FROM scope_nodes n
			JOIN scope_grants g ON g.scope_path @> n.scope_path
			JOIN role_permissions rp ON rp.role_id = g.role_id
			WHERE ` + scopePred + `
			  AND n.org_id = $4
			  AND g.org_id = $4
			  AND (g.expires_at IS NULL OR g.expires_at > now())
			  AND (rp.resource = '*' OR rp.resource = $2)
			  AND (rp.action   = '*' OR rp.action   = $3)
			  AND ` + nodePredicate + `
			UNION
			SELECT n.id::text AS node_id, n.scope_path::text AS scope_path, n.kind AS kind, n.label AS label, n.scope_path AS path
			FROM scope_nodes n
			JOIN record_shares sh ON sh.resource_type = n.resource_type AND sh.resource_id = n.resource_id
			JOIN role_permissions rp ON rp.role_id = sh.role_id
			WHERE ` + sharePred + `
			  AND n.org_id = $4
			  AND sh.org_id = $4
			  AND sh.resource_type = $2
			  AND (sh.expires_at IS NULL OR sh.expires_at > now())
			  AND (rp.resource = '*' OR rp.resource = $2)
			  AND (rp.action   = '*' OR rp.action   = $3)
			  AND ` + nodePredicate + `
		) accessible`, nil
}

// CanReadScopeNode tests exact membership using the same grants and shares as scope listing.
func (s *PostgresStore) CanReadScopeNode(ctx context.Context, orgID, subjectID string, subjectKind gen.SubjectKind, resourceType, action, nodeID string) (bool, error) {
	// Compare against `n.id::text`, the exact projection ListAccessibleScopes
	// returns as node_id, so exact membership is tested against the same set the
	// listing enumerates and the two can never disagree on a node.
	//
	// It also settles the id's type: scope_nodes.id is UUID, and binding a
	// caller-supplied string straight to it aborts the transaction with "invalid
	// input syntax for type uuid" instead of answering. Comparing as text makes
	// an unparseable id simply match nothing — a denial, which is the honest
	// answer and keeps a malformed id indistinguishable from an unauthorized one.
	//
	// A UUID has several accepted spellings (uppercase, braced, urn, unhyphenated)
	// that all denote the same node, but only one text form. Canonicalize so a
	// caller naming a node it may read is not denied over punctuation; anything
	// that is not a UUID is passed through, which matches nothing on a UUID column.
	node := nodeID
	if parsed, err := uuid.Parse(nodeID); err == nil {
		node = parsed.String()
	}
	query, err := accessibleScopesQuery(subjectKind, "n.id::text = $5")
	if err != nil {
		return false, err
	}
	var allowed bool
	err = s.getQueryExecutor(ctx).QueryRow(ctx, "SELECT EXISTS ("+query+")", subjectID, resourceType, action, orgID, node).Scan(&allowed)
	return allowed, err
}

// ListAccessibleScopes enumerates the scope nodes subject may act on with
// (resourceType, action) — the list-objects companion to CheckAccess. A node is
// returned when EITHER a scope grant at an ancestor-or-equal path carries a role
// permitting (resourceType, action), OR the node is a placed record of that type
// with a per-record share permitting it. Both branches match roles through the
// same role_permissions rows and the same wildcard rule as CheckAccess, so the
// set returned here and CheckAccess's per-record verdict never disagree.
//
// Runs inside WithOrgTx: RLS confines every table to the caller's tenant. Results
// are ordered by scope_path and windowed with a keyset cursor (afterPath) plus a
// row limit, so a subject entitled at a broad ancestor (whose subtree can hold
// every placed record in the org) is paged rather than returned all at once.
func (s *PostgresStore) ListAccessibleScopes(ctx context.Context, orgID, subjectID string, subjectKind gen.SubjectKind, resourceType, action, afterPath string, limit int) ([]*gen.AccessibleScope, error) {
	w := wool.Get(ctx).In("ListAccessibleScopes")
	executor := s.getQueryExecutor(ctx)

	query, err := accessibleScopesQuery(subjectKind, "($5::ltree IS NULL OR n.scope_path > $5::ltree)")
	if err != nil {
		return nil, err
	}
	query += " ORDER BY path LIMIT $6"

	var cursor any
	if afterPath != "" {
		cursor = afterPath
	}
	rows, err := executor.Query(ctx, query, subjectID, resourceType, action, orgID, cursor, limit)
	if err != nil {
		return nil, w.Wrapf(err, "failed to list accessible scopes")
	}
	defer rows.Close()

	var out []*gen.AccessibleScope
	for rows.Next() {
		var node gen.AccessibleScope
		if err := rows.Scan(&node.NodeId, &node.ScopePath, &node.Kind, &node.Label); err != nil {
			return nil, w.Wrapf(err, "failed to scan accessible scope")
		}
		out = append(out, &node)
	}
	if err := rows.Err(); err != nil {
		return nil, w.Wrapf(err, "iterating accessible scope rows")
	}
	return out, nil
}

// GetOrCreateCollectionNode resolves a `collection` boundary by its label: if the
// tenant already has a collection node with that label it is reused, otherwise
// the supplied node is registered and its id returned. This keeps one boundary
// per collection name, so connecting several sources to the same collection (the
// only path the connect UI exposes) converges on one grantable node instead of
// minting a fresh, separately-granted node each time. A per-(org,label) advisory
// lock held to commit serializes concurrent first-time creates so a race cannot
// still split them. Runs inside WithOrgTx; RLS confines the lookup to the tenant.
func (s *PostgresStore) GetOrCreateCollectionNode(ctx context.Context, node *gen.ScopeNode) (string, error) {
	w := wool.Get(ctx).In("GetOrCreateCollectionNode")
	executor := s.getQueryExecutor(ctx)

	if err := validateScopePath(node.ScopePath); err != nil {
		return "", err
	}
	if _, err := executor.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, node.OrgId, node.Label,
	); err != nil {
		return "", w.Wrapf(err, "failed to lock collection label")
	}

	var existing string
	err := executor.QueryRow(ctx, `
		SELECT id::text FROM scope_nodes
		WHERE org_id = $1 AND kind = $2 AND label = $3
		ORDER BY created_at
		LIMIT 1`, node.OrgId, node.Kind, node.Label,
	).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", w.Wrapf(err, "failed to look up collection node")
	}
	if err := s.RegisterScopeNode(ctx, node); err != nil {
		return "", err
	}
	return node.Id, nil
}

// PlaceRecordNode registers node as the placement of its (ResourceType,
// ResourceId) record, or returns the node that record is already placed at.
//
// A record maps to exactly one node (idx_scope_nodes_resource), so a second
// placement of the same record would otherwise surface as a unique violation
// rather than as the accepted no-op the module surface's at-least-once contract
// needs. The advisory lock serializes the read-then-insert on the record key,
// as GetOrCreateCollectionNode does on the collection label, so two concurrent
// placements agree on one node instead of racing the index. Runs inside
// WithOrgTx, so RLS confines both the lookup and the insert to the tenant.
func (s *PostgresStore) PlaceRecordNode(ctx context.Context, node *gen.ScopeNode) (*gen.ScopeNode, error) {
	w := wool.Get(ctx).In("PlaceRecordNode")
	executor := s.getQueryExecutor(ctx)

	if node.ResourceType == "" || node.ResourceId == "" {
		return nil, status.Error(codes.InvalidArgument, "resource_type and resource_id must be set together")
	}
	if _, err := executor.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`,
		node.OrgId, node.ResourceType+"/"+node.ResourceId,
	); err != nil {
		return nil, w.Wrapf(err, "failed to lock record placement")
	}

	existing := &gen.ScopeNode{
		OrgId:        node.OrgId,
		ResourceType: node.ResourceType,
		ResourceId:   node.ResourceId,
	}
	var createdAt time.Time
	err := executor.QueryRow(ctx, `
		SELECT id::text, scope_path::text, kind, label, created_at FROM scope_nodes
		WHERE resource_type = $1 AND resource_id = $2`,
		node.ResourceType, node.ResourceId,
	).Scan(&existing.Id, &existing.ScopePath, &existing.Kind, &existing.Label, &createdAt)
	if err == nil {
		existing.CreatedAt = timestamppb.New(createdAt)
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, w.Wrapf(err, "failed to look up record placement")
	}
	if err := s.RegisterScopeNode(ctx, node); err != nil {
		return nil, err
	}
	return node, nil
}

// ScopeNodeExists reports whether nodeID is a scope node visible in the caller's
// tenant. Run under WithOrgTx so the RLS policy confines the probe to the org;
// this is the org-membership check the datasource boundary FK cannot make (RI
// bypasses RLS, so the FK alone would accept another org's node id).
func (s *PostgresStore) ScopeNodeExists(ctx context.Context, nodeID string) (bool, error) {
	var exists bool
	if err := s.getQueryExecutor(ctx).QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM scope_nodes WHERE id = $1)`, nodeID,
	).Scan(&exists); err != nil {
		return false, wool.Get(ctx).In("ScopeNodeExists").Wrapf(err, "failed to check scope node")
	}
	return exists, nil
}

// scopeParentPath returns the immediate parent of a dotted ltree path, or "" if
// the path is a root (a single label with no separator).
func scopeParentPath(path string) string {
	i := strings.LastIndex(path, ".")
	if i < 0 {
		return ""
	}
	return path[:i]
}

// requireVisibleRole rejects a role_id the caller's tenant cannot see. The
// roles FK bypasses RLS, so without this a tenant could bind a grant/share to
// another org's role_id; such a row is inert (that role's role_permissions are
// hidden, so it never authorizes) but it is meaningless junk. Under WithOrgTx
// the roles policy exposes only own-org and built-in/global (org_id IS NULL)
// roles, so a plain existence probe is the visibility test.
func requireVisibleRole(ctx context.Context, executor QueryExecutor, roleID string) error {
	var visible bool
	if err := executor.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1)`, roleID,
	).Scan(&visible); err != nil {
		return err
	}
	if !visible {
		return status.Errorf(codes.FailedPrecondition, "role %q is not a role in this org", roleID)
	}
	return nil
}

// RegisterScopeNode inserts a node into the org's scope tree, or places a
// product record at a node when ResourceType/ResourceId are set. node.Id and
// node.OrgId are set by the caller.
func (s *PostgresStore) RegisterScopeNode(ctx context.Context, node *gen.ScopeNode) error {
	w := wool.Get(ctx).In("RegisterScopeNode")
	executor := s.getQueryExecutor(ctx)

	if err := validateScopePath(node.ScopePath); err != nil {
		return err
	}

	// Enforce parent-exists so the registry stays a connected tree rather than a
	// bag of orphan paths (the typed-registry intent of gap 6). A root node — a
	// single label with no dot — has no parent to check.
	if parent := scopeParentPath(node.ScopePath); parent != "" {
		var parentExists bool
		if err := executor.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM scope_nodes WHERE scope_path = $1::ltree)`, parent,
		).Scan(&parentExists); err != nil {
			return w.Wrapf(err, "failed to check parent scope node")
		}
		if !parentExists {
			return status.Errorf(codes.FailedPrecondition, "parent scope %q is not registered", parent)
		}
	}

	var resourceType, resourceID any
	if node.ResourceType != "" || node.ResourceId != "" {
		if node.ResourceType == "" || node.ResourceId == "" {
			return status.Error(codes.InvalidArgument, "resource_type and resource_id must be set together")
		}
		resourceType = node.ResourceType
		resourceID = node.ResourceId
	}

	var createdAt time.Time
	err := executor.QueryRow(ctx, `
		INSERT INTO scope_nodes (id, org_id, scope_path, kind, label, resource_type, resource_id, created_at)
		VALUES ($1, $2, $3::ltree, $4, $5, $6, $7, NOW())
		RETURNING created_at`,
		node.Id, node.OrgId, node.ScopePath, node.Kind, node.Label, resourceType, resourceID,
	).Scan(&createdAt)
	if err != nil {
		return w.Wrapf(err, "failed to register scope node")
	}
	node.CreatedAt = timestamppb.New(createdAt)
	return nil
}

// GrantScope inserts a hierarchical scope grant. The scope path must already be
// a registered node in this org (gap 6: granting on an unregistered scope
// fails). grant.Id and grant.OrgId are set by the caller.
func (s *PostgresStore) GrantScope(ctx context.Context, grant *gen.ScopeGrant) error {
	w := wool.Get(ctx).In("GrantScope")
	executor := s.getQueryExecutor(ctx)

	if err := validateScopePath(grant.ScopePath); err != nil {
		return err
	}
	kind, err := subjectKindColumn(grant.SubjectKind)
	if err != nil {
		return err
	}
	if err := requireVisibleRole(ctx, executor, grant.RoleId); err != nil {
		return w.Wrapf(err, "failed to validate role")
	}

	var exists bool
	if err := executor.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM scope_nodes WHERE scope_path = $1::ltree)`,
		grant.ScopePath,
	).Scan(&exists); err != nil {
		return w.Wrapf(err, "failed to check scope node")
	}
	if !exists {
		return status.Errorf(codes.FailedPrecondition, "scope %q is not a registered node", grant.ScopePath)
	}

	var grantedBy, expiresAt any
	if grant.GrantedBy != "" {
		grantedBy = grant.GrantedBy
	}
	if grant.ExpiresAt != nil {
		expiresAt = grant.ExpiresAt.AsTime()
	}

	// Idempotent on the natural key: re-granting the same (subject, scope, role)
	// refreshes granted_by/expiry instead of raising a unique violation, matching
	// AssignRole's ON CONFLICT behavior. RETURNING id echoes the existing row's
	// id on conflict so the returned grant reflects what is actually stored.
	var createdAt time.Time
	err = executor.QueryRow(ctx, `
		INSERT INTO scope_grants (id, org_id, subject_id, subject_kind, scope_path, role_id, granted_by, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5::ltree, $6, $7, $8, NOW())
		ON CONFLICT (org_id, subject_id, subject_kind, scope_path, role_id)
		DO UPDATE SET granted_by = EXCLUDED.granted_by, expires_at = EXCLUDED.expires_at
		RETURNING id, created_at`,
		grant.Id, grant.OrgId, grant.SubjectId, kind, grant.ScopePath, grant.RoleId, grantedBy, expiresAt,
	).Scan(&grant.Id, &createdAt)
	if err != nil {
		return w.Wrapf(err, "failed to grant scope")
	}
	grant.CreatedAt = timestamppb.New(createdAt)
	return nil
}

// RevokeScope removes a hierarchical scope grant matching the exact tuple.
func (s *PostgresStore) RevokeScope(ctx context.Context, orgID, subjectID string, subjectKind gen.SubjectKind, scopePath, roleID string) error {
	w := wool.Get(ctx).In("RevokeScope")
	executor := s.getQueryExecutor(ctx)

	kind, err := subjectKindColumn(subjectKind)
	if err != nil {
		return err
	}
	_, err = executor.Exec(ctx, `
		DELETE FROM scope_grants
		WHERE org_id = $1 AND subject_id = $2 AND subject_kind = $3
		  AND scope_path = $4::ltree AND role_id = $5`,
		orgID, subjectID, kind, scopePath, roleID,
	)
	if err != nil {
		return w.Wrapf(err, "failed to revoke scope grant")
	}
	return nil
}

// ShareRecord inserts a per-record share. share.Id and share.OrgId are set by
// the caller.
func (s *PostgresStore) ShareRecord(ctx context.Context, share *gen.RecordShare) error {
	w := wool.Get(ctx).In("ShareRecord")
	executor := s.getQueryExecutor(ctx)

	kind, err := subjectKindColumn(share.SubjectKind)
	if err != nil {
		return err
	}
	if err := requireVisibleRole(ctx, executor, share.RoleId); err != nil {
		return w.Wrapf(err, "failed to validate role")
	}
	var grantedBy, expiresAt any
	if share.GrantedBy != "" {
		grantedBy = share.GrantedBy
	}
	if share.ExpiresAt != nil {
		expiresAt = share.ExpiresAt.AsTime()
	}

	// Idempotent on the natural key: re-sharing the same (record, subject, role)
	// refreshes granted_by/expiry instead of raising a unique violation. RETURNING
	// id echoes the existing row's id on conflict so the returned share reflects
	// what is actually stored.
	var createdAt time.Time
	err = executor.QueryRow(ctx, `
		INSERT INTO record_shares (id, org_id, resource_type, resource_id, subject_id, subject_kind, role_id, granted_by, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		ON CONFLICT (org_id, resource_type, resource_id, subject_id, subject_kind, role_id)
		DO UPDATE SET granted_by = EXCLUDED.granted_by, expires_at = EXCLUDED.expires_at
		RETURNING id, created_at`,
		share.Id, share.OrgId, share.ResourceType, share.ResourceId,
		share.SubjectId, kind, share.RoleId, grantedBy, expiresAt,
	).Scan(&share.Id, &createdAt)
	if err != nil {
		return w.Wrapf(err, "failed to share record")
	}
	share.CreatedAt = timestamppb.New(createdAt)
	return nil
}

// RevokeShare removes a per-record share matching the exact tuple.
func (s *PostgresStore) RevokeShare(ctx context.Context, orgID, resourceType, resourceID, subjectID string, subjectKind gen.SubjectKind, roleID string) error {
	w := wool.Get(ctx).In("RevokeShare")
	executor := s.getQueryExecutor(ctx)

	kind, err := subjectKindColumn(subjectKind)
	if err != nil {
		return err
	}
	_, err = executor.Exec(ctx, `
		DELETE FROM record_shares
		WHERE org_id = $1 AND resource_type = $2 AND resource_id = $3
		  AND subject_id = $4 AND subject_kind = $5 AND role_id = $6`,
		orgID, resourceType, resourceID, subjectID, kind, roleID,
	)
	if err != nil {
		return w.Wrapf(err, "failed to revoke record share")
	}
	return nil
}

// ListShares returns the shares on a specific record, newest first.
func (s *PostgresStore) ListShares(ctx context.Context, orgID, resourceType, resourceID string) ([]*gen.RecordShare, error) {
	w := wool.Get(ctx).In("ListShares")
	executor := s.getQueryExecutor(ctx)

	rows, err := executor.Query(ctx, `
		SELECT id, org_id, resource_type, resource_id, subject_id, subject_kind, role_id, granted_by, expires_at, created_at
		FROM record_shares
		WHERE org_id = $1 AND resource_type = $2 AND resource_id = $3
		ORDER BY created_at DESC`,
		orgID, resourceType, resourceID,
	)
	if err != nil {
		return nil, w.Wrapf(err, "failed to list record shares")
	}
	defer rows.Close()

	var out []*gen.RecordShare
	for rows.Next() {
		var (
			id, oid, rtype, rid, subjID, kind, roleID string
			grantedBy                                 *string
			expiresAt                                 *time.Time
			createdAt                                 time.Time
		)
		if err := rows.Scan(&id, &oid, &rtype, &rid, &subjID, &kind, &roleID, &grantedBy, &expiresAt, &createdAt); err != nil {
			return nil, w.Wrapf(err, "failed to scan record share")
		}
		share := &gen.RecordShare{
			Id:           id,
			OrgId:        oid,
			ResourceType: rtype,
			ResourceId:   rid,
			SubjectId:    subjID,
			RoleId:       roleID,
			CreatedAt:    timestamppb.New(createdAt),
		}
		switch kind {
		case "principal":
			share.SubjectKind = gen.SubjectKind_SUBJECT_KIND_PRINCIPAL
		case "team":
			share.SubjectKind = gen.SubjectKind_SUBJECT_KIND_TEAM
		default:
			return nil, fmt.Errorf("list record shares: unsupported stored subject kind %q", kind)
		}
		if grantedBy != nil {
			share.GrantedBy = *grantedBy
		}
		if expiresAt != nil {
			share.ExpiresAt = timestamppb.New(*expiresAt)
		}
		out = append(out, share)
	}
	if err := rows.Err(); err != nil {
		return nil, w.Wrapf(err, "iterating record share rows")
	}
	return out, nil
}

// ListCollectionAccess lists collection boundaries with the grants that confer
// read on their content. readResources names the permission resource types that
// content is governed by; it comes from the composition's declared module
// registry, because the host holds no domain content and so cannot name the
// resource itself. An empty set matches nothing, so an undeclared composition
// reports no read grants rather than inventing authority (fail-closed).
func (s *PostgresStore) ListCollectionAccess(ctx context.Context, orgID, afterPath string, limit int, readResources []string) ([]*gen.CollectionAccess, error) {
	// A nil slice would bind as NULL, and `= ANY(NULL)` is NULL rather than false.
	// Both refuse the grant, but only an empty array says so in the plan.
	if readResources == nil {
		readResources = []string{}
	}
	executor := s.getQueryExecutor(ctx)
	rows, err := executor.Query(ctx, `SELECT id, scope_path::text, label FROM scope_nodes
 WHERE org_id = $1 AND kind = 'collection' AND scope_path::text > $2
 ORDER BY scope_path::text LIMIT $3`, orgID, afterPath, limit)
	if err != nil {
		return nil, err
	}
	var collections []*gen.CollectionAccess
	for rows.Next() {
		node := &gen.ScopeNode{OrgId: orgID, Kind: "collection"}
		if err := rows.Scan(&node.Id, &node.ScopePath, &node.Label); err != nil {
			rows.Close()
			return nil, err
		}
		collections = append(collections, &gen.CollectionAccess{Node: node})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, collection := range collections {
		grants, err := executor.Query(ctx, `SELECT g.id, g.subject_id, g.subject_kind, g.scope_path::text, g.role_id,
   COALESCE(g.granted_by::text, ''), g.expires_at, g.created_at,
   COALESCE(t.name, p.display_name, g.subject_id::text), r.name,
   COALESCE(a.display_name, g.granted_by::text, 'Unknown actor')
   FROM scope_grants g JOIN roles r ON r.id = g.role_id
   LEFT JOIN principals p ON g.subject_kind = 'principal' AND p.id = g.subject_id
   LEFT JOIN teams t ON g.subject_kind = 'team' AND t.id = g.subject_id
   LEFT JOIN principals a ON a.id = g.granted_by
   WHERE g.org_id = $1 AND g.scope_path @> $2::ltree
   AND (g.expires_at IS NULL OR g.expires_at > NOW())
   AND EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id = g.role_id
    AND (rp.resource = ANY($3::text[]) OR rp.resource = '*') AND rp.action IN ('read', '*'))
   ORDER BY g.created_at, g.id`, orgID, collection.Node.ScopePath, readResources)
		if err != nil {
			return nil, err
		}
		for grants.Next() {
			view := &gen.CollectionReadGrant{Grant: &gen.ScopeGrant{OrgId: orgID}}
			g := view.Grant
			var kind string
			var expires *time.Time
			var created time.Time
			if err := grants.Scan(&g.Id, &g.SubjectId, &kind, &g.ScopePath, &g.RoleId, &g.GrantedBy,
				&expires, &created, &view.SubjectLabel, &view.RoleName, &view.ActorLabel); err != nil {
				grants.Close()
				return nil, err
			}
			g.SubjectKind = gen.SubjectKind_SUBJECT_KIND_PRINCIPAL
			if kind == "team" {
				g.SubjectKind = gen.SubjectKind_SUBJECT_KIND_TEAM
			}
			g.CreatedAt = timestamppb.New(created)
			if expires != nil {
				g.ExpiresAt = timestamppb.New(*expires)
			}
			collection.ReadGrants = append(collection.ReadGrants, view)
		}
		err = grants.Err()
		grants.Close()
		if err != nil {
			return nil, err
		}
	}
	return collections, nil
}
