//go:build !pure

package infra_test

import (
	"context"
	"testing"
	"time"

	"accounts/pkg/business"
	gen "accounts/pkg/gen/saas/accounts/v1"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// layeredFixture seeds an org with an owner principal and a role that permits
// (resource, action). It returns the org id, the owner principal id, and the
// role id, ready for scope grants / record shares.
func layeredFixture(t *testing.T, resource, action string) (orgID, principalID, roleID string) {
	t.Helper()
	principalID = seedUser(t)
	orgID = seedOrg(t, principalID)
	require.NoError(t, testStore.As(business.Identity{OrgID: orgID}).AddOrgMember(testCtx, principalID, "owner"))

	roleID = business.NewIDString()
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.CreateRole(ctx, &gen.Role{
			Id:          roleID,
			Name:        "layered " + roleID,
			Description: "grants " + resource + ":" + action,
			OrgId:       orgID,
			Permissions: []*gen.Permission{{Resource: resource, Action: action}},
		})
	}))
	return orgID, principalID, roleID
}

func registerNode(t *testing.T, orgID, path, kind, resourceType, resourceID string) {
	t.Helper()
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.RegisterScopeNode(ctx, &gen.ScopeNode{
			Id:           business.NewIDString(),
			OrgId:        orgID,
			ScopePath:    path,
			Kind:         kind,
			Label:        path,
			ResourceType: resourceType,
			ResourceId:   resourceID,
		})
	}))
}

func checkAccess(t *testing.T, orgID, subjectID string, kind gen.SubjectKind, resourceType, resourceID, action string) bool {
	t.Helper()
	var allowed bool
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		var err error
		allowed, _, err = testStore.CheckAccess(ctx, subjectID, kind, resourceType, resourceID, action)
		return err
	}))
	return allowed
}

// A grant at an ancestor scope node inherits to a record placed anywhere in the
// subtree (@> ancestor match), while a record under a sibling subtree the caller
// is NOT granted stays denied.
func TestCheckAccess_AncestorGrantInheritsToDescendant(t *testing.T) {
	orgID, principalID, roleID := layeredFixture(t, "doc", "read")

	registerNode(t, orgID, "foundation", "foundation", "", "")
	registerNode(t, orgID, "foundation.solution_a", "solution", "", "")
	registerNode(t, orgID, "foundation.solution_b", "solution", "", "")
	// Records placed as leaves under each solution.
	registerNode(t, orgID, "foundation.solution_a.doc_1", "record", "doc", "doc-a-1")
	registerNode(t, orgID, "foundation.solution_b.doc_2", "record", "doc", "doc-b-2")

	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.GrantScope(ctx, &gen.ScopeGrant{
			Id:          business.NewIDString(),
			OrgId:       orgID,
			SubjectId:   principalID,
			SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL,
			ScopePath:   "foundation.solution_a",
			RoleId:      roleID,
		})
	}))

	require.True(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "doc-a-1", "read"),
		"a grant at solution_a must inherit to a record in its subtree")
	require.False(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "doc-b-2", "read"),
		"the same grant must NOT reach a record under solution_b")
	require.False(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "doc-a-1", "write"),
		"the role does not permit the write action")
}

// SECURITY (RFC-0001 open-question 2): the record's scope is resolved from its
// own registered node, never from a caller-supplied path. A caller entitled at
// solution_a cannot authorize a resource_id that actually lives under
// solution_b — even though the resource_id string is fully caller-controlled.
func TestCheckAccess_ResolvesRecordScopeFromResourceIDNotCaller(t *testing.T) {
	orgID, principalID, roleID := layeredFixture(t, "doc", "read")

	registerNode(t, orgID, "root", "root", "", "")
	registerNode(t, orgID, "root.solution_a", "solution", "", "")
	registerNode(t, orgID, "root.solution_b", "solution", "", "")
	// The record TRULY lives under solution_b.
	registerNode(t, orgID, "root.solution_b.secret", "record", "doc", "cross-scope-doc")

	// The caller is entitled at solution_a only.
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.GrantScope(ctx, &gen.ScopeGrant{
			Id:          business.NewIDString(),
			OrgId:       orgID,
			SubjectId:   principalID,
			SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL,
			ScopePath:   "root.solution_a",
			RoleId:      roleID,
		})
	}))

	require.False(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "cross-scope-doc", "read"),
		"entitlement at solution_a must not authorize a record whose true scope is solution_b")

	// A record with no registered node has no scope at all → scope branch denies.
	require.False(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "unplaced-doc", "read"),
		"an unplaced record has no resolvable scope and must fail closed on the scope branch")
}

// PlaceRecordNode is the store half of the module-facing placement path. A
// record maps to exactly one node, so placing the same record again returns the
// node it already has instead of colliding with idx_scope_nodes_resource — and
// that node is what CheckAccess then resolves the record's scope from.
func TestPlaceRecordNode_IdempotentOnTheRecord(t *testing.T) {
	orgID, principalID, roleID := layeredFixture(t, "doc", "read")

	registerNode(t, orgID, "tree", "root", "", "")
	registerNode(t, orgID, "tree.other", "space", "", "")

	place := func(path string) *gen.ScopeNode {
		t.Helper()
		var placed *gen.ScopeNode
		require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
			var err error
			placed, err = testStore.PlaceRecordNode(ctx, &gen.ScopeNode{
				Id:           business.NewIDString(),
				OrgId:        orgID,
				ScopePath:    path,
				Kind:         "record",
				Label:        path,
				ResourceType: "doc",
				ResourceId:   "placed-doc",
			})
			return err
		}))
		return placed
	}

	first := place("tree.doc_1")
	require.Equal(t, "tree.doc_1", first.ScopePath)

	require.Equal(t, first.Id, place("tree.doc_1").Id,
		"placing the same record at the same path must return the node it already has")

	elsewhere := place("tree.other.doc_1")
	require.Equal(t, first.Id, elsewhere.Id, "a placed record is never silently re-pointed")
	require.Equal(t, "tree.doc_1", elsewhere.ScopePath,
		"the caller learns the path the record actually sits at, so it can refuse the move")

	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.GrantScope(ctx, &gen.ScopeGrant{
			Id:          business.NewIDString(),
			OrgId:       orgID,
			SubjectId:   principalID,
			SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL,
			ScopePath:   "tree",
			RoleId:      roleID,
		})
	}))
	require.True(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "placed-doc", "read"),
		"a placed record resolves its scope from the node PlaceRecordNode created")
}

// A direct record share grants access to exactly that record, independent of the
// scope hierarchy, and only for that record.
func TestCheckAccess_PerRecordShare(t *testing.T) {
	orgID, principalID, roleID := layeredFixture(t, "doc", "read")

	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.ShareRecord(ctx, &gen.RecordShare{
			Id:           business.NewIDString(),
			OrgId:        orgID,
			ResourceType: "doc",
			ResourceId:   "shared-doc",
			SubjectId:    principalID,
			SubjectKind:  gen.SubjectKind_SUBJECT_KIND_PRINCIPAL,
			RoleId:       roleID,
		})
	}))

	require.True(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "shared-doc", "read"),
		"a direct share must grant access to that record")
	require.False(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "other-doc", "read"),
		"a share on one record must not leak to another")
}

// A human principal inherits scope grants and record shares assigned to teams
// they belong to, exactly like CheckPermission.
func TestCheckAccess_TeamInheritance(t *testing.T) {
	orgID, principalID, roleID := layeredFixture(t, "doc", "read")

	teamID := business.NewIDString()
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		if err := testStore.CreateTeam(ctx, &gen.Team{
			Id: teamID, OrgId: orgID, Name: "Team", Slug: "team-" + teamID, Path: "team-" + teamID,
		}); err != nil {
			return err
		}
		if err := testStore.AddTeamMember(ctx, teamID, principalID, "member"); err != nil {
			return err
		}
		if err := testStore.RegisterScopeNode(ctx, &gen.ScopeNode{
			Id: business.NewIDString(), OrgId: orgID, ScopePath: "space", Kind: "space", Label: "space",
		}); err != nil {
			return err
		}
		if err := testStore.RegisterScopeNode(ctx, &gen.ScopeNode{
			Id: business.NewIDString(), OrgId: orgID, ScopePath: "space.doc_1", Kind: "record",
			Label: "space.doc_1", ResourceType: "doc", ResourceId: "team-doc",
		}); err != nil {
			return err
		}
		return testStore.GrantScope(ctx, &gen.ScopeGrant{
			Id: business.NewIDString(), OrgId: orgID, SubjectId: teamID,
			SubjectKind: gen.SubjectKind_SUBJECT_KIND_TEAM, ScopePath: "space", RoleId: roleID,
		})
	}))

	require.True(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "team-doc", "read"),
		"a member must inherit their team's scope grant")
}

// An expired grant and an expired share both stop granting access.
func TestCheckAccess_ExpiryDenies(t *testing.T) {
	orgID, principalID, roleID := layeredFixture(t, "doc", "read")
	past := timestamppb.New(time.Now().Add(-time.Hour))

	registerNode(t, orgID, "area", "area", "", "")
	registerNode(t, orgID, "area.doc_1", "record", "doc", "expiring-doc")

	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		if err := testStore.GrantScope(ctx, &gen.ScopeGrant{
			Id: business.NewIDString(), OrgId: orgID, SubjectId: principalID,
			SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, ScopePath: "area", RoleId: roleID,
			ExpiresAt: past,
		}); err != nil {
			return err
		}
		return testStore.ShareRecord(ctx, &gen.RecordShare{
			Id: business.NewIDString(), OrgId: orgID, ResourceType: "doc", ResourceId: "expiring-share",
			SubjectId: principalID, SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, RoleId: roleID,
			ExpiresAt: past,
		})
	}))

	require.False(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "expiring-doc", "read"),
		"an expired scope grant must not authorize")
	require.False(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "expiring-share", "read"),
		"an expired share must not authorize")
}

// A role whose permission is the (*, *) wildcard authorizes any action, exactly
// as CheckPermission treats wildcards.
func TestCheckAccess_WildcardPermission(t *testing.T) {
	orgID, principalID, roleID := layeredFixture(t, "*", "*")

	registerNode(t, orgID, "wild", "wild", "", "")
	registerNode(t, orgID, "wild.doc_1", "record", "doc", "wild-doc")

	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.GrantScope(ctx, &gen.ScopeGrant{
			Id: business.NewIDString(), OrgId: orgID, SubjectId: principalID,
			SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, ScopePath: "wild", RoleId: roleID,
		})
	}))

	require.True(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "wild-doc", "delete"),
		"a wildcard role must authorize any action on a record in the granted subtree")
}

// Granting on a scope path that is not a registered node fails (gap 6: the
// registry makes the taxonomy typed).
func TestGrantScope_RejectsUnregisteredScope(t *testing.T) {
	orgID, principalID, roleID := layeredFixture(t, "doc", "read")

	err := testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.GrantScope(ctx, &gen.ScopeGrant{
			Id: business.NewIDString(), OrgId: orgID, SubjectId: principalID,
			SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, ScopePath: "never_registered", RoleId: roleID,
		})
	})
	require.ErrorContains(t, err, "not a registered node")
}

// The ltree label encoding is enforced at the boundary: a path with an invalid
// label (e.g. a raw UUID's hyphens, or uppercase) is rejected cleanly.
func TestRegisterScopeNode_RejectsInvalidLabelEncoding(t *testing.T) {
	orgID, _, _ := layeredFixture(t, "doc", "read")

	for _, bad := range []string{"Foundation", "a-b-c", "root.Solution", "root..leaf"} {
		err := testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
			return testStore.RegisterScopeNode(ctx, &gen.ScopeNode{
				Id: business.NewIDString(), OrgId: orgID, ScopePath: bad, Kind: "x", Label: bad,
			})
		})
		require.Error(t, err, "path %q must be rejected", bad)
	}
}

// Re-granting / re-sharing the same natural-key tuple is idempotent — it must
// refresh the row, not raise a unique violation — matching AssignRole.
func TestGrantScopeAndShareRecord_Idempotent(t *testing.T) {
	orgID, principalID, roleID := layeredFixture(t, "doc", "read")
	registerNode(t, orgID, "idem", "area", "", "")

	grant := func() error {
		return testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
			return testStore.GrantScope(ctx, &gen.ScopeGrant{
				Id: business.NewIDString(), OrgId: orgID, SubjectId: principalID,
				SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, ScopePath: "idem", RoleId: roleID,
			})
		})
	}
	require.NoError(t, grant())
	require.NoError(t, grant(), "re-granting the same tuple must be idempotent")

	share := func() error {
		return testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
			return testStore.ShareRecord(ctx, &gen.RecordShare{
				Id: business.NewIDString(), OrgId: orgID, ResourceType: "doc", ResourceId: "idem-doc",
				SubjectId: principalID, SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, RoleId: roleID,
			})
		})
	}
	require.NoError(t, share())
	require.NoError(t, share(), "re-sharing the same tuple must be idempotent")

	var shares []*gen.RecordShare
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		var e error
		shares, e = testStore.ListShares(ctx, orgID, "doc", "idem-doc")
		return e
	}))
	require.Len(t, shares, 1, "an idempotent re-share must not create a duplicate row")
}

// The scope registry stays a connected tree: registering a node whose immediate
// parent is not yet registered fails (roots are exempt).
func TestRegisterScopeNode_RequiresParent(t *testing.T) {
	orgID, _, _ := layeredFixture(t, "doc", "read")

	orphan := testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.RegisterScopeNode(ctx, &gen.ScopeNode{
			Id: business.NewIDString(), OrgId: orgID, ScopePath: "missing_parent.child", Kind: "x", Label: "child",
		})
	})
	require.ErrorContains(t, orphan, "parent scope")

	// Building top-down works.
	registerNode(t, orgID, "present", "area", "", "")
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.RegisterScopeNode(ctx, &gen.ScopeNode{
			Id: business.NewIDString(), OrgId: orgID, ScopePath: "present.child", Kind: "x", Label: "child",
		})
	}))
}

// A grant/share must reference a role the tenant can actually see. A role
// belonging to another org (reachable only because the FK bypasses RLS) is
// rejected instead of stored as inert junk.
func TestGrantScope_RejectsForeignOrgRole(t *testing.T) {
	orgA, principalA, _ := layeredFixture(t, "doc", "read")
	_, _, roleB := layeredFixture(t, "doc", "read") // role lives in a different org
	registerNode(t, orgA, "foreign", "area", "", "")

	err := testStore.WithOrgTx(testCtx, orgA, func(ctx context.Context) error {
		return testStore.GrantScope(ctx, &gen.ScopeGrant{
			Id: business.NewIDString(), OrgId: orgA, SubjectId: principalA,
			SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, ScopePath: "foreign", RoleId: roleB,
		})
	})
	require.ErrorContains(t, err, "not a role in this org")

	err = testStore.WithOrgTx(testCtx, orgA, func(ctx context.Context) error {
		return testStore.ShareRecord(ctx, &gen.RecordShare{
			Id: business.NewIDString(), OrgId: orgA, ResourceType: "doc", ResourceId: "foreign-doc",
			SubjectId: principalA, SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, RoleId: roleB,
		})
	})
	require.ErrorContains(t, err, "not a role in this org")
}

// A role assignment must reference a role the tenant can actually see, matching
// the grant/share paths. Assigning another org's role_id (reachable only because
// the FK bypasses RLS) is rejected rather than stored as inert junk.
func TestAssignRole_RejectsForeignOrgRole(t *testing.T) {
	orgA, principalA, _ := layeredFixture(t, "doc", "read")
	_, _, roleB := layeredFixture(t, "doc", "read") // role lives in a different org

	err := testStore.WithOrgTx(testCtx, orgA, func(ctx context.Context) error {
		return testStore.AssignRole(ctx, &gen.RoleAssignment{
			Id: business.NewIDString(), OrgId: orgA, SubjectId: principalA,
			SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, RoleId: roleB,
		})
	})
	require.ErrorContains(t, err, "not a role in this org")
}

// A grant via a built-in / global role (org_id IS NULL) authorizes: CheckAccess
// resolves the wildcard permission through role_permissions, whose RLS exposes
// global roles inside a tenant tx. This is the load-bearing visibility the whole
// resolver relies on.
func TestCheckAccess_GlobalRoleGrant(t *testing.T) {
	principalID := seedUser(t)
	orgID := seedOrg(t, principalID)
	require.NoError(t, testStore.As(business.Identity{OrgID: orgID}).AddOrgMember(testCtx, principalID, "owner"))

	// Global roles (org_id NULL) can only be minted by the control plane.
	globalRoleID := business.NewIDString()
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		return testStore.CreateRole(ctx, &gen.Role{
			Id: globalRoleID, Name: "global reader " + globalRoleID, Description: "global",
			BuiltIn: true, Permissions: []*gen.Permission{{Resource: "doc", Action: "read"}},
		})
	}))

	registerNode(t, orgID, "g", "area", "", "")
	registerNode(t, orgID, "g.doc_1", "record", "doc", "global-doc")
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.GrantScope(ctx, &gen.ScopeGrant{
			Id: business.NewIDString(), OrgId: orgID, SubjectId: principalID,
			SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, ScopePath: "g", RoleId: globalRoleID,
		})
	}))

	require.True(t, checkAccess(t, orgID, principalID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "doc", "global-doc", "read"),
		"a grant via a global/built-in role must authorize")
}

func TestListCollectionAccess_ReadGrantsAndTenantIsolation(t *testing.T) {
	// The resource the composition declares its content under. The host never
	// names it; this stands in for the declared module registry.
	declared := []string{"documents"}
	orgID, actorID, roleID := layeredFixture(t, "documents", "read")
	otherOrg, _, _ := layeredFixture(t, "documents", "read")
	registerNode(t, orgID, "root", "solution", "", "")
	registerNode(t, orgID, "root.example", "collection", "", "")
	registerNode(t, orgID, "root.empty", "collection", "", "")
	registerNode(t, otherOrg, "private", "collection", "", "")
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		for _, permission := range []string{"documents", "knowledge"} {
			excludedRole := business.NewIDString()
			require.NoError(t, testStore.CreateRole(ctx, &gen.Role{Id: excludedRole, OrgId: orgID, Name: "Example " + excludedRole, Permissions: []*gen.Permission{{Resource: permission, Action: "read"}}}))
			grant := &gen.ScopeGrant{Id: business.NewIDString(), OrgId: orgID, SubjectId: actorID, SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, ScopePath: "root.example", RoleId: excludedRole, GrantedBy: actorID}
			if permission == "documents" {
				grant.ExpiresAt = timestamppb.New(time.Now().Add(-time.Hour))
			}
			require.NoError(t, testStore.GrantScope(ctx, grant))
		}
		return nil
	}))
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.GrantScope(ctx, &gen.ScopeGrant{Id: business.NewIDString(), OrgId: orgID, SubjectId: actorID, SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, ScopePath: "root", RoleId: roleID, GrantedBy: actorID})
	}))
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		rows, err := testStore.ListCollectionAccess(ctx, orgID, "", 1, declared)
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.Equal(t, "root.empty", rows[0].Node.ScopePath)
		require.Len(t, rows[0].ReadGrants, 1)
		require.Equal(t, "root", rows[0].ReadGrants[0].Grant.ScopePath)
		require.NotEmpty(t, rows[0].ReadGrants[0].ActorLabel)
		next, err := testStore.ListCollectionAccess(ctx, orgID, rows[0].Node.ScopePath, 100, declared)
		require.NoError(t, err)
		require.Len(t, next, 1)
		require.Equal(t, "root.example", next[0].Node.ScopePath)
		foreign, err := testStore.ListCollectionAccess(ctx, otherOrg, "", 100, declared)
		require.NoError(t, err)
		require.Empty(t, foreign)
		// A composition that declares no content resource authorizes nothing: the
		// boundaries still list, but no grant is reported as conferring read.
		undeclared, err := testStore.ListCollectionAccess(ctx, orgID, "", 100, nil)
		require.NoError(t, err)
		require.Len(t, undeclared, 2)
		for _, row := range undeclared {
			require.Empty(t, row.ReadGrants, "an undeclared resource must confer no read")
		}
		return testStore.RevokeScope(ctx, orgID, actorID, gen.SubjectKind_SUBJECT_KIND_PRINCIPAL, "root", roleID)
	}))
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		rows, err := testStore.ListCollectionAccess(ctx, orgID, "", 100, declared)
		require.NoError(t, err)
		require.Len(t, rows, 2)
		require.Empty(t, rows[0].ReadGrants)
		require.Empty(t, rows[1].ReadGrants)
		return nil
	}))
}
