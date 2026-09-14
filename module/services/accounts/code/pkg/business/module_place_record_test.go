package business_test

import (
	"context"
	"testing"

	"accounts/pkg/business"
	gen "accounts/pkg/gen/saas/accounts/v1"

	"google.golang.org/grpc/codes"
)

// fakePlacementStore records placements under the record identity the real
// unique index keys on, so the surface's idempotency and re-point rules can be
// asserted without a database.
type fakePlacementStore struct {
	fakeTxStore
	placed map[string]*gen.ScopeNode
}

func newPlacementStore() *fakePlacementStore {
	return &fakePlacementStore{placed: map[string]*gen.ScopeNode{}}
}

func (f *fakePlacementStore) PlaceRecordNode(_ context.Context, node *gen.ScopeNode) (*gen.ScopeNode, error) {
	key := node.GetResourceType() + "/" + node.GetResourceId()
	if existing, ok := f.placed[key]; ok {
		return existing, nil
	}
	f.placed[key] = node
	return node, nil
}

func newPlacementService(t *testing.T, store business.Store, grant business.ModulePrincipalGrant) *business.Service {
	t.Helper()
	svc, err := business.NewService(store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.SetModuleCapabilities(nil, nil, business.ModulePrincipalRegistry{modulePrincSvc: grant})
	return svc
}

func placeRecord(t *testing.T, svc *business.Service, tenant, path, resourceType, resourceID string) (string, error) {
	t.Helper()
	return svc.ModulePlaceRecord(context.Background(),
		business.ModuleCaller{PrincipalID: modulePrincSvc, BoundOrg: moduleTenantA},
		tenant, path, "record", "Record", resourceType, resourceID)
}

func TestModulePlaceRecord_PlacesADeclaredResource(t *testing.T) {
	store := newPlacementStore()
	svc := newPlacementService(t, store, business.ModulePrincipalGrant{Resources: []string{"documents"}})

	nodeID, err := placeRecord(t, svc, moduleTenantA, "space.doc_1", "documents", "doc-1")
	if err != nil {
		t.Fatalf("ModulePlaceRecord: %v", err)
	}
	placed := store.placed["documents/doc-1"]
	if placed == nil || placed.GetId() != nodeID {
		t.Fatalf("expected the record placed at the returned node, got %+v", placed)
	}
	if placed.GetScopePath() != "space.doc_1" || placed.GetOrgId() != moduleTenantA {
		t.Fatalf("placed at the wrong scope: %+v", placed)
	}
}

// The declared resource vocabulary is the whole authority bound: a module may
// place only what its composition said its content is governed by, so it can
// neither introduce a type it holds no grant for nor reach another module's.
func TestModulePlaceRecord_UndeclaredResourceTypeDenied(t *testing.T) {
	store := newPlacementStore()
	svc := newPlacementService(t, store, business.ModulePrincipalGrant{Resources: []string{"documents"}})

	_, err := placeRecord(t, svc, moduleTenantA, "space.deal_1", "deals", "deal-1")
	requireCode(t, err, codes.PermissionDenied)
	if len(store.placed) != 0 {
		t.Fatalf("a denied placement must write nothing, got %d", len(store.placed))
	}
}

// A composition that declares no resources for a module authorizes no
// placement — the registry is the allowlist, not a default.
func TestModulePlaceRecord_NoDeclaredResourcesFailsClosed(t *testing.T) {
	svc := newPlacementService(t, newPlacementStore(), business.ModulePrincipalGrant{})

	_, err := placeRecord(t, svc, moduleTenantA, "space.doc_1", "documents", "doc-1")
	requireCode(t, err, codes.PermissionDenied)
}

func TestModulePlaceRecord_UnregisteredPrincipalDenied(t *testing.T) {
	svc := newPlacementService(t, newPlacementStore(), business.ModulePrincipalGrant{Resources: []string{"documents"}})

	_, err := svc.ModulePlaceRecord(context.Background(),
		business.ModuleCaller{PrincipalID: moduleUserA, BoundOrg: moduleTenantA},
		moduleTenantA, "space.doc_1", "record", "Record", "documents", "doc-1")
	requireCode(t, err, codes.PermissionDenied)
}

func TestModulePlaceRecord_OtherTenantRequiresCrossTenant(t *testing.T) {
	svc := newPlacementService(t, newPlacementStore(), business.ModulePrincipalGrant{Resources: []string{"documents"}})

	_, err := placeRecord(t, svc, moduleTenantB, "space.doc_1", "documents", "doc-1")
	requireCode(t, err, codes.PermissionDenied)

	crossTenant := newPlacementService(t, newPlacementStore(),
		business.ModulePrincipalGrant{Resources: []string{"documents"}, CrossTenant: true})
	if _, err := placeRecord(t, crossTenant, moduleTenantB, "space.doc_1", "documents", "doc-1"); err != nil {
		t.Fatalf("a cross-tenant principal may place on another tenant: %v", err)
	}
}

// The surface is at-least-once, so the same placement arriving twice must
// converge on the node that already exists rather than collide with it.
func TestModulePlaceRecord_SamePlacementIsANoOp(t *testing.T) {
	store := newPlacementStore()
	svc := newPlacementService(t, store, business.ModulePrincipalGrant{Resources: []string{"documents"}})

	first, err := placeRecord(t, svc, moduleTenantA, "space.doc_1", "documents", "doc-1")
	if err != nil {
		t.Fatalf("first placement: %v", err)
	}
	second, err := placeRecord(t, svc, moduleTenantA, "space.doc_1", "documents", "doc-1")
	if err != nil {
		t.Fatalf("second placement: %v", err)
	}
	if first != second {
		t.Fatalf("a repeated placement must return the same node, got %s then %s", first, second)
	}
	if len(store.placed) != 1 {
		t.Fatalf("expected one placement, got %d", len(store.placed))
	}
}

// A record resolves through exactly one node, so moving it rewrites who can
// reach it. That is an authorization change and this surface refuses it.
func TestModulePlaceRecord_RepointRefused(t *testing.T) {
	store := newPlacementStore()
	svc := newPlacementService(t, store, business.ModulePrincipalGrant{Resources: []string{"documents"}})

	first, err := placeRecord(t, svc, moduleTenantA, "space.doc_1", "documents", "doc-1")
	if err != nil {
		t.Fatalf("first placement: %v", err)
	}
	_, err = placeRecord(t, svc, moduleTenantA, "other_space.doc_1", "documents", "doc-1")
	requireCode(t, err, codes.FailedPrecondition)
	if got := store.placed["documents/doc-1"]; got.GetId() != first || got.GetScopePath() != "space.doc_1" {
		t.Fatalf("the refused re-point must leave the placement untouched, got %+v", got)
	}
}
