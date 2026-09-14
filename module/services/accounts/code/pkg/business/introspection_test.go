//go:build !pure

package business_test

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/codefly-dev/core/wool"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"accounts/pkg/business"
	gen "accounts/pkg/gen/saas/accounts/v1"
	policyv1 "accounts/pkg/gen/saas/policy/v1"
	"accounts/pkg/relationcatalog"
)

// authedCtx returns a context that GetServiceInfo will treat as
// authenticated (callerIsAuthenticated returns true). Used by
// drift-guard tests so the redaction pass doesn't strip privileged
// RPCs.
//
// wool's WithUserAuthID mutates the Wool's internal ctx; we extract
// it back via w.Context() so subsequent wool.Get(ctx) sees the value.
func authedCtx() context.Context {
	w := wool.Get(context.Background())
	w.WithUserAuthID("test-authed-user")
	return w.Context()
}

// TestIntrospection_GetServiceInfo — pins the catalog endpoint
// shape. The RPC list derives from gRPC service descriptors at
// runtime; this test asserts:
//
//   - Service info (name="api", module="saas-starter", version) set.
//   - Every RLS-protected table has fail_closed = true.
//   - Public RPCs are advertised as such.
//   - Built-in 'admin' role holds the wildcard permission.
func TestIntrospection_GetServiceInfo(t *testing.T) {
	resp, err := testService.GetServiceInfo(authedCtx(), &gen.GetServiceInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	caps := resp.Capabilities
	require.NotNil(t, caps)
	require.NotNil(t, caps.Info)

	require.Equal(t, "accounts", caps.Info.Name)
	require.Equal(t, "saas-starter", caps.Info.Module)
	require.NotEmpty(t, caps.Info.Version)
	require.NotEmpty(t, caps.Rpcs)
	require.NotEmpty(t, caps.Permissions)
	require.NotEmpty(t, caps.RlsTables)
	require.NotEmpty(t, caps.Scopes)

	// Every RLS table claims fail-closed semantics — the load-bearing
	// safety property of the BeforeAcquire pattern.
	for _, tbl := range caps.RlsTables {
		require.True(t, tbl.FailClosed,
			"table %q must declare fail_closed=true", tbl.Table)
		require.NotEmpty(t, tbl.Table)
		require.Contains(t,
			[]string{
				"control_plane", "direct", "function_scoped", "join",
				"polymorphic", "self_referential", "union",
			},
			tbl.PolicyShape,
			"table %q has unexpected policy_shape %q", tbl.Table, tbl.PolicyShape)
	}

	// admin has wildcard.
	var adminWildcard bool
	for _, p := range caps.Permissions {
		if p.Resource == "*" && p.Action == "*" {
			for _, r := range p.BuiltInRoles {
				if r == "admin" {
					adminWildcard = true
				}
			}
		}
	}
	require.True(t, adminWildcard,
		"built-in 'admin' role must hold wildcard *:* permission")
}

// TestIntrospection_RLSCatalogCoversEveryProtectedRelation — drift guard. The
// published catalog is a projection of the store schema's authority inventory,
// which the infrastructure suite checks against a live database. Anything the
// catalog omits or invents is therefore a projection bug rather than a stale
// hand-maintained list.
func TestIntrospection_RLSCatalogCoversEveryProtectedRelation(t *testing.T) {
	resp, err := testService.GetServiceInfo(authedCtx(), &gen.GetServiceInfoRequest{})
	require.NoError(t, err)

	inventory := relationcatalog.All()
	var expected []string
	for relation, authority := range inventory {
		if authority.Scope.RequiresRLS() {
			expected = append(expected, relation)
		}
	}
	sort.Strings(expected)

	published := make([]string, 0, len(resp.Capabilities.RlsTables))
	for _, table := range resp.Capabilities.RlsTables {
		published = append(published, table.Table)

		authority := inventory[table.Table]
		require.Equal(t, authority.PolicyShape, table.PolicyShape, table.Table)
		require.Equal(t, authority.ScopeColumn, table.ScopeColumn, table.Table)
		require.Equal(t, authority.Notes, table.Notes, table.Table)
	}
	require.Equal(t, expected, published)
}

// TestIntrospection_NoMissingPolicy — drift guard. The RPC list and policy are
// descriptor-derived; adding a method without a valid method_policy option is
// therefore visible as an unclassified row and fails loud.
func TestIntrospection_NoMissingPolicy(t *testing.T) {
	resp, err := testService.GetServiceInfo(authedCtx(), &gen.GetServiceInfoRequest{})
	require.NoError(t, err)

	var missing []string
	for _, r := range resp.Capabilities.Rpcs {
		if r.HandlerAuthz == "" {
			missing = append(missing, r.Service+"/"+r.Method)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("RPCs without valid descriptor method policy (%d):\n  %v\nAdd saas.policy.v1.method_policy options.", len(missing), missing)
	}
}

func TestRPCPolicyInventoryIsCompleteAndClassified(t *testing.T) {
	policies := business.RPCPolicies()
	require.NotEmpty(t, policies)
	seen := make(map[string]struct{}, len(policies))
	streaming := make(map[string]bool)
	var internalWithoutHTTP []string
	for _, policy := range policies {
		require.Empty(t, policy.PolicyError, "%s has invalid descriptor policy", policy.FullMethod)
		require.NotNil(t, policy.MethodPolicy, "%s has no descriptor policy", policy.FullMethod)
		require.True(t, policy.Tier.Valid(), "%s has invalid tier %q", policy.FullMethod, policy.Tier)
		if policy.MethodPolicy.GetExposure() == policyv1.Exposure_EXPOSURE_INTERNAL {
			require.Empty(t, policy.HTTPMethod, "%s must not opt into REST", policy.FullMethod)
			require.Empty(t, policy.HTTPPath, "%s must not opt into REST", policy.FullMethod)
			internalWithoutHTTP = append(internalWithoutHTTP, policy.FullMethod)
		} else {
			require.Equal(t, policy.HTTPMethod == "", policy.HTTPPath == "", "%s has incomplete HTTP metadata", policy.FullMethod)
		}
		require.NotEmpty(t, policy.Description, "%s has no description", policy.FullMethod)
		_, duplicate := seen[policy.FullMethod]
		require.False(t, duplicate, "duplicate policy for %s", policy.FullMethod)
		seen[policy.FullMethod] = struct{}{}
		streaming[policy.FullMethod] = policy.Streaming
	}
	require.ElementsMatch(t, []string{
		"/saas.accounts.v1.APIKeyService/ValidateAPIKey",
		"/saas.accounts.v1.IdentityService/ResolveIdentity",
		"/saas.accounts.v1.ModuleCapabilitiesService/ListReadableSourceCollections",
		"/saas.accounts.v1.ModuleCapabilitiesService/PlaceRecord",
		"/saas.accounts.v1.ModuleCapabilitiesService/EnqueueJob",
		"/saas.accounts.v1.ModuleCapabilitiesService/ClaimJobs",
		"/saas.accounts.v1.ModuleCapabilitiesService/HeartbeatJob",
		"/saas.accounts.v1.ModuleCapabilitiesService/AckJob",
		"/saas.accounts.v1.ModuleCapabilitiesService/NackJob",
		"/saas.accounts.v1.ModuleCapabilitiesService/NotifyUser",
		"/saas.accounts.v1.ModuleCapabilitiesService/RequestApproval",
		"/saas.accounts.v1.ModuleCapabilitiesService/GetApproval",
		"/saas.accounts.v1.ModuleCapabilitiesService/CancelApproval",
		"/saas.accounts.v1.ModuleCapabilitiesService/EmitAuditEvent",
		"/saas.accounts.v1.ModuleCapabilitiesService/FetchDatasourceBlob",
		"/saas.accounts.v1.ModuleCapabilitiesService/MintModuleRegistration",
		"/saas.accounts.v1.ModuleCapabilitiesService/MintModuleWorkContext",
		"/saas.accounts.v1.ModuleCapabilitiesService/MintSolutionRegistration",
		"/saas.accounts.v1.ModuleCapabilitiesService/PublishEvent",
		"/saas.accounts.v1.ModuleCapabilitiesService/Subscribe",
		"/saas.accounts.v1.ModuleCapabilitiesService/Unsubscribe",
		"/saas.accounts.v1.ModuleCapabilitiesService/ListSubscriptions",
		"/saas.accounts.v1.ModuleCapabilitiesService/ReplayEvents",
		"/saas.accounts.v1.PermissionService/CheckAccess",
		"/saas.accounts.v1.PermissionService/CheckPermission",
		"/saas.accounts.v1.PermissionService/Decide",
		"/saas.accounts.v1.PermissionService/ListAccessibleScopes",
		"/saas.accounts.v1.PrincipalService/DisableAgentPrincipal",
		"/saas.accounts.v1.PrincipalService/EnableAgentPrincipal",
		"/saas.accounts.v1.PrincipalService/GetAgentPrincipal",
		"/saas.accounts.v1.PrincipalService/GetPrincipal",
		"/saas.accounts.v1.SolutionRegistryService/DeleteSolutionRegistration",
		"/saas.accounts.v1.SolutionRegistryService/ListSolutionRegistrations",
		"/saas.accounts.v1.SolutionRegistryService/PutSolutionRegistration",
		"/saas.accounts.v1.UsageService/ConsumeUsage",
		"/saas.accounts.v1.WorkContextService/AuthorizeEvidenceRead",
		"/saas.accounts.v1.WorkContextService/CheckAuthorizationRevision",
		"/saas.accounts.v1.WorkContextService/ConsumeSingleUse",
		"/saas.accounts.v1.WorkContextService/StartInstallationTask",
	}, internalWithoutHTTP, "the exact internal RPC inventory must remain off the REST surface")
	require.True(t, streaming["/saas.accounts.v1.DelegationService/WaitForDelegation"], "server-streaming RPC must be present and marked streaming")
	require.True(t, streaming["/saas.accounts.v1.ModuleCapabilitiesService/FetchDatasourceBlob"], "server-streaming RPC must be present and marked streaming")
}

func TestRPCPolicyDescriptorFixesFormerManualDrift(t *testing.T) {
	byMethod := make(map[string]business.RPCPolicy)
	for _, policy := range business.RPCPolicies() {
		byMethod[policy.FullMethod] = policy
	}

	authenticate := byMethod["/saas.accounts.v1.AuthService/Authenticate"]
	require.True(t, authenticate.EmitsAudit)
	require.ElementsMatch(t, []string{"saas.auth.login", "saas.auth.mfa_challenge_started"}, authenticate.MethodPolicy.GetAudit().GetEvents())

	listUsers := byMethod["/saas.accounts.v1.UserService/ListUsers"]
	require.Equal(t, []string{"users:read"}, listUsers.Scopes)
	require.Equal(t, "GET", listUsers.HTTPMethod)
	require.Equal(t, "/v1/users", listUsers.HTTPPath)

	entitlements := byMethod["/saas.accounts.v1.PlatformAdminService/GetOrgEntitlements"]
	require.Equal(t, business.RPCPolicyOrgMember, entitlements.Tier)
	require.Equal(t, "/v1/platform/organizations/{org_id}/entitlements", entitlements.HTTPPath)

	grantPlatformRole := byMethod["/saas.accounts.v1.PlatformAdminService/GrantPlatformRole"]
	require.Equal(t, policyv1.PlatformRoleRequirement_PLATFORM_ROLE_REQUIREMENT_SUPER_ADMIN, grantPlatformRole.MethodPolicy.GetPlatformRole())
	require.Equal(t, policyv1.MFARequirement_MFA_REQUIREMENT_IF_ENROLLED_RECENT_STEP_UP, grantPlatformRole.MethodPolicy.GetMfa())
}

func TestRPCPolicyMatrixIsCurrent(t *testing.T) {
	want := business.RenderRPCPolicyMatrix()
	got, err := os.ReadFile("../../../AUTHZ_MATRIX.md")
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "run: go generate ./pkg/business")
}

// TestIntrospection_PublicRPCsAdvertised — the gRPC auth interceptor
// publicGrpcMethods skip-list and the catalog must agree on which
// RPCs are public.
func TestIntrospection_PublicRPCsAdvertised(t *testing.T) {
	resp, err := testService.GetServiceInfo(authedCtx(), &gen.GetServiceInfoRequest{})
	require.NoError(t, err)

	got := map[string]string{}
	for _, r := range resp.Capabilities.Rpcs {
		got[r.Service+"/"+r.Method] = r.HandlerAuthz
	}

	for _, key := range []string{
		"IntrospectionService/GetServiceInfo",
		"UserService/Version",
		"UserService/RegisterUser",
		"AuthService/GetJWKS",
		"AuthService/BeginOAuth",
		"AuthService/Authenticate",
		"AuthService/CompleteMFAChallenge",
		"AuthService/BeginWebAuthnMFAChallenge",
		"AuthService/CompleteWebAuthnMFAChallenge",
		"AuthService/RefreshToken",
		"AuthService/Logout",
	} {
		require.Equal(t, "public", got[key],
			"RPC %s must be advertised as handler_authz=public", key)
	}
}

// TestIntrospection_RPCListMatchesDescriptors — strongest drift
// guard. Builds the expected (service, method) set from gRPC
// descriptors and compares to the response.
func TestIntrospection_RPCListMatchesDescriptors(t *testing.T) {
	resp, err := testService.GetServiceInfo(authedCtx(), &gen.GetServiceInfoRequest{})
	require.NoError(t, err)

	wanted := map[string]struct{}{}
	protoregistry.GlobalFiles.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		if string(file.Package()) != "saas.accounts.v1" {
			return true
		}
		for i := 0; i < file.Services().Len(); i++ {
			service := file.Services().Get(i)
			for j := 0; j < service.Methods().Len(); j++ {
				wanted[string(service.Name())+"/"+string(service.Methods().Get(j).Name())] = struct{}{}
			}
		}
		return true
	})

	got := map[string]struct{}{}
	for _, r := range resp.Capabilities.Rpcs {
		got[r.Service+"/"+r.Method] = struct{}{}
	}

	var missing []string
	for k := range wanted {
		if _, ok := got[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	require.Empty(t, missing,
		"catalog response missing %d RPCs that exist in proto: %v", len(missing), missing)

	var extra []string
	for k := range got {
		if _, ok := wanted[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	require.Empty(t, extra,
		"catalog response includes %d RPCs that don't exist in proto: %v", len(extra), extra)
}

// TestIntrospection_UnauthenticatedRedacts — anonymous callers
// should not see platform_admin / mfa-tier rows.
func TestIntrospection_UnauthenticatedRedacts(t *testing.T) {
	anonResp, err := testService.GetServiceInfo(context.Background(), &gen.GetServiceInfoRequest{})
	require.NoError(t, err)
	for _, r := range anonResp.Capabilities.Rpcs {
		require.NotEqual(t, "platform_admin", r.HandlerAuthz,
			"anonymous response must not include platform_admin RPCs (got %s)", r.Service+"/"+r.Method)
		require.NotEqual(t, "mfa", r.HandlerAuthz,
			"anonymous response must not include mfa-tier RPCs (got %s)", r.Service+"/"+r.Method)
		require.NotEqual(t, "internal", r.HandlerAuthz,
			"anonymous response must not include internal RPCs (got %s)", r.Service+"/"+r.Method)
	}
	require.NotEmpty(t, anonResp.Capabilities.Rpcs,
		"anonymous still gets non-privileged RPCs")
	require.Empty(t, anonResp.Capabilities.RlsTables,
		"anonymous response must not map the schema: relation names, scope columns, and the notes describing each boundary's mechanism")
}

var _ = business.ServiceVersion // keep business import alive
