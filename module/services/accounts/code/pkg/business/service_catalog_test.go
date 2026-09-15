package business_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"accounts/pkg/business"
	catalogv1 "accounts/pkg/gen/saas/catalog/v1"
	policyv1 "accounts/pkg/gen/saas/policy/v1"
)

func TestServiceCatalogCompilation(t *testing.T) {
	catalog, err := business.BuildServiceCatalog()
	require.NoError(t, err)
	require.NoError(t, business.ValidateServiceCatalog(catalog))
	require.Equal(t, business.ServiceCatalogSchemaVersion, catalog.GetSchemaVersion())
	require.Equal(t, "saas-starter", catalog.GetOwner().GetModule())
	require.Equal(t, "accounts", catalog.GetOwner().GetService())
	require.Equal(t, "saas.accounts.v1", catalog.GetApiPackage())
	require.Equal(t, business.ServiceVersion, catalog.GetApiVersion())
	require.Len(t, catalog.GetServices(), 32)
	require.Len(t, catalog.GetMethods(), 201)
	require.Len(t, catalog.GetPermissions(), 24)
	require.Len(t, catalog.GetEntitlements(), 5)
	require.Equal(t, "*:*", catalog.GetPermissions()[0].GetPermission())
	require.Equal(t, "api_calls_monthly", catalog.GetEntitlements()[0].GetKey())

	methods := make(map[string]*catalogv1.Method, len(catalog.GetMethods()))
	for _, method := range catalog.GetMethods() {
		methods[method.GetProcedure()] = method
		require.Equal(t, catalog.GetOwner().GetModule(), method.GetOwner().GetModule())
		require.Equal(t, catalog.GetOwner().GetService(), method.GetOwner().GetService())
		require.NotEmpty(t, method.GetInputType())
		require.NotEmpty(t, method.GetOutputType())
		require.NotEmpty(t, method.GetSourceProto())
		require.NotNil(t, method.GetPolicy())
	}

	readableSources := methods["/saas.accounts.v1.ModuleCapabilitiesService/ListReadableSourceCollections"]
	require.NotNil(t, readableSources)
	require.Equal(t, policyv1.Exposure_EXPOSURE_INTERNAL, readableSources.GetPolicy().GetExposure())
	require.Empty(t, readableSources.GetHttpBindings())
	require.Equal(t, []catalogv1.Protocol{catalogv1.Protocol_PROTOCOL_GRPC, catalogv1.Protocol_PROTOCOL_CONNECT}, readableSources.GetProtocols())
	require.Equal(t, "saas.accounts.v1.ListReadableSourceCollectionsRequest", readableSources.GetInputType())
	require.Equal(t, "saas.accounts.v1.ListReadableSourceCollectionsResponse", readableSources.GetOutputType())

	collectionAccess := methods["/saas.accounts.v1.PermissionService/ListCollectionAccess"]
	require.NotNil(t, collectionAccess)
	require.Equal(t, policyv1.Exposure_EXPOSURE_AUTHENTICATED, collectionAccess.GetPolicy().GetExposure())
	require.Equal(t, policyv1.TenantRequirement_TENANT_REQUIREMENT_ORG_ADMIN, collectionAccess.GetPolicy().GetTenant())
	require.Equal(t, "/v1/collection-access", collectionAccess.GetHttpBindings()[0].GetPath())

	authenticate := methods["/saas.accounts.v1.AuthService/Authenticate"]
	require.NotNil(t, authenticate)
	require.Equal(t, "saas.accounts.v1.AuthenticateRequest", authenticate.GetInputType())
	require.Equal(t, "saas.accounts.v1.AuthenticateResponse", authenticate.GetOutputType())
	require.Equal(t, "saas/accounts/v1/authentication.proto", authenticate.GetSourceProto())
	require.Equal(t, []catalogv1.Protocol{
		catalogv1.Protocol_PROTOCOL_GRPC,
		catalogv1.Protocol_PROTOCOL_CONNECT,
		catalogv1.Protocol_PROTOCOL_REST,
	}, authenticate.GetProtocols())
	require.Equal(t, "POST", authenticate.GetHttpBindings()[0].GetMethod())
	require.Equal(t, "/v1/auth/authenticate", authenticate.GetHttpBindings()[0].GetPath())
	require.Equal(t, "*", authenticate.GetHttpBindings()[0].GetBody())
	require.Equal(t, policyv1.Exposure_EXPOSURE_PUBLIC, authenticate.GetPolicy().GetExposure())
	require.ElementsMatch(t, []string{"saas.auth.login", "saas.auth.mfa_challenge_started"}, authenticate.GetPolicy().GetAudit().GetEvents())

	wait := methods["/saas.accounts.v1.DelegationService/WaitForDelegation"]
	require.NotNil(t, wait)
	require.False(t, wait.GetClientStreaming())
	require.True(t, wait.GetServerStreaming())

	replayJob := methods["/saas.accounts.v1.PlatformAdminService/ReplayJob"]
	require.NotNil(t, replayJob)
	require.Equal(t, policyv1.PlatformRoleRequirement_PLATFORM_ROLE_REQUIREMENT_SUPER_ADMIN, replayJob.GetPolicy().GetPlatformRole())
	require.Equal(t, policyv1.MFARequirement_MFA_REQUIREMENT_RECENT_STEP_UP, replayJob.GetPolicy().GetMfa())
	require.Equal(t, "/v1/platform/jobs/{source_job_id}:replay", replayJob.GetHttpBindings()[0].GetPath())

	usageHistory := methods["/saas.accounts.v1.UsageService/GetUsageHistory"]
	require.NotNil(t, usageHistory)
	require.Equal(t, "/v1/organizations/{organization_id}/usage/{meter}/history", usageHistory.GetHttpBindings()[0].GetPath())
}

func TestLegacyFeatureFlagInventoryIsReadOnly(t *testing.T) {
	catalog, err := business.BuildServiceCatalog()
	require.NoError(t, err)

	methods := make(map[string]*catalogv1.Method, len(catalog.GetMethods()))
	for _, method := range catalog.GetMethods() {
		methods[method.GetProcedure()] = method
	}

	list := methods["/saas.accounts.v1.PlatformAdminService/ListFeatureFlags"]
	require.NotNil(t, list)
	require.Equal(t, "GET", list.GetHttpBindings()[0].GetMethod())
	require.Equal(t, "/v1/platform/feature-flags", list.GetHttpBindings()[0].GetPath())
	upsert := methods["/saas.accounts.v1.PlatformAdminService/UpsertFeatureFlag"]
	require.NotNil(t, upsert, "published v1 RPC must remain for wire compatibility")
	require.Equal(t, policyv1.PlatformRoleRequirement_PLATFORM_ROLE_REQUIREMENT_SUPER_ADMIN, upsert.GetPolicy().GetPlatformRole())
	require.Equal(t, "PUT", upsert.GetHttpBindings()[0].GetMethod())
	require.Equal(t, "/v1/platform/feature-flags/{name}", upsert.GetHttpBindings()[0].GetPath())
}

func TestServiceCatalogJSONIsDeterministicAndCurrent(t *testing.T) {
	first, err := business.RenderServiceCatalogJSON()
	require.NoError(t, err)
	second, err := business.RenderServiceCatalogJSON()
	require.NoError(t, err)
	require.Equal(t, first, second)

	checkedIn, err := os.ReadFile("../../../generated/service-catalog.json")
	require.NoError(t, err)
	require.Equal(t, string(first), string(checkedIn), "run: go generate ./pkg/business")

	parsed := &catalogv1.ServiceCatalog{}
	require.NoError(t, (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(checkedIn, parsed))
	require.NoError(t, business.ValidateServiceCatalog(parsed))
	built, err := business.BuildServiceCatalog()
	require.NoError(t, err)
	require.True(t, proto.Equal(built, parsed))
}

func TestServiceCatalogValidationRejectsConsumerUnsafeDrift(t *testing.T) {
	catalog, err := business.BuildServiceCatalog()
	require.NoError(t, err)

	wrongSchema := proto.Clone(catalog).(*catalogv1.ServiceCatalog)
	wrongSchema.SchemaVersion = "saas.catalog.v2"
	require.ErrorContains(t, business.ValidateServiceCatalog(wrongSchema), "unsupported")

	wrongOwner := proto.Clone(catalog).(*catalogv1.ServiceCatalog)
	wrongOwner.Methods[0].Owner.Service = "other"
	require.ErrorContains(t, business.ValidateServiceCatalog(wrongOwner), "owner does not match")

	unsorted := proto.Clone(catalog).(*catalogv1.ServiceCatalog)
	unsorted.Methods[0], unsorted.Methods[1] = unsorted.Methods[1], unsorted.Methods[0]
	require.ErrorContains(t, business.ValidateServiceCatalog(unsorted), "not strictly sorted")

	transportMismatch := proto.Clone(catalog).(*catalogv1.ServiceCatalog)
	transportMismatch.Methods[0].Protocols = transportMismatch.Methods[0].Protocols[:2]
	require.ErrorContains(t, business.ValidateServiceCatalog(transportMismatch), "protocol list is not canonical")

	internalREST := proto.Clone(catalog).(*catalogv1.ServiceCatalog)
	for _, method := range internalREST.Methods {
		if method.GetPolicy().GetExposure() != policyv1.Exposure_EXPOSURE_INTERNAL {
			continue
		}
		method.HttpBindings = []*catalogv1.HTTPBinding{{Method: "POST", Path: "/v1/internal"}}
		method.Protocols = append(method.Protocols, catalogv1.Protocol_PROTOCOL_REST)
		break
	}
	require.ErrorContains(t, business.ValidateServiceCatalog(internalREST), "must not declare HTTP bindings")

	duplicateRoute := proto.Clone(catalog).(*catalogv1.ServiceCatalog)
	duplicateRoute.Methods[1].HttpBindings[0].Method = duplicateRoute.Methods[0].HttpBindings[0].GetMethod()
	duplicateRoute.Methods[1].HttpBindings[0].Path = duplicateRoute.Methods[0].HttpBindings[0].GetPath()
	require.ErrorContains(t, business.ValidateServiceCatalog(duplicateRoute), "duplicate HTTP route")

	unknownPermission := proto.Clone(catalog).(*catalogv1.ServiceCatalog)
	unknownPermission.Methods[0].Policy.Permissions = append(unknownPermission.Methods[0].Policy.Permissions, "unknown:read")
	require.ErrorContains(t, business.ValidateServiceCatalog(unknownPermission), "unknown permission")

	unknownScope := proto.Clone(catalog).(*catalogv1.ServiceCatalog)
	unknownScope.Methods[0].Policy.Scopes = append(unknownScope.Methods[0].Policy.Scopes, "knowledge:read")
	require.ErrorContains(t, business.ValidateServiceCatalog(unknownScope), "unsupported API-key scope")

	unsortedPermissions := proto.Clone(catalog).(*catalogv1.ServiceCatalog)
	unsortedPermissions.Permissions[0], unsortedPermissions.Permissions[1] = unsortedPermissions.Permissions[1], unsortedPermissions.Permissions[0]
	require.ErrorContains(t, business.ValidateServiceCatalog(unsortedPermissions), "permissions are not strictly sorted")

	invalidEntitlement := proto.Clone(catalog).(*catalogv1.ServiceCatalog)
	invalidEntitlement.Entitlements[0].Kind = catalogv1.EntitlementKind_ENTITLEMENT_KIND_UNSPECIFIED
	require.ErrorContains(t, business.ValidateServiceCatalog(invalidEntitlement), "incomplete entitlement")
}
