package cataloggen_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"accounts/pkg/cataloggen"
	catalogv1 "accounts/pkg/gen/saas/catalog/v1"
	policyv1 "accounts/pkg/gen/saas/policy/v1"
)

func TestAuthorizationCatalogCompilationAndPolicyProjection(t *testing.T) {
	serviceDocument := readFixture(t, "../../../generated/service-catalog.json")
	catalog, err := cataloggen.BuildAuthorizationCatalog(serviceDocument)
	require.NoError(t, err)
	require.NoError(t, cataloggen.ValidateAuthorizationCatalog(catalog))
	require.Equal(t, "saas.authz.methods.v1", catalog.GetSchemaVersion())
	require.Equal(t, "accounts", catalog.GetOwner().GetService())

	// Security-invariant coverage counts. These deliberately do NOT track the
	// raw method total (that churns on every endpoint and is already pinned
	// byte-for-byte by the generated/authz-methods.json fixture-equality
	// below) — they encode posture that a reviewer wants flagged if it moves.
	var internalCount, failClosedCount, factorAttemptCount int
	for _, method := range catalog.GetMethods() {
		require.Regexp(t, `^[0-9a-f]{64}$`, method.GetPolicySha256())
		if method.GetPolicy().GetExposure() == policyv1.Exposure_EXPOSURE_INTERNAL {
			internalCount++
		}
		if method.GetRateLimitBackendFailureMode() == catalogv1.RateLimitBackendFailureMode_RATE_LIMIT_BACKEND_FAILURE_MODE_FAIL_CLOSED {
			failClosedCount++
		}
		if method.GetPolicy().GetAuthenticationFactorAttempt() {
			factorAttemptCount++
			require.Contains(t, method.GetProcedure(), "Complete")
		}
	}
	require.Equal(t, 39, internalCount)
	require.Equal(t, 15, failClosedCount)
	require.Equal(t, 2, factorAttemptCount)
	require.Equal(
		t,
		policyv1.Exposure_EXPOSURE_AUTHENTICATED,
		methodByProcedure(catalog, "/saas.accounts.v1.WorkContextService/ExchangeAudience").GetPolicy().GetExposure(),
	)
	require.Equal(
		t,
		policyv1.Exposure_EXPOSURE_AUTHENTICATED,
		methodByProcedure(catalog, "/saas.accounts.v1.UsageService/GetUsageHistory").GetPolicy().GetExposure(),
	)
	require.Equal(
		t,
		policyv1.PlatformRoleRequirement_PLATFORM_ROLE_REQUIREMENT_SUPER_ADMIN,
		methodByProcedure(catalog, "/saas.accounts.v1.PlatformAdminService/UpsertFeatureFlag").GetPolicy().GetPlatformRole(),
	)
}

func TestAuthorizationArtifactsAreDeterministicAndCurrent(t *testing.T) {
	serviceDocument := readFixture(t, "../../../generated/service-catalog.json")
	authz, err := cataloggen.BuildAuthorizationCatalog(serviceDocument)
	require.NoError(t, err)

	first, err := cataloggen.RenderAuthorizationCatalogJSON(authz)
	require.NoError(t, err)
	second, err := cataloggen.RenderAuthorizationCatalogJSON(authz)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, string(readFixture(t, "../../../generated/authz-methods.json")), string(first), "run: go generate ./pkg/cataloggen")

	parsed := &catalogv1.AuthorizationCatalog{}
	require.NoError(t, (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(first, parsed))
	require.True(t, proto.Equal(authz, parsed))

	service := &catalogv1.ServiceCatalog{}
	require.NoError(t, (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(serviceDocument, service))
	goDocument, err := cataloggen.RenderAuthGatewayAuthorizationMetadata(authz, service)
	require.NoError(t, err)
	require.Equal(t, string(readFixture(t, "../../../../auth-gateway/code/authz_catalog_gen.go")), string(goDocument), "run: go generate ./pkg/cataloggen")
	// The byte-equality above already pins every generated line; assert only
	// that the runtime doc keeps its two-section shape, not exact row counts.
	runtimeSections := strings.Split(string(goDocument), "var generatedRESTProcedureByRoute")
	require.Len(t, runtimeSections, 2)
}

func methodByProcedure(
	catalog *catalogv1.AuthorizationCatalog,
	procedure string,
) *catalogv1.AuthorizationMethod {
	for _, method := range catalog.GetMethods() {
		if method.GetProcedure() == procedure {
			return method
		}
	}
	return nil
}

func TestAuthorizationCatalogValidationRejectsUnsafeDrift(t *testing.T) {
	catalog, err := cataloggen.BuildAuthorizationCatalog(readFixture(t, "../../../generated/service-catalog.json"))
	require.NoError(t, err)

	wrongSchema := proto.Clone(catalog).(*catalogv1.AuthorizationCatalog)
	wrongSchema.SchemaVersion = "saas.authz.methods.v2"
	require.ErrorContains(t, cataloggen.ValidateAuthorizationCatalog(wrongSchema), "unsupported")

	wrongHash := proto.Clone(catalog).(*catalogv1.AuthorizationCatalog)
	wrongHash.Methods[0].PolicySha256 = strings.Repeat("0", 64)
	require.ErrorContains(t, cataloggen.ValidateAuthorizationCatalog(wrongHash), "policy hash")

	wrongFailureMode := proto.Clone(catalog).(*catalogv1.AuthorizationCatalog)
	wrongFailureMode.Methods[0].RateLimitBackendFailureMode = catalogv1.RateLimitBackendFailureMode_RATE_LIMIT_BACKEND_FAILURE_MODE_FAIL_CLOSED
	require.ErrorContains(t, cataloggen.ValidateAuthorizationCatalog(wrongFailureMode), "failure mode")

	invalidFactor := proto.Clone(catalog).(*catalogv1.AuthorizationCatalog)
	invalidFactor.Methods[0].Policy.AuthenticationFactorAttempt = true
	require.ErrorContains(t, cataloggen.ValidateAuthorizationCatalog(invalidFactor), "authentication-factor")

	invalidCondition := proto.Clone(catalog).(*catalogv1.AuthorizationCatalog)
	invalidCondition.Methods[0].Policy.Conditions = []*policyv1.Condition{
		{Attribute: policyv1.ConditionAttribute_CONDITION_ATTRIBUTE_STATUS},
	}
	require.ErrorContains(t, cataloggen.ValidateAuthorizationCatalog(invalidCondition), "attribute condition")

	unregisteredEvent := proto.Clone(catalog).(*catalogv1.AuthorizationCatalog)
	unregisteredEvent.Methods[0].Policy.Audit = &policyv1.AuditPolicy{
		Emission: policyv1.AuditEmission_AUDIT_EMISSION_SUCCESS,
		Events:   []string{"nope.not_real"},
	}
	require.ErrorContains(t, cataloggen.ValidateAuthorizationCatalog(unregisteredEvent), "not registered")
}
