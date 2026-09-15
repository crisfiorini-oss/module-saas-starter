package adapters

import (
	"context"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/codefly-dev/core/wool"

	"accounts/pkg/auth"
	"accounts/pkg/business"
	gen "accounts/pkg/gen/saas/accounts/v1"
	eventsv1 "accounts/pkg/gen/saas/events/v1"
	jobsv1 "accounts/pkg/gen/saas/jobs/v1"
)

// connectCtx converts Connect HTTP headers to gRPC incoming metadata so that
// existing gRPC handlers using `wool.GRPC().Inject()` continue to work unchanged
// when invoked from the Connect adapters.
func connectCtx(ctx context.Context, h http.Header) context.Context {
	md := metadata.New(nil)
	for header, key := range wool.HTTPMappings {
		if values := h.Values(header); len(values) > 0 {
			md.Set(string(key), values...)
		}
	}
	if v := h.Values("Authorization"); len(v) > 0 {
		md.Set("authorization", v...)
	}
	if v := h.Values("X-Codefly-Internal-Token"); len(v) > 0 {
		md.Set("x-codefly-internal-token", v...)
	}
	if v := h.Values("X-Scopes"); len(v) > 0 {
		md.Set("x-scopes", v...)
	}
	if v := h.Values("Idempotency-Key"); len(v) > 0 {
		md.Set("idempotency-key", v...)
	}
	return metadata.NewIncomingContext(ctx, md)
}

// unary adapts a gRPC-style handler fn to a Connect handler by unwrapping the
// request, delegating, and wrapping the response.
//
// Errors from gRPC handlers are typed via `status.Error(codes.X, ...)`.
// Connect-Go has its own error code enum and won't recognize a raw
// gRPC status; without translation, every authenticated-but-denied
// call would surface as HTTP 500 / connect code "unknown" instead of
// the correct 401/403/404/etc. translateGRPCError fixes that.
func unary[Req, Resp any](
	ctx context.Context,
	req *connect.Request[Req],
	fn func(context.Context, *Req) (*Resp, error),
) (*connect.Response[Resp], error) {
	ctx = connectCtx(ctx, req.Header())
	resp, err := fn(ctx, req.Msg)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	return connect.NewResponse(resp), nil
}

// translateGRPCError converts a google.golang.org/grpc/status error
// into a connect.Error with the matching code. Pass-through for
// errors that are already connect.Errors or don't carry a gRPC status.
//
// The mapping mirrors Connect's own grpc → connect lookup table; we
// only need a subset because handlers don't currently emit every
// possible code. Anything we don't list explicitly falls back to
// connect.CodeUnknown — the original Connect default — so behaviour
// for unmapped codes is unchanged.
func translateGRPCError(err error) error {
	if err == nil {
		return nil
	}
	// Already a connect error → pass through (handlers may produce
	// these directly when interacting with Connect-only paths).
	var ce *connect.Error
	if asConnectError(err, &ce) {
		return err
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	cc := connectCodeFromGRPC(st.Code())
	return connect.NewError(cc, st.Err())
}

// asConnectError is a tiny errors.As shim kept here to avoid pulling
// `errors` into every connect_handlers consumer. Returns true if err
// (or any wrapped error) is a *connect.Error and writes the result
// into out.
func asConnectError(err error, out **connect.Error) bool {
	for cur := err; cur != nil; {
		if ce, ok := cur.(*connect.Error); ok {
			*out = ce
			return true
		}
		// Unwrap manually to avoid a hard dep on errors.Unwrap from
		// callers; Connect doesn't expose its own.
		type unwrapper interface{ Unwrap() error }
		if u, ok := cur.(unwrapper); ok {
			cur = u.Unwrap()
			continue
		}
		break
	}
	return false
}

func connectCodeFromGRPC(c codes.Code) connect.Code {
	switch c {
	case codes.Canceled:
		return connect.CodeCanceled
	case codes.Unknown:
		return connect.CodeUnknown
	case codes.InvalidArgument:
		return connect.CodeInvalidArgument
	case codes.DeadlineExceeded:
		return connect.CodeDeadlineExceeded
	case codes.NotFound:
		return connect.CodeNotFound
	case codes.AlreadyExists:
		return connect.CodeAlreadyExists
	case codes.PermissionDenied:
		return connect.CodePermissionDenied
	case codes.ResourceExhausted:
		return connect.CodeResourceExhausted
	case codes.FailedPrecondition:
		return connect.CodeFailedPrecondition
	case codes.Aborted:
		return connect.CodeAborted
	case codes.OutOfRange:
		return connect.CodeOutOfRange
	case codes.Unimplemented:
		return connect.CodeUnimplemented
	case codes.Internal:
		return connect.CodeInternal
	case codes.Unavailable:
		return connect.CodeUnavailable
	case codes.DataLoss:
		return connect.CodeDataLoss
	case codes.Unauthenticated:
		return connect.CodeUnauthenticated
	}
	return connect.CodeUnknown
}

// callerID extracts the authenticated user id from request headers/context.
// Returns a gRPC Unauthenticated error if not present.
func callerID(ctx context.Context) (string, error) {
	if identity, ok := auth.VerifiedRequestIdentity(ctx); ok {
		return identity.EffectiveSubjectID(), nil
	}
	w := wool.Get(ctx).In("callerID")
	w.GRPC().Inject()
	// GRPC().Inject() copies forwarded metadata over the stamped identity, and a
	// present-but-empty user.id would otherwise be returned as a non-empty-looking
	// but blank actor. Guard empties the same way requireAuth does.
	id, ok := w.UserID()
	if !ok || id == "" {
		id, ok = w.UserAuthID()
	}
	if !ok || id == "" {
		return "", status.Error(codes.Unauthenticated, "caller identity not found")
	}
	return id, nil
}

// verifiedActor resolves the audit identity of an already-authenticated caller.
// actorID is the verified caller id the handler authorized; the credential kind
// is the one the auth perimeter reports it authenticated (see
// credentialKindFromContext), and the delegation chain comes from the trusted
// `act` claim or gateway-forwarded X-Act header, never from a caller-controlled
// one.
//
// It returns an error rather than a default when the perimeter reported no
// credential kind. A record naming the wrong kind of credential is worse than
// no record: the mutation fails loudly and leaves nothing behind, which is the
// same fail-closed contract emitTx enforces for a failed audit write.
func verifiedActor(ctx context.Context, actorID string) (business.AuditActor, error) {
	actor := business.AuditActor{ID: actorID}
	switch kind := credentialKindFromContext(ctx); kind {
	case credentialKindSession:
		actor.Type = business.ActorTypeUser
	case credentialKindAPIKey:
		actor.Type = business.ActorTypeAPIKey
	default:
		return business.AuditActor{}, status.Error(codes.Internal,
			"cannot attribute the caller: the auth perimeter reported no credential kind")
	}
	actor.DelegationChain = verifiedDelegationChain(ctx)
	return actor, nil
}

// verifiedDelegationChain flattens the RFC 8693 `act` chain into the parties
// that acted on the subject's behalf, immediate delegate first. Every hop is
// recorded: the chain exists only in the token, so a hop dropped here is
// unrecoverable — the audit trail could no longer answer which systems touched
// the mutation, only which one touched it last.
//
// The walk is bounded by MaxActorChainDepth. Both the mint and the verify paths
// already enforce that bound (see auth.ValidateActorChain), so this cannot
// truncate a legitimate chain; it fails closed against an in-memory cycle
// rather than looping forever.
func verifiedDelegationChain(ctx context.Context) []string {
	delegate, ok := auth.VerifiedActorFromContext(ctx)
	if !ok {
		return nil
	}
	var chain []string
	for hop := delegate; hop != nil && len(chain) < auth.MaxActorChainDepth; hop = hop.Act {
		if hop.Subject == "" {
			continue
		}
		chain = append(chain, hop.Subject)
	}
	return chain
}

// callerOrg extracts the caller's org id from context, empty string if absent.
func callerOrg(ctx context.Context) string {
	w := wool.Get(ctx).In("callerOrg")
	w.GRPC().Inject()
	id, _ := w.OrgID()
	return id
}

// ============================================================================
// UserService
// ============================================================================

type userConnectHandler struct{ inner *UserServer }

func (h *userConnectHandler) Version(ctx context.Context, req *connect.Request[gen.VersionRequest]) (*connect.Response[gen.VersionResponse], error) {
	return unary(ctx, req, h.inner.Version)
}
func (h *userConnectHandler) GetSelf(ctx context.Context, req *connect.Request[gen.GetSelfRequest]) (*connect.Response[gen.GetSelfResponse], error) {
	return unary(ctx, req, h.inner.GetSelf)
}
func (h *userConnectHandler) RegisterUser(ctx context.Context, req *connect.Request[gen.RegisterUserRequest]) (*connect.Response[gen.RegisterUserResponse], error) {
	return unary(ctx, req, h.inner.RegisterUser)
}
func (h *userConnectHandler) GetUser(ctx context.Context, req *connect.Request[gen.GetUserRequest]) (*connect.Response[gen.User], error) {
	return unary(ctx, req, h.inner.GetUser)
}
func (h *userConnectHandler) ListUsers(ctx context.Context, req *connect.Request[gen.ListUsersRequest]) (*connect.Response[gen.ListUsersResponse], error) {
	return unary(ctx, req, h.inner.ListUsers)
}
func (h *userConnectHandler) UpdateUser(ctx context.Context, req *connect.Request[gen.UpdateUserRequest]) (*connect.Response[gen.User], error) {
	return unary(ctx, req, h.inner.UpdateUser)
}
func (h *userConnectHandler) DeleteUser(ctx context.Context, req *connect.Request[gen.GetUserRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.DeleteUser)
}
func (h *userConnectHandler) AddIdentity(ctx context.Context, req *connect.Request[gen.AddIdentityRequest]) (*connect.Response[gen.UserIdentity], error) {
	return unary(ctx, req, h.inner.AddIdentity)
}
func (h *userConnectHandler) FindUserByIdentity(ctx context.Context, req *connect.Request[gen.FindUserByIdentityRequest]) (*connect.Response[gen.User], error) {
	return unary(ctx, req, h.inner.FindUserByIdentity)
}
func (h *userConnectHandler) ListUserIdentities(ctx context.Context, req *connect.Request[gen.ListUserIdentitiesRequest]) (*connect.Response[gen.ListUserIdentitiesResponse], error) {
	return unary(ctx, req, h.inner.ListUserIdentities)
}

// ============================================================================
// OrganizationService
// ============================================================================

type orgConnectHandler struct{ inner *OrgServer }

func (h *orgConnectHandler) CreateOrganization(ctx context.Context, req *connect.Request[gen.CreateOrganizationRequest]) (*connect.Response[gen.CreateOrganizationResponse], error) {
	return unary(ctx, req, h.inner.CreateOrganization)
}
func (h *orgConnectHandler) GetOrganization(ctx context.Context, req *connect.Request[gen.GetOrganizationRequest]) (*connect.Response[gen.Organization], error) {
	return unary(ctx, req, h.inner.GetOrganization)
}
func (h *orgConnectHandler) ListOrganizations(ctx context.Context, req *connect.Request[gen.ListOrganizationsRequest]) (*connect.Response[gen.ListOrganizationsResponse], error) {
	return unary(ctx, req, h.inner.ListOrganizations)
}
func (h *orgConnectHandler) AddMember(ctx context.Context, req *connect.Request[gen.AddOrgMemberRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.AddMember)
}
func (h *orgConnectHandler) RemoveMember(ctx context.Context, req *connect.Request[gen.RemoveOrgMemberRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.RemoveMember)
}
func (h *orgConnectHandler) ListMembers(ctx context.Context, req *connect.Request[gen.ListOrgMembersRequest]) (*connect.Response[gen.ListOrgMembersResponse], error) {
	return unary(ctx, req, h.inner.ListMembers)
}
func (h *orgConnectHandler) GetOrgSettings(ctx context.Context, req *connect.Request[gen.GetOrgSettingsRequest]) (*connect.Response[gen.OrgSettings], error) {
	return unary(ctx, req, h.inner.GetOrgSettings)
}
func (h *orgConnectHandler) UpdateOrgSettings(ctx context.Context, req *connect.Request[gen.UpdateOrgSettingsRequest]) (*connect.Response[gen.OrgSettings], error) {
	return unary(ctx, req, h.inner.UpdateOrgSettings)
}
func (h *orgConnectHandler) GetOrganizationSettings(ctx context.Context, req *connect.Request[gen.GetOrganizationSettingsRequest]) (*connect.Response[gen.OrganizationSettings], error) {
	return unary(ctx, req, h.inner.GetOrganizationSettings)
}
func (h *orgConnectHandler) UpdateOrganizationSettings(ctx context.Context, req *connect.Request[gen.UpdateOrganizationSettingsRequest]) (*connect.Response[gen.OrganizationSettings], error) {
	return unary(ctx, req, h.inner.UpdateOrganizationSettings)
}

// ============================================================================
// TeamService
// ============================================================================

type teamConnectHandler struct{ inner *TeamServer }

func (h *teamConnectHandler) CreateTeam(ctx context.Context, req *connect.Request[gen.CreateTeamRequest]) (*connect.Response[gen.CreateTeamResponse], error) {
	return unary(ctx, req, h.inner.CreateTeam)
}
func (h *teamConnectHandler) ListTeams(ctx context.Context, req *connect.Request[gen.ListTeamsRequest]) (*connect.Response[gen.ListTeamsResponse], error) {
	return unary(ctx, req, h.inner.ListTeams)
}
func (h *teamConnectHandler) AddMember(ctx context.Context, req *connect.Request[gen.AddTeamMemberRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.AddMember)
}
func (h *teamConnectHandler) RemoveMember(ctx context.Context, req *connect.Request[gen.RemoveTeamMemberRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.RemoveMember)
}
func (h *teamConnectHandler) ListMembers(ctx context.Context, req *connect.Request[gen.ListTeamMembersRequest]) (*connect.Response[gen.ListTeamMembersResponse], error) {
	return unary(ctx, req, h.inner.ListMembers)
}
func (h *teamConnectHandler) UpdateTeam(ctx context.Context, req *connect.Request[gen.UpdateTeamRequest]) (*connect.Response[gen.UpdateTeamResponse], error) {
	return unary(ctx, req, h.inner.UpdateTeam)
}
func (h *teamConnectHandler) DeleteTeam(ctx context.Context, req *connect.Request[gen.DeleteTeamRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.DeleteTeam)
}

// ============================================================================
// PermissionService
// ============================================================================

type permConnectHandler struct{ inner *PermServer }

func (h *permConnectHandler) CreateRole(ctx context.Context, req *connect.Request[gen.CreateRoleRequest]) (*connect.Response[gen.CreateRoleResponse], error) {
	return unary(ctx, req, h.inner.CreateRole)
}
func (h *permConnectHandler) ListRoles(ctx context.Context, req *connect.Request[gen.ListRolesRequest]) (*connect.Response[gen.ListRolesResponse], error) {
	return unary(ctx, req, h.inner.ListRoles)
}
func (h *permConnectHandler) DeleteRole(ctx context.Context, req *connect.Request[gen.DeleteRoleRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.DeleteRole)
}
func (h *permConnectHandler) AssignRole(ctx context.Context, req *connect.Request[gen.AssignRoleRequest]) (*connect.Response[gen.AssignRoleResponse], error) {
	return unary(ctx, req, h.inner.AssignRole)
}
func (h *permConnectHandler) RevokeRole(ctx context.Context, req *connect.Request[gen.RevokeRoleRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.RevokeRole)
}
func (h *permConnectHandler) ListRoleAssignments(ctx context.Context, req *connect.Request[gen.ListRoleAssignmentsRequest]) (*connect.Response[gen.ListRoleAssignmentsResponse], error) {
	return unary(ctx, req, h.inner.ListRoleAssignments)
}
func (h *permConnectHandler) CheckPermission(ctx context.Context, req *connect.Request[gen.CheckPermissionRequest]) (*connect.Response[gen.CheckPermissionResponse], error) {
	return unary(ctx, req, h.inner.CheckPermission)
}
func (h *permConnectHandler) Decide(ctx context.Context, req *connect.Request[gen.DecideRequest]) (*connect.Response[gen.DecideResponse], error) {
	return unary(ctx, req, h.inner.Decide)
}
func (h *permConnectHandler) CheckAccess(ctx context.Context, req *connect.Request[gen.CheckAccessRequest]) (*connect.Response[gen.CheckAccessResponse], error) {
	return unary(ctx, req, h.inner.CheckAccess)
}
func (h *permConnectHandler) ListAccessibleScopes(ctx context.Context, req *connect.Request[gen.ListAccessibleScopesRequest]) (*connect.Response[gen.ListAccessibleScopesResponse], error) {
	return unary(ctx, req, h.inner.ListAccessibleScopes)
}
func (h *permConnectHandler) RegisterScopeNode(ctx context.Context, req *connect.Request[gen.RegisterScopeNodeRequest]) (*connect.Response[gen.RegisterScopeNodeResponse], error) {
	return unary(ctx, req, h.inner.RegisterScopeNode)
}
func (h *permConnectHandler) GrantScope(ctx context.Context, req *connect.Request[gen.GrantScopeRequest]) (*connect.Response[gen.GrantScopeResponse], error) {
	return unary(ctx, req, h.inner.GrantScope)
}
func (h *permConnectHandler) RevokeScope(ctx context.Context, req *connect.Request[gen.RevokeScopeRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.RevokeScope)
}
func (h *permConnectHandler) ShareRecord(ctx context.Context, req *connect.Request[gen.ShareRecordRequest]) (*connect.Response[gen.ShareRecordResponse], error) {
	return unary(ctx, req, h.inner.ShareRecord)
}
func (h *permConnectHandler) RevokeShare(ctx context.Context, req *connect.Request[gen.RevokeShareRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.RevokeShare)
}
func (h *permConnectHandler) ListShares(ctx context.Context, req *connect.Request[gen.ListSharesRequest]) (*connect.Response[gen.ListSharesResponse], error) {
	return unary(ctx, req, h.inner.ListShares)
}

// ============================================================================
// IntrospectionService
// ============================================================================

type introspectionConnectHandler struct{ inner *IntrospectionServer }

func (h *introspectionConnectHandler) GetServiceInfo(ctx context.Context, req *connect.Request[gen.GetServiceInfoRequest]) (*connect.Response[gen.GetServiceInfoResponse], error) {
	return unary(ctx, req, h.inner.GetServiceInfo)
}

// ============================================================================
// IdentityService
// ============================================================================

type identConnectHandler struct{ inner *IdentServer }

func (h *identConnectHandler) ResolveIdentity(ctx context.Context, req *connect.Request[gen.ResolveIdentityRequest]) (*connect.Response[gen.ResolveIdentityResponse], error) {
	return unary(ctx, req, h.inner.ResolveIdentity)
}

// ============================================================================
// APIKeyService
// ============================================================================

type apiKeyConnectHandler struct{ inner *APIKeyServer }

func (h *apiKeyConnectHandler) CreateAPIKey(ctx context.Context, req *connect.Request[gen.CreateAPIKeyRequest]) (*connect.Response[gen.CreateAPIKeyResponse], error) {
	return unary(ctx, req, h.inner.CreateAPIKey)
}
func (h *apiKeyConnectHandler) ListAPIKeys(ctx context.Context, req *connect.Request[gen.ListAPIKeysRequest]) (*connect.Response[gen.ListAPIKeysResponse], error) {
	return unary(ctx, req, h.inner.ListAPIKeys)
}
func (h *apiKeyConnectHandler) RevokeAPIKey(ctx context.Context, req *connect.Request[gen.RevokeAPIKeyRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.RevokeAPIKey)
}
func (h *apiKeyConnectHandler) ValidateAPIKey(ctx context.Context, req *connect.Request[gen.ValidateAPIKeyRequest]) (*connect.Response[gen.ValidateAPIKeyResponse], error) {
	return unary(ctx, req, h.inner.ValidateAPIKey)
}

// ============================================================================
// AuthService
// ============================================================================

type authConnectHandler struct{ inner *AuthServer }

// headerJWTLoginHeader names the gateway-injected identity header consumed by
// the login route under IDENTITY_PROVIDER=header-jwt. Empty for every other
// provider. Set once at startup from work.go. The header is read here and
// nowhere else — it is never copied into gRPC metadata (see connectCtx), so it
// cannot be forwarded downstream.
var headerJWTLoginHeader string

// SetHeaderJWTLoginHeader installs the configured identity header name. Empty
// disables header consumption. Idempotent; call before serving.
func SetHeaderJWTLoginHeader(name string) { headerJWTLoginHeader = name }

func (h *authConnectHandler) BeginOAuth(ctx context.Context, req *connect.Request[gen.BeginOAuthRequest]) (*connect.Response[gen.BeginOAuthResponse], error) {
	return unary(ctx, req, h.inner.BeginOAuth)
}

func (h *authConnectHandler) Authenticate(ctx context.Context, req *connect.Request[gen.AuthenticateRequest]) (*connect.Response[gen.AuthenticateResponse], error) {
	injectHeaderJWTCredential(req.Msg, req.Header())
	return unary(ctx, req, h.inner.Authenticate)
}

// injectHeaderJWTCredential turns a gateway-injected identity header into the
// header-jwt login credential. When the header is configured and present, it is
// authoritative: the token is verified against the configured JWKS downstream,
// so this simply forwards the header's value into the request the login flow
// already understands. A no-op when no header is configured or none is present.
func injectHeaderJWTCredential(req *gen.AuthenticateRequest, h http.Header) {
	if headerJWTLoginHeader == "" || req == nil {
		return
	}
	// In header-jwt mode the gateway-injected header is the ONLY trusted
	// credential source. Drop any client-supplied credential before setting
	// from the header, so a caller cannot smuggle a second credential in the
	// request body — including when the trusted header is absent.
	req.Authentication = nil
	token := h.Get(headerJWTLoginHeader)
	if token == "" {
		return
	}
	req.Authentication = &gen.AuthenticateRequest_HeaderJwt{
		HeaderJwt: &gen.HeaderJWTAuthentication{Token: token},
	}
}
func (h *authConnectHandler) CompleteMFAChallenge(ctx context.Context, req *connect.Request[gen.CompleteMFAChallengeRequest]) (*connect.Response[gen.CompleteMFAChallengeResponse], error) {
	return unary(ctx, req, h.inner.CompleteMFAChallenge)
}
func (h *authConnectHandler) BeginWebAuthnMFAChallenge(ctx context.Context, req *connect.Request[gen.BeginWebAuthnMFAChallengeRequest]) (*connect.Response[gen.BeginWebAuthnMFAChallengeResponse], error) {
	return unary(ctx, req, h.inner.BeginWebAuthnMFAChallenge)
}
func (h *authConnectHandler) CompleteWebAuthnMFAChallenge(ctx context.Context, req *connect.Request[gen.CompleteWebAuthnMFAChallengeRequest]) (*connect.Response[gen.CompleteMFAChallengeResponse], error) {
	return unary(ctx, req, h.inner.CompleteWebAuthnMFAChallenge)
}
func (h *authConnectHandler) RefreshToken(ctx context.Context, req *connect.Request[gen.RefreshTokenRequest]) (*connect.Response[gen.RefreshTokenResponse], error) {
	return unary(ctx, req, h.inner.RefreshToken)
}
func (h *authConnectHandler) SwitchOrganization(ctx context.Context, req *connect.Request[gen.SwitchOrganizationRequest]) (*connect.Response[gen.SwitchOrganizationResponse], error) {
	return unary(ctx, req, h.inner.SwitchOrganization)
}
func (h *authConnectHandler) Logout(ctx context.Context, req *connect.Request[gen.LogoutRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.Logout)
}
func (h *authConnectHandler) GetJWKS(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[gen.JWKSResponse], error) {
	return unary(ctx, req, h.inner.GetJWKS)
}

// ============================================================================
// AuditService
// ============================================================================

type auditConnectHandler struct{ inner *AuditServer }

func (h *auditConnectHandler) QueryAuditLog(ctx context.Context, req *connect.Request[gen.QueryAuditLogRequest]) (*connect.Response[gen.QueryAuditLogResponse], error) {
	return unary(ctx, req, h.inner.QueryAuditLog)
}
func (h *auditConnectHandler) ExportAuditLog(ctx context.Context, req *connect.Request[gen.ExportAuditLogRequest]) (*connect.Response[gen.ExportAuditLogResponse], error) {
	return unary(ctx, req, h.inner.ExportAuditLog)
}
func (h *auditConnectHandler) AggregateAuditLog(ctx context.Context, req *connect.Request[gen.AggregateAuditLogRequest]) (*connect.Response[gen.AggregateAuditLogResponse], error) {
	return unary(ctx, req, h.inner.AggregateAuditLog)
}
func (h *auditConnectHandler) ListAuditEventTypes(ctx context.Context, req *connect.Request[gen.ListAuditEventTypesRequest]) (*connect.Response[gen.ListAuditEventTypesResponse], error) {
	return unary(ctx, req, h.inner.ListAuditEventTypes)
}

// ============================================================================
// InvitationService
// ============================================================================

type invitationConnectHandler struct{ inner *InvitationServer }

func (h *invitationConnectHandler) CreateInvitation(ctx context.Context, req *connect.Request[gen.CreateInvitationRequest]) (*connect.Response[gen.CreateInvitationResponse], error) {
	return unary(ctx, req, h.inner.CreateInvitation)
}
func (h *invitationConnectHandler) InspectInvitation(ctx context.Context, req *connect.Request[gen.InspectInvitationRequest]) (*connect.Response[gen.InvitationSummary], error) {
	return unary(ctx, req, h.inner.InspectInvitation)
}
func (h *invitationConnectHandler) InspectInvitationById(ctx context.Context, req *connect.Request[gen.InspectInvitationByIdRequest]) (*connect.Response[gen.InvitationSummary], error) {
	return unary(ctx, req, h.inner.InspectInvitationById)
}
func (h *invitationConnectHandler) AcceptInvitation(ctx context.Context, req *connect.Request[gen.AcceptInvitationRequest]) (*connect.Response[gen.AcceptInvitationResponse], error) {
	return unary(ctx, req, h.inner.AcceptInvitation)
}
func (h *invitationConnectHandler) ListInvitations(ctx context.Context, req *connect.Request[gen.ListInvitationsRequest]) (*connect.Response[gen.ListInvitationsResponse], error) {
	return unary(ctx, req, h.inner.ListInvitations)
}
func (h *invitationConnectHandler) RevokeInvitation(ctx context.Context, req *connect.Request[gen.RevokeInvitationRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.RevokeInvitation)
}
func (h *invitationConnectHandler) ResendInvitation(ctx context.Context, req *connect.Request[gen.ResendInvitationRequest]) (*connect.Response[gen.Invitation], error) {
	return unary(ctx, req, h.inner.ResendInvitation)
}

// ============================================================================
// PlatformAdminService
// ============================================================================

type platformAdminConnectHandler struct{ inner *PlatformAdminServer }

func (h *platformAdminConnectHandler) SearchUsers(ctx context.Context, req *connect.Request[gen.SearchUsersRequest]) (*connect.Response[gen.SearchUsersResponse], error) {
	return unary(ctx, req, h.inner.SearchUsers)
}
func (h *platformAdminConnectHandler) SuspendUser(ctx context.Context, req *connect.Request[gen.SuspendUserRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.SuspendUser)
}
func (h *platformAdminConnectHandler) UnsuspendUser(ctx context.Context, req *connect.Request[gen.UnsuspendUserRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.UnsuspendUser)
}
func (h *platformAdminConnectHandler) ImpersonateUser(ctx context.Context, req *connect.Request[gen.ImpersonateUserRequest]) (*connect.Response[gen.ImpersonateUserResponse], error) {
	return unary(ctx, req, h.inner.ImpersonateUser)
}
func (h *platformAdminConnectHandler) ListActiveSessions(ctx context.Context, req *connect.Request[gen.ListActiveSessionsRequest]) (*connect.Response[gen.ListActiveSessionsResponse], error) {
	return unary(ctx, req, h.inner.ListActiveSessions)
}
func (h *platformAdminConnectHandler) RevokeSession(ctx context.Context, req *connect.Request[gen.RevokeSessionRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.RevokeSession)
}
func (h *platformAdminConnectHandler) GetOrgEntitlements(ctx context.Context, req *connect.Request[gen.GetOrgEntitlementsRequest]) (*connect.Response[gen.GetOrgEntitlementsResponse], error) {
	return unary(ctx, req, h.inner.GetOrgEntitlements)
}
func (h *platformAdminConnectHandler) OverrideEntitlement(ctx context.Context, req *connect.Request[gen.OverrideEntitlementRequest]) (*connect.Response[gen.OverrideEntitlementResponse], error) {
	return unary(ctx, req, h.inner.OverrideEntitlement)
}
func (h *platformAdminConnectHandler) GrantPlatformRole(ctx context.Context, req *connect.Request[gen.GrantPlatformRoleRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.GrantPlatformRole)
}
func (h *platformAdminConnectHandler) RevokePlatformRole(ctx context.Context, req *connect.Request[gen.RevokePlatformRoleRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.RevokePlatformRole)
}
func (h *platformAdminConnectHandler) ListPlatformAdmins(ctx context.Context, req *connect.Request[gen.ListPlatformAdminsRequest]) (*connect.Response[gen.ListPlatformAdminsResponse], error) {
	return unary(ctx, req, h.inner.ListPlatformAdmins)
}
func (h *platformAdminConnectHandler) ListFeatureFlags(ctx context.Context, req *connect.Request[gen.ListFeatureFlagsRequest]) (*connect.Response[gen.ListFeatureFlagsResponse], error) {
	return unary(ctx, req, h.inner.ListFeatureFlags)
}
func (h *platformAdminConnectHandler) UpsertFeatureFlag(ctx context.Context, req *connect.Request[gen.UpsertFeatureFlagRequest]) (*connect.Response[gen.UpsertFeatureFlagResponse], error) {
	return unary(ctx, req, h.inner.UpsertFeatureFlag)
}
func (h *platformAdminConnectHandler) GetJobOperations(ctx context.Context, req *connect.Request[jobsv1.GetJobOperationsRequest]) (*connect.Response[jobsv1.GetJobOperationsResponse], error) {
	return unary(ctx, req, h.inner.GetJobOperations)
}

func (h *platformAdminConnectHandler) GetEventOperations(ctx context.Context, req *connect.Request[eventsv1.GetEventOperationsRequest]) (*connect.Response[eventsv1.GetEventOperationsResponse], error) {
	return unary(ctx, req, h.inner.GetEventOperations)
}

func (h *platformAdminConnectHandler) ListEventSubscriptions(ctx context.Context, req *connect.Request[eventsv1.ListEventSubscriptionsRequest]) (*connect.Response[eventsv1.ListEventSubscriptionsResponse], error) {
	return unary(ctx, req, h.inner.ListEventSubscriptions)
}
func (h *platformAdminConnectHandler) ListJobs(ctx context.Context, req *connect.Request[jobsv1.ListJobsRequest]) (*connect.Response[jobsv1.ListJobsResponse], error) {
	return unary(ctx, req, h.inner.ListJobs)
}
func (h *platformAdminConnectHandler) GetJob(ctx context.Context, req *connect.Request[jobsv1.GetJobRequest]) (*connect.Response[jobsv1.GetJobResponse], error) {
	return unary(ctx, req, h.inner.GetJob)
}
func (h *platformAdminConnectHandler) ReplayJob(ctx context.Context, req *connect.Request[jobsv1.ReplayJobRequest]) (*connect.Response[jobsv1.ReplayJobResponse], error) {
	return unary(ctx, req, h.inner.ReplayJob)
}

// ============================================================================
// UsageService
// ============================================================================

type usageConnectHandler struct{ inner *UsageServer }

func (h *usageConnectHandler) ConsumeUsage(ctx context.Context, req *connect.Request[gen.ConsumeUsageRequest]) (*connect.Response[gen.ConsumeUsageResponse], error) {
	return unary(ctx, req, h.inner.ConsumeUsage)
}

func (h *usageConnectHandler) GetUsage(ctx context.Context, req *connect.Request[gen.GetUsageRequest]) (*connect.Response[gen.GetUsageResponse], error) {
	return unary(ctx, req, h.inner.GetUsage)
}

func (h *usageConnectHandler) ListUsageMeters(ctx context.Context, req *connect.Request[gen.ListUsageMetersRequest]) (*connect.Response[gen.ListUsageMetersResponse], error) {
	return unary(ctx, req, h.inner.ListUsageMeters)
}

func (h *usageConnectHandler) GetUsageHistory(ctx context.Context, req *connect.Request[gen.GetUsageHistoryRequest]) (*connect.Response[gen.GetUsageHistoryResponse], error) {
	return unary(ctx, req, h.inner.GetUsageHistory)
}

// ============================================================================
// WebhookService — backed by business.Service, no gRPC Server struct yet.
// Secret is server-generated, encrypted at rest, and revealed only in the
// CreateSubscription response.
// ============================================================================

type webhookConnectHandler struct{ svc *business.Service }

func (h *webhookConnectHandler) CreateSubscription(ctx context.Context, req *connect.Request[gen.CreateWebhookSubscriptionRequest]) (*connect.Response[gen.WebhookSubscription], error) {
	ctx = connectCtx(ctx, req.Header())
	if err := requireScope(ctx, "webhooks:write"); err != nil {
		return nil, translateGRPCError(err)
	}
	actorID, err := requireAuth(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	if err := requireOrgAdmin(ctx, actorID, req.Msg.OrgId); err != nil {
		return nil, translateGRPCError(err)
	}
	actor, err := verifiedActor(ctx, actorID)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	sub, err := h.svc.CreateSubscription(ctx, actor, req.Msg.OrgId, req.Msg.Url, req.Msg.Events, req.Msg.Description)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(webhookSubToProto(sub)), nil
}

func (h *webhookConnectHandler) DeleteSubscription(ctx context.Context, req *connect.Request[gen.DeleteWebhookSubscriptionRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx = connectCtx(ctx, req.Header())
	if err := requireScope(ctx, "webhooks:write"); err != nil {
		return nil, translateGRPCError(err)
	}
	actorID, err := requireAuth(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	orgID := callerOrg(ctx)
	if err := requireOrgAdmin(ctx, actorID, orgID); err != nil {
		return nil, translateGRPCError(err)
	}
	actor, err := verifiedActor(ctx, actorID)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	if err := h.svc.DeleteSubscription(ctx, actor, orgID, req.Msg.Id); err != nil {
		return nil, err
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (h *webhookConnectHandler) ListSubscriptions(ctx context.Context, req *connect.Request[gen.ListWebhookSubscriptionsRequest]) (*connect.Response[gen.ListWebhookSubscriptionsResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	if err := requireScope(ctx, "webhooks:read"); err != nil {
		return nil, translateGRPCError(err)
	}
	actorID, err := requireAuth(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	if err := requireOrgMember(ctx, actorID, req.Msg.OrgId); err != nil {
		return nil, translateGRPCError(err)
	}
	subs, err := h.svc.ListSubscriptions(ctx, req.Msg.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]*gen.WebhookSubscription, 0, len(subs))
	for _, s := range subs {
		out = append(out, webhookSubToProto(s))
	}
	return connect.NewResponse(&gen.ListWebhookSubscriptionsResponse{Subscriptions: out}), nil
}

func (h *webhookConnectHandler) ListDeliveries(ctx context.Context, req *connect.Request[gen.ListWebhookDeliveriesRequest]) (*connect.Response[gen.ListWebhookDeliveriesResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	if err := requireScope(ctx, "webhooks:read"); err != nil {
		return nil, translateGRPCError(err)
	}
	actorID, err := requireAuth(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	orgID := callerOrg(ctx)
	if err := requireOrgMember(ctx, actorID, orgID); err != nil {
		return nil, translateGRPCError(err)
	}
	pageSize := int(req.Msg.PageSize)
	if pageSize == 0 {
		pageSize = 50
	}
	deliveries, err := h.svc.ListDeliveries(ctx, orgID, req.Msg.SubscriptionId, pageSize)
	if err != nil {
		return nil, err
	}
	out := make([]*gen.WebhookDelivery, 0, len(deliveries))
	for _, d := range deliveries {
		out = append(out, webhookDeliveryToProto(d))
	}
	return connect.NewResponse(&gen.ListWebhookDeliveriesResponse{Deliveries: out}), nil
}

func (h *webhookConnectHandler) TestWebhook(ctx context.Context, req *connect.Request[gen.TestWebhookRequest]) (*connect.Response[gen.WebhookDelivery], error) {
	ctx = connectCtx(ctx, req.Header())
	if err := requireScope(ctx, "webhooks:write"); err != nil {
		return nil, translateGRPCError(err)
	}
	actorID, err := requireAuth(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	orgID := callerOrg(ctx)
	if err := requireOrgAdmin(ctx, actorID, orgID); err != nil {
		return nil, translateGRPCError(err)
	}
	d, err := h.svc.TestWebhook(ctx, orgID, req.Msg.Id, req.Msg.EventType)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(webhookDeliveryToProto(d)), nil
}

// GetDelivery returns the full delivery row including response body
// — used by the deliveries detail panel on row-click. List endpoint
// returns the same shape so this is mostly an explicit fetch when
// the FE wants a fresh read after a replay or a status change.
func (h *webhookConnectHandler) GetDelivery(ctx context.Context, req *connect.Request[gen.GetWebhookDeliveryRequest]) (*connect.Response[gen.WebhookDelivery], error) {
	ctx = connectCtx(ctx, req.Header())
	if err := requireScope(ctx, "webhooks:read"); err != nil {
		return nil, translateGRPCError(err)
	}
	actorID, err := requireAuth(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	orgID := callerOrg(ctx)
	if err := requireOrgMember(ctx, actorID, orgID); err != nil {
		return nil, translateGRPCError(err)
	}
	d, err := h.svc.GetWebhookDelivery(ctx, orgID, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(webhookDeliveryToProto(d)), nil
}

// ReplayDelivery re-fires an existing delivery's payload at the
// current subscription URL. Returns the new delivery row so the FE
// can show outcome immediately. Authz: caller must be org-admin on
// the original delivery's subscription org.
func (h *webhookConnectHandler) ReplayDelivery(ctx context.Context, req *connect.Request[gen.ReplayWebhookDeliveryRequest]) (*connect.Response[gen.WebhookDelivery], error) {
	ctx = connectCtx(ctx, req.Header())
	if err := requireScope(ctx, "webhooks:write"); err != nil {
		return nil, translateGRPCError(err)
	}
	actorID, err := requireAuth(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	orgID := callerOrg(ctx)
	if err := requireOrgAdmin(ctx, actorID, orgID); err != nil {
		return nil, translateGRPCError(err)
	}
	actor, err := verifiedActor(ctx, actorID)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	d, err := h.svc.ReplayWebhookDelivery(ctx, actor, orgID, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(webhookDeliveryToProto(d)), nil
}

// RotateSecret generates a new HMAC signing secret. The secret is
// returned ONCE in the response — the FE shows it with a copy
// button and a warning that this is the last chance to grab it.
//
// Sensitive op: gated by requireMFA (consumer endpoints can be
// hijacked if an attacker rotates and re-signs; same blast radius as
// rotating an API key).
func (h *webhookConnectHandler) RotateSecret(ctx context.Context, req *connect.Request[gen.RotateWebhookSecretRequest]) (*connect.Response[gen.RotateWebhookSecretResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	if err := requireScope(ctx, "webhooks:write"); err != nil {
		return nil, translateGRPCError(err)
	}
	actorID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireRecentMFA(ctx); err != nil {
		return nil, err
	}
	orgID := callerOrg(ctx)
	if err := requireOrgAdmin(ctx, actorID, orgID); err != nil {
		return nil, translateGRPCError(err)
	}
	gracePeriod := time.Duration(req.Msg.GracePeriodSeconds) * time.Second
	actor, err := verifiedActor(ctx, actorID)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	secret, oldSecretExpiresAt, err := h.svc.RotateWebhookSecret(ctx, actor, orgID, req.Msg.Id, gracePeriod)
	if err != nil {
		return nil, err
	}
	resp := &gen.RotateWebhookSecretResponse{Secret: secret}
	if oldSecretExpiresAt != nil {
		resp.OldSecretExpiresAt = timestamppb.New(*oldSecretExpiresAt)
	}
	return connect.NewResponse(resp), nil
}

// ============================================================================
// NotificationService — backed by business.Service.
// Caller identity comes from auth headers.
// ============================================================================

type notificationConnectHandler struct{ svc *business.Service }

func (h *notificationConnectHandler) ListNotifications(ctx context.Context, req *connect.Request[gen.ListNotificationsRequest]) (*connect.Response[gen.ListNotificationsResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	pageSize := int(req.Msg.PageSize)
	if pageSize == 0 {
		pageSize = 50
	}
	notes, nextToken, err := h.svc.ListNotifications(ctx, userID, pageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := make([]*gen.Notification, 0, len(notes))
	for _, n := range notes {
		out = append(out, notificationToProto(n))
	}
	return connect.NewResponse(&gen.ListNotificationsResponse{Notifications: out, NextPageToken: nextToken}), nil
}

func (h *notificationConnectHandler) GetUnreadCount(ctx context.Context, req *connect.Request[gen.GetUnreadCountRequest]) (*connect.Response[gen.GetUnreadCountResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	count, err := h.svc.GetUnreadCount(ctx, userID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&gen.GetUnreadCountResponse{Count: int32(count)}), nil
}

func (h *notificationConnectHandler) MarkRead(ctx context.Context, req *connect.Request[gen.MarkNotificationReadRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	if err := h.svc.MarkRead(ctx, userID, req.Msg.Id); err != nil {
		return nil, err
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (h *notificationConnectHandler) MarkAllRead(ctx context.Context, req *connect.Request[gen.MarkAllNotificationsReadRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.MarkAllRead(ctx, userID); err != nil {
		return nil, err
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (h *notificationConnectHandler) DeleteNotification(ctx context.Context, req *connect.Request[gen.DeleteNotificationRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	if err := h.svc.DeleteNotification(ctx, userID, req.Msg.Id); err != nil {
		return nil, err
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// ResolveNotificationAction re-authorizes a deep link as it is followed. A
// notification the caller may no longer reach is NOT_FOUND, never denied, so an
// id substitution and a revoked resource look the same from outside.
func (h *notificationConnectHandler) ResolveNotificationAction(ctx context.Context, req *connect.Request[gen.ResolveNotificationActionRequest]) (*connect.Response[gen.ResolveNotificationActionResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	actionURL, err := h.svc.ResolveNotificationAction(ctx, userID, req.Msg.Id)
	if err != nil {
		if errors.Is(err, business.ErrNotificationNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, translateGRPCError(err)
	}
	return connect.NewResponse(&gen.ResolveNotificationActionResponse{ActionUrl: actionURL}), nil
}

// ============================================================================
// ResourceFollowService — backed by business.Service.
// Caller identity comes from auth headers; neither request carries a subject.
// ============================================================================

type resourceFollowConnectHandler struct{ svc *business.Service }

func (h *resourceFollowConnectHandler) Follow(ctx context.Context, req *connect.Request[gen.FollowResourceRequest]) (*connect.Response[gen.FollowResourceResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	orgID := callerOrg(ctx)
	if err := requireOrgMember(ctx, userID, orgID); err != nil {
		return nil, err
	}
	follow, err := h.svc.Follow(ctx, userID, orgID, req.Msg.ResourceType, req.Msg.ResourceId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&gen.FollowResourceResponse{Id: follow.ID}), nil
}

func (h *resourceFollowConnectHandler) Unfollow(ctx context.Context, req *connect.Request[gen.UnfollowResourceRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	orgID := callerOrg(ctx)
	if err := requireOrgMember(ctx, userID, orgID); err != nil {
		return nil, err
	}
	if err := h.svc.Unfollow(ctx, userID, req.Msg.ResourceType, req.Msg.ResourceId); err != nil {
		return nil, err
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// ============================================================================
// OnboardingService — backed by business.Service.
// ============================================================================

type onboardingConnectHandler struct{ svc *business.Service }

func (h *onboardingConnectHandler) GetProgress(ctx context.Context, req *connect.Request[gen.GetOnboardingProgressRequest]) (*connect.Response[gen.OnboardingProgress], error) {
	ctx = connectCtx(ctx, req.Header())
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgMember(ctx, userID, req.Msg.OrganizationId); err != nil {
		return nil, translateGRPCError(err)
	}
	p, err := h.svc.GetProgress(ctx, userID, req.Msg.OrganizationId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(onboardingToProto(p)), nil
}

func (h *onboardingConnectHandler) CompleteStep(ctx context.Context, req *connect.Request[gen.CompleteOnboardingStepRequest]) (*connect.Response[gen.OnboardingProgress], error) {
	ctx = connectCtx(ctx, req.Header())
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgMember(ctx, userID, req.Msg.OrganizationId); err != nil {
		return nil, translateGRPCError(err)
	}
	if err := h.svc.CompleteStep(ctx, userID, req.Msg.OrganizationId, req.Msg.StepId); err != nil {
		return nil, err
	}
	p, err := h.svc.GetProgress(ctx, userID, req.Msg.OrganizationId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(onboardingToProto(p)), nil
}

func (h *onboardingConnectHandler) SkipStep(ctx context.Context, req *connect.Request[gen.SkipOnboardingStepRequest]) (*connect.Response[gen.OnboardingProgress], error) {
	ctx = connectCtx(ctx, req.Header())
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgMember(ctx, userID, req.Msg.OrganizationId); err != nil {
		return nil, translateGRPCError(err)
	}
	if err := h.svc.SkipStep(ctx, userID, req.Msg.OrganizationId, req.Msg.StepId, req.Msg.Reason); err != nil {
		return nil, err
	}
	p, err := h.svc.GetProgress(ctx, userID, req.Msg.OrganizationId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(onboardingToProto(p)), nil
}

// ============================================================================
// GDPRService — backed by business.Service.
// ============================================================================

type gdprConnectHandler struct{ svc *business.Service }

func (h *gdprConnectHandler) RequestExport(ctx context.Context, req *connect.Request[gen.RequestDataExportRequest]) (*connect.Response[gen.GDPRRequest], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.RequestExport(ctx, userID)
	if err != nil {
		return nil, translateGRPCError(privacyStatusError(err))
	}
	return connect.NewResponse(gdprToProto(r)), nil
}

func (h *gdprConnectHandler) GetExportStatus(ctx context.Context, req *connect.Request[gen.GetExportStatusRequest]) (*connect.Response[gen.GDPRRequest], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	r, err := h.svc.GetExportStatus(ctx, userID, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(gdprToProto(r)), nil
}

func (h *gdprConnectHandler) RequestDeletion(ctx context.Context, req *connect.Request[gen.RequestDeletionRequest]) (*connect.Response[gen.GDPRRequest], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	// GDPR deletion is irreversible — gate behind MFA when enrolled.
	if err := requireMFA(ctx, userID); err != nil {
		return nil, err
	}
	r, err := h.svc.RequestDeletion(ctx, userID)
	if err != nil {
		return nil, translateGRPCError(privacyStatusError(err))
	}
	return connect.NewResponse(gdprToProto(r)), nil
}

func (h *gdprConnectHandler) GetDeletionStatus(ctx context.Context, req *connect.Request[gen.GetDeletionStatusRequest]) (*connect.Response[gen.GDPRRequest], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	r, err := h.svc.GetDeletionStatus(ctx, userID, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(gdprToProto(r)), nil
}

// ============================================================================
// MFAService — backed by business.Service.
// ============================================================================

type mfaConnectHandler struct{ svc *business.Service }

func (h *mfaConnectHandler) BeginWebAuthnRegistration(ctx context.Context, req *connect.Request[gen.BeginWebAuthnRegistrationRequest]) (*connect.Response[gen.BeginWebAuthnRegistrationResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, translateGRPCError(err)
	}
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	ceremonyToken, optionsJSON, err := h.svc.BeginWebAuthnRegistration(ctx, userID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&gen.BeginWebAuthnRegistrationResponse{
		CeremonyToken:        ceremonyToken,
		PublicKeyOptionsJson: optionsJSON,
	}), nil
}

func (h *mfaConnectHandler) FinishWebAuthnRegistration(ctx context.Context, req *connect.Request[gen.FinishWebAuthnRegistrationRequest]) (*connect.Response[gen.FinishWebAuthnRegistrationResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, translateGRPCError(err)
	}
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	device, err := h.svc.FinishWebAuthnRegistration(ctx, userID, req.Msg.CeremonyToken, req.Msg.CredentialResponseJson, req.Msg.Name)
	if errors.Is(err, business.ErrWebAuthnCeremonyRejected) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("WebAuthn ceremony rejected"))
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&gen.FinishWebAuthnRegistrationResponse{Device: mfaDeviceToProto(device)}), nil
}

func (h *mfaConnectHandler) SetupTOTP(ctx context.Context, req *connect.Request[gen.SetupTOTPRequest]) (*connect.Response[gen.SetupTOTPResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	secret, uri, err := h.svc.SetupTOTP(ctx, userID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&gen.SetupTOTPResponse{Secret: secret, ProvisioningUri: uri}), nil
}

func (h *mfaConnectHandler) VerifyTOTP(ctx context.Context, req *connect.Request[gen.VerifyTOTPRequest]) (*connect.Response[gen.VerifyTOTPResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.VerifyTOTP(ctx, userID, req.Msg.Code); err != nil {
		return connect.NewResponse(&gen.VerifyTOTPResponse{Valid: false}), nil
	}
	return connect.NewResponse(&gen.VerifyTOTPResponse{Valid: true}), nil
}

func (h *mfaConnectHandler) ListDevices(ctx context.Context, req *connect.Request[gen.ListMFADevicesRequest]) (*connect.Response[gen.ListMFADevicesResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	devices, err := h.svc.ListMFADevices(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*gen.MFADevice, 0, len(devices))
	for _, d := range devices {
		out = append(out, mfaDeviceToProto(d))
	}
	return connect.NewResponse(&gen.ListMFADevicesResponse{Devices: out}), nil
}

func (h *mfaConnectHandler) RevokeDevice(ctx context.Context, req *connect.Request[gen.RevokeMFADeviceRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.RevokeMFADevice(ctx, userID, req.Msg.Id); err != nil {
		return nil, err
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (h *mfaConnectHandler) GenerateBackupCodes(ctx context.Context, req *connect.Request[gen.GenerateBackupCodesRequest]) (*connect.Response[gen.GenerateBackupCodesResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	userID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	codes, err := h.svc.GenerateBackupCodes(ctx, userID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&gen.GenerateBackupCodesResponse{BackupCodes: codes}), nil
}

// ============================================================================
// business ↔ proto mappers
// ============================================================================

func webhookSubToProto(s *business.WebhookSubscription) *gen.WebhookSubscription {
	if s == nil {
		return nil
	}
	out := &gen.WebhookSubscription{
		Id:          s.ID,
		OrgId:       s.OrgID,
		Url:         s.URL,
		Events:      s.Events,
		Active:      s.Active,
		Description: s.Description,
		Secret:      s.SecretReveal,
	}
	if !s.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(s.CreatedAt)
	}
	return out
}

func webhookDeliveryToProto(d *business.WebhookDelivery) *gen.WebhookDelivery {
	if d == nil {
		return nil
	}
	out := &gen.WebhookDelivery{
		Id:             d.ID,
		SubscriptionId: d.SubscriptionID,
		EventType:      d.EventType,
		Payload:        d.Payload,
		Attempts:       int32(d.AttemptCount),
		HttpStatus:     int32(d.HTTPStatus),
		Status:         webhookDeliveryStatusToProto(d.Status),
		ResponseBody:   d.ResponseBody,
		EventId:        d.EventID,
	}
	if !d.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(d.CreatedAt)
	}
	if d.LastAttemptAt != nil {
		out.LastAttemptAt = timestamppb.New(*d.LastAttemptAt)
	}
	if d.DeliveredAt != nil {
		out.DeliveredAt = timestamppb.New(*d.DeliveredAt)
	}
	return out
}

func webhookDeliveryStatusToProto(s string) gen.WebhookDeliveryStatus {
	switch s {
	case "delivered", "success":
		return gen.WebhookDeliveryStatus_WEBHOOK_DELIVERY_STATUS_SUCCESS
	case "failed":
		return gen.WebhookDeliveryStatus_WEBHOOK_DELIVERY_STATUS_FAILED
	case "pending":
		return gen.WebhookDeliveryStatus_WEBHOOK_DELIVERY_STATUS_PENDING
	}
	return gen.WebhookDeliveryStatus_WEBHOOK_DELIVERY_STATUS_UNSPECIFIED
}

func notificationToProto(n *business.Notification) *gen.Notification {
	if n == nil {
		return nil
	}
	out := &gen.Notification{
		Id:        n.ID,
		UserId:    n.UserID,
		OrgId:     n.OrgID,
		Title:     n.Title,
		Body:      n.Body,
		Type:      n.Type,
		ActionUrl: n.ActionURL,
	}
	if !n.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(n.CreatedAt)
	}
	if n.ReadAt != nil {
		out.ReadAt = timestamppb.New(*n.ReadAt)
	}
	return out
}

func onboardingToProto(p *business.OnboardingProgress) *gen.OnboardingProgress {
	if p == nil {
		return &gen.OnboardingProgress{}
	}
	steps := make([]*gen.OnboardingStep, 0, len(p.Steps))
	for _, s := range p.Steps {
		step := &gen.OnboardingStep{
			Id:               s.ID,
			Status:           onboardingStepStatusToProto(s.Status),
			Required:         s.Required,
			Prerequisites:    append([]gen.OnboardingStepId(nil), s.Prerequisites...),
			CompletionMethod: onboardingCompletionMethodToProto(s.CompletionMethod),
			SkipReason:       s.SkipReason,
		}
		if !s.FirstSeenAt.IsZero() {
			step.FirstSeenAt = timestamppb.New(s.FirstSeenAt)
		}
		if !s.LastSeenAt.IsZero() {
			step.LastSeenAt = timestamppb.New(s.LastSeenAt)
		}
		if s.CompletedAt != nil {
			step.CompletedAt = timestamppb.New(*s.CompletedAt)
		}
		if s.SkippedAt != nil {
			step.SkippedAt = timestamppb.New(*s.SkippedAt)
		}
		steps = append(steps, step)
	}
	out := &gen.OnboardingProgress{
		OrganizationId:     p.OrganizationID,
		FlowId:             p.FlowID,
		FlowVersion:        p.FlowVersion,
		Variant:            p.Variant,
		Audience:           p.Audience,
		Persona:            p.Persona,
		Steps:              steps,
		CurrentStep:        p.CurrentStep,
		NextStep:           p.NextStep,
		RequiredComplete:   p.RequiredComplete,
		ChecklistComplete:  p.ChecklistComplete,
		ActivationAchieved: p.ActivationAchieved,
	}
	if p.StartedAt != nil {
		out.StartedAt = timestamppb.New(*p.StartedAt)
	}
	if p.CompletedAt != nil {
		out.CompletedAt = timestamppb.New(*p.CompletedAt)
	}
	if p.ActivatedAt != nil {
		out.ActivatedAt = timestamppb.New(*p.ActivatedAt)
	}
	return out
}

func onboardingStepStatusToProto(s string) gen.OnboardingStepStatus {
	switch s {
	case "pending":
		return gen.OnboardingStepStatus_ONBOARDING_STEP_STATUS_PENDING
	case "completed":
		return gen.OnboardingStepStatus_ONBOARDING_STEP_STATUS_COMPLETED
	case "skipped":
		return gen.OnboardingStepStatus_ONBOARDING_STEP_STATUS_SKIPPED
	}
	return gen.OnboardingStepStatus_ONBOARDING_STEP_STATUS_UNSPECIFIED
}

func onboardingCompletionMethodToProto(s string) gen.OnboardingCompletionMethod {
	switch s {
	case "detected":
		return gen.OnboardingCompletionMethod_ONBOARDING_COMPLETION_METHOD_DETECTED
	case "domain_action":
		return gen.OnboardingCompletionMethod_ONBOARDING_COMPLETION_METHOD_DOMAIN_ACTION
	case "user_skip":
		return gen.OnboardingCompletionMethod_ONBOARDING_COMPLETION_METHOD_USER_SKIP
	case "migrated":
		return gen.OnboardingCompletionMethod_ONBOARDING_COMPLETION_METHOD_MIGRATED
	default:
		return gen.OnboardingCompletionMethod_ONBOARDING_COMPLETION_METHOD_UNSPECIFIED
	}
}

func gdprToProto(r *business.GDPRRequest) *gen.GDPRRequest {
	if r == nil {
		return nil
	}
	out := &gen.GDPRRequest{
		Id:          r.ID,
		UserId:      r.UserID,
		Type:        gdprTypeToProto(r.Type),
		Status:      gdprStatusToProto(r.Status),
		DownloadUrl: r.DownloadURL,
	}
	if !r.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(r.CreatedAt)
	}
	if r.CompletedAt != nil {
		out.CompletedAt = timestamppb.New(*r.CompletedAt)
	}
	if r.ExpiresAt != nil {
		out.ExpiresAt = timestamppb.New(*r.ExpiresAt)
	}
	return out
}

func gdprTypeToProto(t business.GDPRRequestType) gen.GDPRRequestType {
	switch t {
	case business.GDPRExport:
		return gen.GDPRRequestType_GDPR_REQUEST_TYPE_EXPORT
	case business.GDPRDeletion:
		return gen.GDPRRequestType_GDPR_REQUEST_TYPE_DELETION
	}
	return gen.GDPRRequestType_GDPR_REQUEST_TYPE_UNSPECIFIED
}

func gdprStatusToProto(s business.GDPRRequestStatus) gen.GDPRRequestStatus {
	switch string(s) {
	case "pending":
		return gen.GDPRRequestStatus_GDPR_REQUEST_STATUS_PENDING
	// A retryable failure is still in flight for the subject: the durable job
	// is scheduled for another attempt, so the request has not failed.
	case "processing", "retrying":
		return gen.GDPRRequestStatus_GDPR_REQUEST_STATUS_PROCESSING
	case "completed":
		return gen.GDPRRequestStatus_GDPR_REQUEST_STATUS_COMPLETED
	case "failed":
		return gen.GDPRRequestStatus_GDPR_REQUEST_STATUS_FAILED
	}
	return gen.GDPRRequestStatus_GDPR_REQUEST_STATUS_UNSPECIFIED
}

func mfaDeviceToProto(d *business.MFADevice) *gen.MFADevice {
	if d == nil {
		return nil
	}
	out := &gen.MFADevice{
		Id:         d.ID,
		UserId:     d.UserID,
		DeviceType: mfaDeviceTypeToProto(d.DeviceType),
		Name:       d.Name,
	}
	if !d.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(d.CreatedAt)
	}
	if d.VerifiedAt != nil {
		out.VerifiedAt = timestamppb.New(*d.VerifiedAt)
	}
	if d.LastUsedAt != nil {
		out.LastUsedAt = timestamppb.New(*d.LastUsedAt)
	}
	return out
}

func mfaDeviceTypeToProto(s string) gen.MFADeviceType {
	switch s {
	case "totp":
		return gen.MFADeviceType_MFA_DEVICE_TYPE_TOTP
	case "webauthn":
		return gen.MFADeviceType_MFA_DEVICE_TYPE_WEBAUTHN
	}
	return gen.MFADeviceType_MFA_DEVICE_TYPE_UNSPECIFIED
}

func (h *permConnectHandler) ListCollectionAccess(ctx context.Context, req *connect.Request[gen.ListCollectionAccessRequest]) (*connect.Response[gen.ListCollectionAccessResponse], error) {
	return unary(ctx, req, h.inner.ListCollectionAccess)
}
