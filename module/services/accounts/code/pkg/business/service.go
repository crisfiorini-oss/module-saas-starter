package business

import (
	"accounts/pkg/abuse"
	"accounts/pkg/analytics"
	"accounts/pkg/auth"
	"accounts/pkg/email"
	"accounts/pkg/events"
	gen "accounts/pkg/gen/saas/accounts/v1"
	"accounts/pkg/githubconnector"
	"accounts/pkg/jobs"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/codefly-dev/core/wool"
	"github.com/google/uuid"
)

type Service struct {
	store                     Store
	hasher                    KeyHasher
	validator                 auth.TokenValidator // production: validates provider tokens after OAuth code exchange
	exchanger                 CodeExchanger       // production: exchanges OAuth codes for provider tokens
	devValidator              auth.TokenValidator // development only: allowlists explicit fixture identities
	resolver                  auth.IdentityResolver
	minter                    auth.JWTMinter
	emailOutbox               *email.Outbox    // optional durable email producer; transport is worker-only
	billing                   BillingClient    // optional: Stripe client for checkout/portal
	billingURLs               BillingRedirects // server-owned Stripe return destinations
	appBaseURL                string           // public URL of the frontend, used in email bodies
	audit                     AuditEmitter
	auditTx                   TxAuditEmitter // set when audit also writes on the caller's tx; required in production
	entitlements              EntitlementChecker
	membership                MembershipInvalidator
	slack                     *SlackNotifier // optional: sends critical notifications to Slack
	oauthState                *auth.OAuthStateSigner
	moduleRegistrar           *registrationAuthority
	moduleIdentity            *registrationAuthority
	solutionRegistrar         *registrationAuthority
	oauthPolicy               *auth.OAuthRequestPolicy
	webhookJobs               jobs.Producer // request-scoped, transactional outbound producer
	mfaCipher                 SecretCipher  // required for TOTP enrollment and verification
	webhookCipher             SecretCipher  // required for outbound-webhook signing keys
	webhookPolicy             *WebhookEndpointPolicy
	webAuthn                  WebAuthnEngine    // required for passkey registration and assertion
	jobOperations             jobs.Operations   // isolated, payload-free platform operations
	eventOperations           events.Operations // isolated, payload-free domain-event operations
	followables               []FollowableResource
	followableByEvent         map[string]string // declared followable event type → resource type
	acquisitionMode           gen.AcquisitionMode
	waitlistEmailVerification bool
	eventRegistry             *analytics.Registry
	productEvents             analytics.Emitter
	usageMeters               *UsageMeterCatalog
	privacy                   PrivacyWorkflow
	privacyJobs               jobs.Producer // request-scoped, transactional producer for privacy workflow jobs
	ssoManagementAPIKey       string
	abuseVerifier             abuse.Verifier
	identityCipher            SecretCipher               // encrypts per-org IdP client secrets
	identityRegistry          *IdentityProviderRegistry  // resolves org → provider stack, cache-invalidated on config change
	connectorCipher           SecretCipher               // encrypts per-source datasource connector credentials (#274 connector store)
	githubConnector           *githubconnector.Connector // mints installation tokens and pulls repo contents (#274 connector store)
	datasourceCipher          SecretCipher               // encrypts per-source DatasourceService credentials + webhook secrets
	datasourceJobs            jobs.Producer              // privileged inbox producer for datasource ingest deliveries
	githubBaseURL             string                     // api.github.com override for the datasource connector
	githubAppID               string                     // deployment's GitHub App registration; empty leaves sources on their own PAT
	githubAppKeyPEM           string                     // the App's RSA signing key, deployment custody — never copied onto a source
	datasourceTicketSigner    *datasourceTicketSigner    // mints/verifies opaque content tickets for oversized change-set blobs
	newGitHubClient           func(token string) GitHubContentClient
	newAPIClient              func(cfg APIDatasourceConfig, credential string) APIContentClient
	newCrawlerClient          func(cfg CrawlerDatasourceConfig) CrawlerContentClient
	newUploadClient           func(cfg UploadDatasourceConfig, secretAccessKey string) UploadContentClient
	newOAuth2Refresh          OAuth2RefreshFunc       // refreshes an OAuth 2.0 API source's access token
	moduleProducer            jobs.Producer           // request-scoped, transactional outbox producer for the module-facing surface
	moduleJobStore            jobs.Store              // privileged worker store (claim/finalize) for the module-facing surface
	modulePrincipals          ModulePrincipalRegistry // per-principal capability grants for the module-facing surface
	eventTransport            events.Transport        // domain-event pub/sub transport (transactional outbox + relay); nil denies publish/replay
}

// SetModuleCapabilities wires the module-facing capability surface (issue #463):
// a request-scoped transactional producer for tenant/subject enqueue, the
// privileged worker store for claim/lease/finalize and global inbox enqueue,
// and the per-principal registry declaring which queues each module service
// principal may use and whether it may act across tenants. Leaving the registry
// nil denies every caller (fail-closed).
func (s *Service) SetModuleCapabilities(producer jobs.Producer, store jobs.Store, registry ModulePrincipalRegistry) {
	s.moduleProducer = producer
	s.moduleJobStore = store
	s.modulePrincipals = registry
}

// ModulePrincipals returns the declared registry, and SetModulePrincipals
// replaces it without disturbing the job wiring SetModuleCapabilities also owns.
// The composition declares a module's vocabulary — including the permission
// resources its content is governed by — so a caller that needs to read or
// stand in for that declaration goes through here rather than re-deriving it.
func (s *Service) ModulePrincipals() ModulePrincipalRegistry {
	return s.modulePrincipals
}

func (s *Service) SetModulePrincipals(registry ModulePrincipalRegistry) {
	s.modulePrincipals = registry
}

// SetModuleEventTransport wires the domain-event pub/sub transport backing
// ModuleCapabilitiesService.PublishEvent / ReplayEvents (issue #493). Publish
// writes the event-of-record into the caller's transaction (transactional
// outbox) and the relay fans it out; Replay re-delivers to a single subscriber.
// Leaving it nil denies both RPCs (fail-closed); Subscribe/Unsubscribe/List do
// not need it because they operate on event_subscriptions through the Store.
func (s *Service) SetModuleEventTransport(transport events.Transport) {
	s.eventTransport = transport
}

// VerifyEventWiring fails startup when the module has accepted event
// subscriptions but has no delivery transport wired. Without a transport,
// publishLifecycleEvent and ModulePublishEvent are no-ops, so every event a
// subscriber is waiting on is silently dropped on the floor — a
// misconfiguration that is invisible at runtime and only surfaces as missing
// deliveries. Asserting the invariant at boot turns that silent skew into a
// loud, immediate failure. A wired transport short-circuits before any store
// call, so the check costs nothing on the healthy path.
func (s *Service) VerifyEventWiring(ctx context.Context) error {
	if s.eventTransport != nil {
		return nil
	}
	var live int
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		n, e := s.store.CountLiveEventSubscriptions(ctx)
		if e != nil {
			return e
		}
		live = n
		return nil
	}); err != nil {
		return fmt.Errorf("verify event wiring: %w", err)
	}
	if live > 0 {
		return fmt.Errorf("verify event wiring: %d live event subscription(s) exist but no event transport is wired; events would be silently dropped — call SetModuleEventTransport before serving", live)
	}
	return nil
}

// CodeExchanger abstracts the OAuth 2.0 code-for-token exchange so the
// business layer doesn't depend on the concrete oidc package. In
// production this is *oidc.Exchanger; tests use a fake.
//
// codeVerifier is the PKCE secret the FE generated for THIS sign-in
// attempt — empty when the FE didn't use PKCE (legacy flow). When
// non-empty, it is forwarded to the provider's token endpoint as
// `code_verifier`; the provider re-hashes it and compares with the
// `code_challenge` originally sent in the authorize URL.
type CodeExchanger interface {
	Exchange(ctx context.Context, code, redirectURI, codeVerifier string) (ExchangedTokens, error)
}

// ExchangedTokens is the subset of an OAuth token response the backend
// cares about. Mirrors oidc.TokenResponse without creating an import
// cycle on the auth package.
type ExchangedTokens struct {
	AccessToken string
	IDToken     string
	// Claims is populated by provider adapters whose verified identity data is
	// split between a signed access token and the authenticated exchange
	// response. WorkOS is one example: its access token proves subject/session,
	// while the response's user object carries the verified primary email.
	Claims *auth.Claims
}

func NewService(store Store) (*Service, error) {
	usageMeters, err := DefaultUsageMeterCatalog()
	if err != nil {
		return nil, err
	}
	return &Service{
		store:                     store,
		acquisitionMode:           gen.AcquisitionMode_ACQUISITION_MODE_OPEN_SIGNUP,
		waitlistEmailVerification: true,
		usageMeters:               usageMeters,
		abuseVerifier:             abuse.DisabledVerifier{},
	}, nil
}

func (s *Service) SetAbuseVerifier(verifier abuse.Verifier) {
	if verifier == nil {
		s.abuseVerifier = abuse.DisabledVerifier{}
		return
	}
	s.abuseVerifier = verifier
}

func (s *Service) SetHasher(h KeyHasher) {
	s.hasher = h
}

// SetJobOperations wires the product-neutral administration boundary backed by
// the isolated app_job_worker pool. It is intentionally separate from Store so
// tenant request traffic cannot inherit cross-tenant job access.
func (s *Service) SetJobOperations(operations jobs.Operations) {
	s.jobOperations = operations
}

// SetEventOperations wires the payload-free domain-event administration boundary
// backed by the isolated app_job_worker pool. Like SetJobOperations it is kept
// separate from Store so tenant request traffic cannot inherit cross-tenant
// access to events or subscriptions.
func (s *Service) SetEventOperations(operations events.Operations) {
	s.eventOperations = operations
}

func (s *Service) SetProductAnalytics(registry *analytics.Registry, emitter analytics.Emitter) {
	s.eventRegistry = registry
	s.productEvents = emitter
}

// SetWebhookJobProducer wires the request-scoped producer used by Test and
// Replay. Its implementation must require the caller's organization
// transaction so delivery history and generated work commit atomically.
func (s *Service) SetWebhookJobProducer(producer jobs.Producer) {
	s.webhookJobs = producer
}

// SetMFASecretCipher wires fail-closed encryption for TOTP seeds. Production
// uses Vault Transit; tests may provide an explicit in-memory implementation.
func (s *Service) SetMFASecretCipher(cipher SecretCipher) {
	s.mfaCipher = cipher
}

// SetWebhookSecurity wires the fail-closed signing-key cipher and the shared
// registration/connect-time endpoint policy. Production uses Vault Transit and
// the public-Internet-only dialer; tests can provide deterministic substitutes.
func (s *Service) SetWebhookSecurity(cipher SecretCipher, policy *WebhookEndpointPolicy) {
	s.webhookCipher = cipher
	s.webhookPolicy = policy.ensureDefaults()
}

// SetPrivacyWorkflow enables the privacy capability. The producer and the
// adapter arrive together because neither is usable alone: without a producer
// an accepted request would have no durable owner, and without an adapter the
// job it enqueues could never be executed. Leaving either unset keeps
// RequestExport and RequestDeletion fail-closed.
func (s *Service) SetPrivacyWorkflow(producer jobs.Producer, workflow PrivacyWorkflow) {
	s.privacyJobs = producer
	s.privacy = workflow
}

// SetOrgIdentityProviderCipher wires fail-closed encryption for per-org IdP
// client secrets. Production uses Vault Transit; tests may provide an explicit
// in-memory implementation.
func (s *Service) SetOrgIdentityProviderCipher(cipher SecretCipher) {
	s.identityCipher = cipher
}

// SetConnectorCipher wires fail-closed encryption for per-source datasource
// connector credentials (GitHub App keys and webhook signing secrets).
// Production uses Vault Transit; tests may provide an explicit in-memory
// implementation.
func (s *Service) SetConnectorCipher(cipher SecretCipher) {
	s.connectorCipher = cipher
}

// SetGitHubConnector wires the client that mints installation tokens and pulls
// repository contents for datasource sync and webhook re-fetch.
func (s *Service) SetGitHubConnector(connector *githubconnector.Connector) {
	s.githubConnector = connector
}

// SetIdentityProviderRegistry wires the per-org provider registry so
// configuration changes invalidate the resolved-stack cache. Nil leaves the
// service on the global default provider only.
func (s *Service) SetIdentityProviderRegistry(registry *IdentityProviderRegistry) {
	s.identityRegistry = registry
}

// SetIdentityResolver wires the JIT provisioning + bootstrap layer.
// Required for /auth/login and /auth/signup flows.
func (s *Service) SetIdentityResolver(r auth.IdentityResolver) {
	s.resolver = r
}

// SetJWTMinter wires the token signing + refresh rotation layer.
// Required for every /auth/* endpoint.
func (s *Service) SetJWTMinter(m auth.JWTMinter) {
	s.minter = m
}

// SetOAuthStateSigner wires the server-side state signer used by BeginOAuth
// and verified in Authenticate. OAuth fails closed when this is nil.
func (s *Service) SetOAuthStateSigner(signer *auth.OAuthStateSigner) {
	s.oauthState = signer
}

// SetOAuthRequestPolicy restricts OAuth initiation and callback exchange to
// the configured provider and exact redirect URI allowlist. OAuth fails closed
// when this is nil.
func (s *Service) SetOAuthRequestPolicy(policy *auth.OAuthRequestPolicy) {
	s.oauthPolicy = policy
}

// JWTMinter returns the configured minter so adapters (e.g. the
// Connect auth interceptor) can verify access tokens. Nil if the
// minter has not been wired — callers should treat that as "auth
// disabled" rather than crashing.
func (s *Service) JWTMinter() auth.JWTMinter {
	return s.minter
}

// SetTokenValidator wires a production provider TokenValidator. Authenticate
// uses it only after exchanging an OAuth authorization code. It is deliberately
// separate from the development fixture validator: a missing production
// validator never enables caller-supplied identities as a fallback.
func (s *Service) SetTokenValidator(v auth.TokenValidator) {
	s.validator = v
}

// SetDevelopmentTokenValidator explicitly enables fixture authentication.
// The validator must resolve an opaque fixture token to allowlisted claims;
// Authenticate never trusts provider identity fields supplied by the caller.
// Production wiring must leave this nil.
func (s *Service) SetDevelopmentTokenValidator(v auth.TokenValidator) {
	s.devValidator = v
}

// SetCodeExchanger wires the OAuth code-for-token exchange used in
// production login flows. Optional: if unset, Authenticate cannot
// process OAuth `code` payloads.
func (s *Service) SetCodeExchanger(e CodeExchanger) {
	s.exchanger = e
}

// SetSSOManagementAPIKey wires the optional provider-management credential
// used by the WorkOS Admin Portal adapter. Runtime composition supplies this
// from Codefly's secret workspace configuration; business code never reads
// process environment directly.
func (s *Service) SetSSOManagementAPIKey(apiKey string) {
	s.ssoManagementAPIKey = strings.TrimSpace(apiKey)
}

// SetEmailOutbox wires the transactional producer used by invitations,
// authentication, and other request paths. The provider sender is deliberately
// absent from Service: only the generic email worker may perform delivery.
func (s *Service) SetEmailOutbox(outbox *email.Outbox, appBaseURL string) {
	s.emailOutbox = outbox
	s.appBaseURL = appBaseURL
}

// publicBaseURL is the origin baked into interactive links — magic-link,
// invitation, and waitlist emails, and Stripe redirect targets. Those links are
// delivered out of band and never re-validated downstream, so the origin must be
// operator-trusted. A configured APP_BASE_URL wins; the frontend-supplied
// verified public origin is a per-request, caller-influenced value (the frontend
// derives it from the browser request when its own endpoint is a placeholder),
// so it is only a fallback for deployments that have not pinned a canonical
// origin. Without either, callers fail closed rather than mint a link on an
// unverified host.
func (s *Service) publicBaseURL(ctx context.Context) string {
	if base := strings.TrimSuffix(strings.TrimSpace(s.appBaseURL), "/"); base != "" {
		return base
	}
	if origin, ok := auth.VerifiedPublicOrigin(ctx); ok {
		return origin
	}
	return ""
}

func (s *Service) SetAuditEmitter(a AuditEmitter) {
	s.audit = a
	s.auditTx, _ = a.(TxAuditEmitter)
}

// VerifyAuditWiring fails startup when the wired audit emitter cannot write on
// the caller's transaction. Every security mutation commits its audit row and
// webhook fan-out inside its own transaction; an emitter without EmitTx would
// let those mutations succeed with no durable record and no fan-out, which is
// precisely the state a security-write path must not be able to reach. Boot
// refuses it rather than discovering it as a hole in the trail later.
func (s *Service) VerifyAuditWiring() error {
	if s.audit == nil {
		return errors.New("verify audit wiring: no audit emitter is wired; security mutations would commit unrecorded")
	}
	if s.auditTx == nil {
		return fmt.Errorf("verify audit wiring: audit emitter %T does not implement TxAuditEmitter; security mutations could not commit their audit record atomically", s.audit)
	}
	return nil
}

func (s *Service) SetEntitlementChecker(e EntitlementChecker) {
	s.entitlements = e
}

// MembershipInvalidator is called by the business layer on every mutation
// that changes (orgID, userID) membership — add/remove/role-change. A
// nil invalidator (SetMembershipInvalidator never called) is a no-op,
// which is the correct fallback when Redis caching is disabled.
//
// It reports whether the cached entry was actually dropped. Invalidation runs
// after the mutation has committed, so a failure can never undo the mutation —
// but on a removal it does leave the departed member's positive entry standing
// until it expires, which callers must be able to see rather than infer.
//
// The implementation lives in adapters; this interface keeps the
// business layer from importing adapters or cache directly, matching
// the SetAuditEmitter / SetEntitlementChecker pattern.
type MembershipInvalidator interface {
	InvalidateMembership(ctx context.Context, orgID, userID string) error
}

func (s *Service) SetMembershipInvalidator(i MembershipInvalidator) {
	s.membership = i
}

// invalidateMembership is the internal helper Service methods call after
// mutating membership. Nil-safe so non-cache-wired setups keep working.
//
// The mutation is already committed when this runs, so a cache failure cannot
// be reported as a failed mutation. What it can do is leave a stale entry
// standing until its TTL expires — for a removal, an entry that still says the
// departed member holds a role. That is logged here so it is visible in the one
// place every membership mutation passes through, and returned so a caller can
// react.
func (s *Service) invalidateMembership(ctx context.Context, orgID, userID string) error {
	if s.membership == nil {
		return nil
	}
	err := s.membership.InvalidateMembership(ctx, orgID, userID)
	if err != nil {
		wool.Get(ctx).Warn("cached organization membership survived a membership mutation; it stays authoritative until it expires",
			wool.Field("org_id", orgID), wool.Field("user_id", userID), wool.ErrField(err))
	}
	return err
}

// SetSlackNotifier wires an optional Slack webhook notifier for critical events.
func (s *Service) SetSlackNotifier(n *SlackNotifier) {
	s.slack = n
}

// notifySlack sends a message to Slack if the notifier is configured. Best-effort.
func (s *Service) notifySlack(ctx context.Context, text string) {
	if s.slack != nil {
		_ = s.slack.Send(ctx, "", text)
	}
}

func (s *Service) SetStore(store Store) {
	s.store = store
}

func (s *Service) Store() Store {
	return s.store
}

// RegisterUser creates a new user with identity and a default personal organization.
func (s *Service) RegisterUser(ctx context.Context, input *gen.RegisterUserRequest) (*gen.RegisterUserResponse, error) {
	w := wool.Get(ctx).In("RegisterUser")

	if err := s.abuseVerifier.Verify(ctx, abuse.Challenge{
		Token: input.GetTurnstileToken(), Action: "register_user",
	}); err != nil {
		return nil, err
	}
	if err := s.authorizeAccountCreation(ctx, input.PrimaryEmail); err != nil {
		return nil, err
	}

	userID := NewIDString()
	identityID := NewIDString()

	user := &gen.User{
		Uuid:         userID,
		PrimaryEmail: input.PrimaryEmail,
		Status:       gen.UserStatus_USER_STATUS_ACTIVE,
		Profile:      input.Profile,
	}

	identity := input.Identity
	identity.Uuid = identityID
	identity.UserUuid = userID
	if identity.ProviderEmail == "" {
		identity.ProviderEmail = input.PrimaryEmail
	}

	// RegisterUser already uses its own transaction for user+identity
	if err := s.store.RegisterUser(ctx, user, identity); err != nil {
		return nil, w.Wrapf(err, "cannot register user")
	}

	// Create a default personal organization
	orgID := NewIDString()
	org := &gen.Organization{
		Id:   orgID,
		Name: "Personal",
		// Use the tail of the uuid (random bits) not the head (v7 timestamp prefix)
		// so two users created in the same millisecond get distinct slugs.
		Slug:    "personal-" + userID[len(userID)-12:],
		OwnerId: userID,
	}
	// Personal-org bootstrap: see CreateOrganization comment — at
	// this moment the org doesn't exist; WithControlPlane is correct.
	//
	// The registration is recorded here rather than alongside the role
	// assignment below: this transaction always runs, so the record does not
	// hinge on a built-in admin role existing. Its fan-out is empty by
	// construction — the org is being created in this transaction, so nothing
	// can yet be subscribed to it — which is what lets an org-scoped event be
	// recorded from control-plane scope (the job platform admits tenant outbox
	// work from tenant traffic only).
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		if err := s.store.CreateOrganization(ctx, org); err != nil {
			return err
		}
		return s.emitTx(ctx, userID, "user", EventUserRegistered, "user", userID, orgID)
	}); err != nil {
		return nil, w.Wrapf(err, "cannot create default organization")
	}

	// Assign admin role to user in their org. The built-in roles are
	// org_id=NULL — RLS-protected as of Phase 2E, so the read needs
	// bypass (built-ins are global). The assignment row carries
	// concrete orgID so it goes through WithOrgTx.
	var roles []*gen.Role
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		rs, err := s.store.ListRoles(ctx, "")
		roles = rs
		return err
	}); err != nil {
		return nil, w.Wrapf(err, "cannot list roles")
	}
	for _, role := range roles {
		if role.Name == "admin" && role.BuiltIn {
			assignment := &gen.RoleAssignment{
				Id:          NewIDString(),
				SubjectId:   userID,
				SubjectKind: gen.SubjectKind_SUBJECT_KIND_PRINCIPAL,
				RoleId:      role.Id,
				OrgId:       orgID,
			}
			if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
				return s.store.AssignRole(ctx, assignment)
			}); err != nil {
				return nil, w.Wrapf(err, "cannot assign admin role")
			}
			break
		}
	}

	return &gen.RegisterUserResponse{User: user, Identity: identity}, nil
}

// CheckPermission checks if a subject has permission to perform an action on a resource.
//
// The query JOINs role_assignments + roles + role_permissions
// (+ team_members for team inheritance). All but role_permissions
// are RLS-protected (Phase 2E + 2C); a tenant-scoped check needs
// WithOrgTx so the JOIN sees the right rows. Global checks
// (req.OrgId == "") run under bypass — only platform-internal
// callers exercise that path.
func (s *Service) CheckPermission(ctx context.Context, req *gen.CheckPermissionRequest) (*gen.CheckPermissionResponse, error) {
	var allowed bool
	var reason string
	wrap := func(ctx context.Context) error {
		a, r, err := s.store.CheckPermission(
			ctx, req.SubjectId, req.SubjectKind,
			req.Resource, req.Action, req.OrgId, req.Scope,
		)
		allowed, reason = a, r
		return err
	}
	var err error
	if req.OrgId == "" {
		err = s.store.WithControlPlane(ctx, wrap)
	} else {
		err = s.store.WithOrgTx(ctx, req.OrgId, wrap)
	}
	if err != nil {
		return nil, err
	}
	return &gen.CheckPermissionResponse{Allowed: allowed, Reason: reason}, nil
}

// ResolveIdentity maps an auth provider ID to internal user/org/roles.
//
// Auth-flow read: at login we don't yet know the user's tenant. The
// Store implementation (postgres_permissions.go:ResolveIdentity)
// opens its own tx and assumes app_control_plane inline so
// the JOINs against organization_members + role_assignments (both
// RLS-protected) see all tenants.
//
// The auth interceptor stamps the resolved OrgID on every
// subsequent ctx so downstream queries run properly scoped via
// WithOrgTx.
func (s *Service) ResolveIdentity(ctx context.Context, req *gen.ResolveIdentityRequest) (*gen.ResolveIdentityResponse, error) {
	resolved, err := s.store.ResolveIdentity(ctx, req.Provider, req.ProviderId)
	if err != nil {
		return nil, err
	}
	return &gen.ResolveIdentityResponse{
		UserId:       resolved.UserID,
		OrgId:        resolved.OrgID,
		Roles:        resolved.Roles,
		Found:        resolved.Found,
		OrgRole:      resolved.OrgRole,
		PlatformRole: resolved.PlatformRole,
	}, nil
}

// CreateOrganization creates a new org with the requesting user as owner.
//
// Bootstrap path: at this moment the tenant doesn't exist yet, so
// there's no org context to set. WithControlPlane (which keeps the
// connection's session_user role) is correct here — the role-switch
// in WithOrgTx would put us as app_tenant with no app.current_org_id,
// and the WITH CHECK on organization_members would reject the insert.
// User authz is at the handler — only authenticated users can create
// orgs; abuse is rate-limited.
func (s *Service) CreateOrganization(ctx context.Context, ownerID string, req *gen.CreateOrganizationRequest) (*gen.CreateOrganizationResponse, error) {
	return s.CreateFixtureOrganization(ctx, ownerID, req, "")
}

// CreateFixtureOrganization is CreateOrganization with a caller-chosen id, for
// the fixture seeder only: a fixture pins its organizations' uuids so committed
// configuration (a module principal's tenant) can name one that survives a
// reseed. An empty id mints one, exactly as CreateOrganization does.
//
// The id is validated here rather than trusted from the caller. The seeder does
// validate it, but this method is exported next to CreateOrganization and takes
// a primary key as an argument, so it has to be safe for whoever calls it next —
// a tenant id that reaches the database malformed is not recoverable by anything
// downstream.
func (s *Service) CreateFixtureOrganization(ctx context.Context, ownerID string, req *gen.CreateOrganizationRequest, id string) (*gen.CreateOrganizationResponse, error) {
	slug := req.Slug
	if slug == "" {
		slug = Slugify(req.Name)
	}
	if slug == "" {
		return nil, wool.Get(ctx).In("CreateOrganization").NewError("organization name yields an empty slug")
	}
	if id == "" {
		id = NewIDString()
	} else {
		parsed, err := ParseID(id)
		if err != nil {
			return nil, wool.Get(ctx).In("CreateFixtureOrganization").Wrapf(err, "organization id must be a uuid")
		}
		if parsed == uuid.Nil {
			return nil, wool.Get(ctx).In("CreateFixtureOrganization").NewError("organization id must not be the nil uuid")
		}
		id = parsed.String()
	}
	org := &gen.Organization{
		Id:      id,
		Name:    req.Name,
		Slug:    slug,
		OwnerId: ownerID,
	}
	// The audit row commits with the organization inside this control-plane
	// transaction. Its webhook fan-out is empty by construction — the org is being
	// created here, so no endpoint can yet be subscribed to it — which is what
	// lets an org-scoped event be recorded from control-plane scope at all: the
	// job platform admits tenant outbox work from tenant traffic only.
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		if err := s.store.CreateOrganization(ctx, org); err != nil {
			return err
		}
		return s.emitTx(ctx, ownerID, "user", EventOrgCreated, "organization", org.Id, org.Id)
	}); err != nil {
		return nil, err
	}
	return &gen.CreateOrganizationResponse{Organization: org}, nil
}

// CreateTeam creates a new team within an org.
// actorID is the authenticated caller — recorded in the audit log so we
// know who stood up the team. teams is RLS-protected (Phase 2C) so
// the insert runs inside WithOrgTx scoped to the target org.
//
// Teams form a TREE: path = parent.path + "/" + slug (slug derived from the
// name when not given). Create-under-existing-parent only — there is no
// reparent RPC, so cycles cannot form; a future move feature adds a guard.
func (s *Service) CreateTeam(ctx context.Context, actorID string, req *gen.CreateTeamRequest) (*gen.CreateTeamResponse, error) {
	w := wool.Get(ctx).In("CreateTeam")

	slug := req.Slug
	if slug == "" {
		slug = Slugify(req.Name)
	}
	if slug == "" {
		return nil, w.NewError("team name yields an empty slug")
	}

	team := &gen.Team{
		Id:           NewIDString(),
		OrgId:        req.OrgId,
		Name:         req.Name,
		Description:  req.Description,
		ParentTeamId: req.ParentTeamId,
		Slug:         slug,
		Path:         slug, // root path; child path derived below
	}
	if err := s.store.WithOrgTx(ctx, req.OrgId, func(ctx context.Context) error {
		if req.ParentTeamId != "" {
			parentOrg, parentPath, err := s.store.GetTeamPath(ctx, req.ParentTeamId)
			if err != nil {
				return err
			}
			if parentOrg == "" {
				return w.NewError("parent team not found")
			}
			if parentOrg != req.OrgId {
				return w.NewError("parent team belongs to a different organization")
			}
			team.Path = parentPath + "/" + slug
		}
		if err := s.store.CreateTeam(ctx, team); err != nil {
			return err
		}
		return s.emitTx(ctx, actorID, "user", EventTeamCreated, "team", team.Id, req.OrgId)
	}); err != nil {
		return nil, err
	}
	return &gen.CreateTeamResponse{Team: team}, nil
}

// Slugify derives a path segment from a display name: lowercase, runs of
// non-alphanumerics collapse to "-", trimmed. ("Platform Eng." → "platform-eng")
func Slugify(name string) string {
	var b strings.Builder
	lastDash := true // suppress a leading dash
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// CreateRole creates a new custom role.
// Audit trail records actorID so role additions are traceable — these are
// security-relevant changes (a new role = a new set of permissions).
//
// roles is RLS-protected (Phase 2E). req.OrgId == "" means a global
// built-in role write — only platform admin can do this (handler authz
// enforces requirePlatformAdmin in adapters/rpcs.go), and the WITH
// CHECK on roles requires either bypass or a concrete org. Use bypass
// for the global path and WithOrgTx for tenant roles.
func (s *Service) CreateRole(ctx context.Context, actorID string, req *gen.CreateRoleRequest) (*gen.CreateRoleResponse, error) {
	role := &gen.Role{
		Id:          NewIDString(),
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
		BuiltIn:     false,
		OrgId:       req.OrgId,
	}
	wrap := func(ctx context.Context) error {
		if err := s.store.CreateRole(ctx, role); err != nil {
			return err
		}
		return s.emitTx(ctx, actorID, "user", EventRoleCreated, "role", role.Id, req.OrgId)
	}
	var err error
	if req.OrgId == "" {
		err = s.store.WithControlPlane(ctx, wrap)
	} else {
		err = s.store.WithOrgTx(ctx, req.OrgId, wrap)
	}
	if err != nil {
		return nil, err
	}
	return &gen.CreateRoleResponse{Role: role}, nil
}

// AssignRole assigns a role to a user or team. role_assignments is
// RLS-protected (Phase 2E). Empty OrgId means a platform-level
// assignment (super_admin etc.) — handler authz already required
// platform_admin; the write goes through bypass.
func (s *Service) AssignRole(ctx context.Context, req *gen.AssignRoleRequest) (*gen.AssignRoleResponse, error) {
	assignment := &gen.RoleAssignment{
		Id:          NewIDString(),
		SubjectId:   req.SubjectId,
		SubjectKind: req.SubjectKind,
		RoleId:      req.RoleId,
		OrgId:       req.OrgId,
		Scope:       req.Scope,
	}
	wrap := func(ctx context.Context) error {
		if err := s.store.AssignRole(ctx, assignment); err != nil {
			return err
		}
		return s.emitTx(ctx, req.SubjectId, "user", EventRoleAssigned, "role", req.RoleId, req.OrgId)
	}
	var err error
	if req.OrgId == "" {
		err = s.store.WithControlPlane(ctx, wrap)
	} else {
		err = s.store.WithOrgTx(ctx, req.OrgId, wrap)
	}
	if err != nil {
		return nil, err
	}
	return &gen.AssignRoleResponse{Assignment: assignment}, nil
}
