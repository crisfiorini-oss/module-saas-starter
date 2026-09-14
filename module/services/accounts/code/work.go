package main

import (
	"accounts/fixtures"
	"accounts/pkg/abuse"
	"accounts/pkg/adapters"
	"accounts/pkg/analytics"
	"accounts/pkg/auth"
	devvalidator "accounts/pkg/auth/dev"
	ed25519minter "accounts/pkg/auth/ed25519"
	"accounts/pkg/auth/headerjwt"
	"accounts/pkg/auth/oidc"
	pgauth "accounts/pkg/auth/pg"
	workosauth "accounts/pkg/auth/workos"
	"accounts/pkg/billing"
	pgbilling "accounts/pkg/billing/pg"
	"accounts/pkg/business"
	"accounts/pkg/cache"
	"accounts/pkg/datasource"
	"accounts/pkg/email"
	"accounts/pkg/githubconnector"
	"accounts/pkg/infra"
	"accounts/pkg/jobs"
	"accounts/pkg/metrics"
	"accounts/pkg/permissionsplugin"
	"accounts/pkg/vaultconnection"
	"context"
	ed25519core "crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/codefly-dev/core/wool"
	wooltel "github.com/codefly-dev/core/wool/otel"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
)

func init() {
	WithWork(doWork)
}

func doWork(ctx context.Context) (Clean, error) {
	w := wool.Get(ctx).In("doWork")
	measurementPack, err := metrics.DefaultSeedBundle()
	if err != nil {
		return nil, fmt.Errorf("load measurement seed pack: %w", err)
	}
	w.Info(
		"measurement seed pack loaded",
		wool.Field("dashboard.version", measurementPack.DashboardPack.Version),
		wool.Field("slo.version", measurementPack.SLOPack.Version),
	)
	selectedFixture, err := fixtures.SelectedName()
	if err != nil {
		return nil, err
	}
	stepUpMaxAge, err := configuredMFAStepUpMaxAge()
	if err != nil {
		return nil, err
	}
	adapters.SetRecentStepUpMaxAge(stepUpMaxAge)
	sessionPolicy, err := configuredSessionPolicy()
	if err != nil {
		return nil, err
	}

	// When external observability is configured, OpenTelemetry always targets
	// the in-graph collector. Codefly owns its host and port; the accounts
	// process never reads or hardcodes a collector address.
	var otelProvider *wooltel.Provider
	var otelMetricProvider *otelMetrics
	if observabilityEnabled() {
		collectorNetwork, err := codefly.For(ctx).
			Service("telemetry").
			Endpoint("grpc").
			API("grpc").
			ResolveNetworkInstance()
		if err != nil {
			return nil, fmt.Errorf("resolve telemetry collector through Codefly: %w", err)
		}
		p, oerr := wooltel.Enable(
			wooltel.WithServiceName("saas-starter-api"),
			wooltel.WithEndpoint(collectorNetwork.Host),
			wooltel.WithInsecure(),
		)
		if oerr != nil {
			return nil, fmt.Errorf("configure OTEL tracing: %w", oerr)
		}
		otelProvider = p
		w.Info("OTEL enabled",
			wool.Field("endpoint", collectorNetwork.Host),
			wool.Field("service.name", "saas-starter-api"))
		metricProvider, oerr := enableOTELMetrics(ctx, "saas-starter-api", collectorNetwork.Host)
		if oerr != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = otelProvider.Shutdown(shutdownCtx)
			cancel()
			return nil, fmt.Errorf("configure OTEL metrics: %w", oerr)
		}
		otelMetricProvider = metricProvider
		adapters.RegisterHTTPRoute("/metrics", otelMetricProvider.Handler())
	}

	store, err := infra.NewPostgresStore(ctx)
	if err != nil {
		return nil, err
	}

	service, err := business.NewService(store)
	if err != nil {
		return nil, err
	}
	abuseVerifier, err := configuredAbuseVerifier()
	if err != nil {
		return nil, err
	}
	service.SetAbuseVerifier(abuseVerifier)
	_, abuseDisabled := abuseVerifier.(abuse.DisabledVerifier)
	if abuseDisabled {
		w.Warn("ABUSE PROTECTION DISABLED — anonymous endpoints (Authenticate, RegisterUser, JoinWaitlist, SendMagicLink) are guarded by rate limiting alone; set ABUSE_PROTECTION_MODE=turnstile before serving production traffic")
	}

	// Per-IP rate limiting attributes anonymous traffic to a source address.
	// TRUSTED_PROXY_CIDRS lists the proxies whose X-Forwarded-For we honor;
	// an invalid entry fails boot rather than silently trusting a spoofable
	// header.
	trustedProxies, err := adapters.ParseTrustedProxyCIDRs(workspaceEnv("security", "TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return nil, err
	}
	adapters.WithTrustedProxies(trustedProxies)
	if len(trustedProxies) == 0 {
		w.Warn("TRUSTED_PROXY_CIDRS unset — behind an ingress, per-IP rate limiting attributes all X-Forwarded-For traffic to the proxy's own IP (one shared bucket); set it to the ingress CIDRs to bucket by real client IP")
	}
	if err := service.SetAcquisitionMode(os.Getenv("ACQUISITION_MODE")); err != nil {
		return nil, err
	}
	if configured := strings.TrimSpace(os.Getenv("WAITLIST_EMAIL_VERIFICATION")); configured != "" {
		required, parseErr := strconv.ParseBool(configured)
		if parseErr != nil {
			return nil, fmt.Errorf("configure waitlist email verification: %w", parseErr)
		}
		service.SetWaitlistEmailVerification(required)
	}
	// Cross-tenant job administration is isolated from request traffic at the
	// connection-pool boundary. The API exposes payload-free metadata only;
	// replay copies payload bytes inside PostgreSQL under app_job_worker.
	jobWorkerPool, err := infra.NewJobWorkerPool(ctx)
	if err != nil {
		return nil, fmt.Errorf("configure job operations database pool: %w", err)
	}
	jobStore := infra.NewPostgresJobStore(jobWorkerPool)
	// Durable job-operations metrics are enabled only when OTEL metrics are, i.e.
	// otelMetricProvider != nil (observabilityEnabled()). With observability off
	// the global meter is a no-op, so building the monitor would poll the job
	// store every interval to feed instruments nothing can read; keep it nil and
	// let the Start/Shutdown nil-checks below skip it entirely.
	jobOperationsMonitor, err := newDurableJobMetricsMonitor(otelMetricProvider != nil, jobStore)
	if err != nil {
		return nil, fmt.Errorf("configure durable job metrics: %w", err)
	}
	service.SetJobOperations(jobStore)
	// Domain-event administration (#494 P3) reads the same isolated worker pool:
	// per-type counters and relay lag from domain_events, dead-letters from the
	// inbox, and live subscriptions across every principal — payload-free, and on
	// app_job_worker so request traffic never gains that cross-tenant reach.
	service.SetEventOperations(infra.NewPostgresEventOperations(jobWorkerPool))
	service.SetWebhookJobProducer(store)

	// Module-facing capability surface (issue #463): a request-scoped
	// transactional producer for tenant/subject enqueue, the privileged worker
	// store for claim/lease/finalize and global inbox enqueue, and the registry
	// declaring which queues each module service principal may use. The registry
	// is deployment-provided; an unset value denies every caller (fail-closed).
	modulePrincipals, err := business.ParseModulePrincipalRegistry(workspaceEnv("module-capabilities", "MODULE_PRINCIPALS"))
	if err != nil {
		return nil, fmt.Errorf("parse module principal registry: %w", err)
	}
	service.SetModuleCapabilities(store, jobStore, modulePrincipals)
	// Explicit organization delegation is separate from module identity. A
	// projected policy is refreshed by the delivery system and read per call.
	if policyPath := os.Getenv("MODULE_INSTALLER_POLICY_FILE"); policyPath != "" {
		handler, err := adapters.NewModuleInstallationHTTPHandler(service, policyPath)
		if err != nil {
			return nil, fmt.Errorf("configure module installer policy: %w", err)
		}
		adapters.RegisterHTTPRoute("/v1/module-installations/", handler)
	}

	// Domain-event pub/sub (issue #493): the reference events.Transport over the
	// durable jobs platform. A module publish joins its WithOrgTx transaction so
	// the insert is the transactional outbox and the tenant gate re-checks under
	// app_tenant; the relay worker then drains domain_events after commit, fanning
	// each event out to matching subscriptions on the app_job_worker pool
	// (BYPASSRLS, so it resolves events and subscriptions across every tenant).
	// The relay is also the outbound-webhook fan-out: a webhook endpoint is an
	// event_subscriptions row with delivery = webhook (#488), and this is the
	// dispatcher it is delivered through.
	eventTransport := infra.NewPostgresEventTransport(
		jobStore, jobWorkerPool, "events-relay-"+uuid.NewString(), time.Minute,
		infra.WithWebhookRelay(infra.NewPostgresWebhookRelay(store)),
	)
	service.SetModuleEventTransport(eventTransport)
	eventRelayWorker := infra.NewEventRelayWorker(eventTransport, 0)

	// Fail fast if a deployment ever ends up with live subscriptions but no
	// transport: without one, every publish is a silent no-op and subscribers
	// receive nothing. The transport is wired unconditionally just above, so this
	// is a regression guard — but it converts a future mis-wiring from invisible
	// event loss into a startup error.
	if err := service.VerifyEventWiring(ctx); err != nil {
		return nil, err
	}
	// The symmetric guard for the other half of fan-out: a transport with no
	// outbound dispatcher relays to module queues and silently never to webhook
	// endpoints, which is the same invisible loss one layer over.
	if err := eventTransport.RequireWebhookRelay(); err != nil {
		return nil, err
	}

	eventRegistry, err := analytics.DefaultRegistry()
	if err != nil {
		return nil, err
	}
	analyticsSink, analyticsEnabled, err := configuredAnalyticsSink()
	if err != nil {
		return nil, err
	}
	var analyticsWorker *jobs.Worker
	if analyticsEnabled {
		productEventOutbox, err := analytics.NewOutbox(store, eventRegistry)
		if err != nil {
			return nil, err
		}
		service.SetProductAnalytics(eventRegistry, productEventOutbox)
		analyticsHandler, err := analytics.NewExportHandler(analytics.ExportHandlerConfig{
			Destination: analyticsSink,
			Deliveries:  jobStore,
		})
		if err != nil {
			return nil, err
		}
		analyticsWorker, err = jobs.NewWorker(jobs.WorkerConfig{
			Store:      jobStore,
			Queue:      analytics.ExportQueue,
			Handler:    analyticsHandler,
			RetryDelay: analytics.ExportRetryDelay,
		})
		if err != nil {
			return nil, err
		}
	}

	// Vault is a required security dependency: API-key HMAC and TOTP seed
	// encryption must be stable across replicas and fail closed.
	vaultClient, err := infra.NewVaultClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("configure Vault security services: %w", err)
	}
	service.SetHasher(vaultClient)
	service.SetMFASecretCipher(vaultClient)
	service.SetOrgIdentityProviderCipher(vaultClient)
	service.SetConnectorCipher(vaultClient)
	service.SetGitHubConnector(githubconnector.NewConnector(
		githubconnector.WithBaseURL(os.Getenv("GITHUB_API_BASE_URL"))))
	// Datasource connector (issue #274): per-source credentials are Vault-transit
	// encrypted, and pulled files are enqueued onto the durable inbox seam the
	// documents module consumes. GITHUB_API_BASE_URL overrides api.github.com for
	// GitHub Enterprise or tests.
	service.SetDatasourceConnector(vaultClient, jobStore, os.Getenv("GITHUB_API_BASE_URL"))
	// The App registration is deployment custody: the signing key is read here
	// and never copied onto a source record. Unset leaves sources on their own
	// stored fine-grained PAT.
	service.SetGitHubAppRegistration(
		workspaceEnv("github-app", "GITHUB_APP_ID"),
		workspaceEnv("github-app", "GITHUB_APP_PRIVATE_KEY"),
		workspaceEnv("github-app", "GITHUB_APP_SLUG"),
		workspaceEnv("github-app", "GITHUB_APP_WEBHOOK_SECRET"),
	)
	webhookPolicy := business.NewWebhookEndpointPolicy()
	service.SetWebhookSecurity(vaultClient, webhookPolicy)
	webAuthnRPID, webAuthnDisplayName, webAuthnOrigins, err := configuredWebAuthn()
	if err != nil {
		return nil, fmt.Errorf("configure WebAuthn: %w", err)
	}
	webAuthnEngine, err := infra.NewWebAuthnEngine(webAuthnRPID, webAuthnDisplayName, webAuthnOrigins)
	if err != nil {
		return nil, err
	}
	service.SetWebAuthnEngine(webAuthnEngine)
	if migrated, err := store.MigrateLegacyMFASecrets(ctx, vaultClient); err != nil {
		return nil, fmt.Errorf("migrate legacy MFA secrets: %w", err)
	} else if migrated > 0 {
		w.Info("encrypted legacy MFA secrets", wool.Field("count", migrated))
	}
	if migrated, disabled, err := store.MigrateLegacyWebhookSecrets(ctx, vaultClient); err != nil {
		return nil, fmt.Errorf("migrate legacy webhook secrets: %w", err)
	} else if migrated > 0 {
		w.Info("encrypted legacy webhook secrets",
			wool.Field("count", migrated),
			wool.Field("disabled_empty_secret_endpoints", disabled))
	}

	// Auth pipeline: IdentityResolver + JWTMinter + optional provider
	// validator/exchanger chain for the OAuth code flow.
	// SessionStore needs WithUserTx/WithControlPlane helpers (sessions is
	// RLS-protected per Phase 2H); pass *PostgresStore which
	// implements them.
	sessionStore := pgauth.NewSessionStore(store, sessionPolicy)
	resolver := pgauth.NewResolver(store)
	resolver.SetBootstrapAdminEmail(applicationEnv("BOOTSTRAP_ADMIN_EMAIL"))
	signupMode, err := auth.ParseSignupMode(identityEnv("IDENTITY_SIGNUP_MODE"))
	if err != nil {
		return nil, err
	}
	resolver.SetSignupMode(signupMode)
	authProvider := configuredAuthProvider(selectedFixture)
	if err := requireLocalForDevFixtureProvider(authProvider, codefly.IsLocal()); err != nil {
		return nil, err
	}
	priv, err := loadSigningKey(ctx, devFixtureAuthProvider(authProvider))
	if err != nil {
		return nil, err
	}
	// Default fail-closed: a token whose revocation status can't be read is
	// denied. Operators fronting accounts directly (no auth-gateway) can opt into
	// fail-open to keep the direct verify path serving through a revocation-store
	// outage, trading a revoked token's remaining-TTL exposure for availability —
	// the same choice the auth-gateway ext_authz check exposes via SIDECAR_REVOCATION_FAIL_OPEN.
	revocationFailOpen := strings.EqualFold(strings.TrimSpace(workspaceEnv("security", "ACCOUNTS_REVOCATION_FAIL_OPEN")), "true")
	if revocationFailOpen {
		wool.Get(ctx).Warn("ACCOUNTS_REVOCATION_FAIL_OPEN enabled: a revocation-store outage will admit possibly-revoked access tokens on the direct verify path until they expire")
	}
	minter := ed25519minter.New(ed25519minter.Config{
		Issuer:                     "saas-starter",
		Audience:                   "saas-starter",
		SessionPolicy:              sessionPolicy,
		AdditionalVerificationKeys: previousSigningKeys(ctx),
		RevocationFailOpen:         revocationFailOpen,
	}, priv, sessionStore)

	service.SetIdentityResolver(resolver)
	service.SetJWTMinter(minter)
	// The standards-named HTTP endpoint must return a top-level JSON Web Key
	// Set. grpc-gateway otherwise wraps the document in JWKSResponse.keys_json,
	// which generic verifiers correctly reject.
	adapters.RegisterHTTPRoute(
		"/v1/auth/.well-known/jwks.json",
		adapters.NewJWKSHTTPHandler(service),
	)
	// Composed-module REST federation: the gateway admits a registration only
	// against a token signed here, so a module exchanges its composition-declared
	// registration secret for one. Unset means no module may federate.
	moduleRegistrationSecrets, err := business.ParseRegistrationSecrets(
		workspaceEnv("federation", "MODULE_REGISTRATION_SECRETS"))
	if err != nil {
		return nil, fmt.Errorf("read module registration secrets: %w", err)
	}
	service.SetModuleRegistrar(minter, moduleRegistrationSecrets)
	if err := configureModuleIdentity(service); err != nil {
		return nil, err
	}

	// Solution registration: the same issuer, a separate declaration. A solution
	// remote executes in the host origin with the viewer's credentials, so who
	// may publish one is stated on its own key rather than inherited from the
	// module list. Unset means no solution may register.
	solutionRegistrationSecrets, err := business.ParseRegistrationSecrets(
		workspaceEnv("federation", "SOLUTION_REGISTRATION_SECRETS"))
	if err != nil {
		return nil, fmt.Errorf("read solution registration secrets: %w", err)
	}
	service.SetSolutionRegistrar(minter, solutionRegistrationSecrets)

	// Permissions plugin: configure signing keys before NewServer builds the
	// generated gRPC registrations. The ed25519 key is
	// the SAME one we use for JWT minting (saas-starter's cluster
	// identity); plugins running in this cluster verify both with
	// the matching public key. The HMAC fallback is read through the Codefly
	// SDK; the host populates it when spawning plugins. In
	// dev (no host, no env), v2 (ed25519) takes precedence so the
	// approve flow still works end-to-end.
	permissionsplugin.Default().
		WithEd25519Key([]byte(priv)).
		WithHMACSecret([]byte(codefly.ScopedAuthSecret())).
		WithWorkContextAuthority("saas-starter", minter.KeyID())

	// Server-side OAuth state signer. Seeded from the JWT private key so
	// state survives across api restarts and is consistent across
	// instances. Without this, OAuth callbacks rely solely on the FE's
	// sessionStorage check — fine for single-page-app threat models but
	// not defense-in-depth.
	stateSigner, err := auth.NewOAuthStateSigner(priv)
	if err != nil {
		return nil, fmt.Errorf("configure oauth state signer: %w", err)
	}
	service.SetOAuthStateSigner(stateSigner)

	// Authentication mode is explicit in the Codefly identity configuration.
	// A selected fixture is an optional data seed and cannot replace the
	// configured provider. Fixture authentication must itself be selected and
	// additionally requires an explicit fixture.
	v, ex, err := buildProviderStack(authProvider, selectedFixture)
	if err != nil {
		return nil, fmt.Errorf("configure authentication: %w", err)
	}
	switch authProvider {
	case "dev":
		service.SetDevelopmentTokenValidator(v)
	case "header-jwt":
		// Gateway-pre-authenticated: no OAuth ceremony, no code exchange. The
		// login route consumes the configured identity header and hands its
		// value to the validator; sessions/refresh/MFA are unchanged afterwards.
		headerName := identityEnv("IDENTITY_HEADER_NAME")
		if !hasConfiguredValue(headerName) {
			return nil, fmt.Errorf("identity provider header-jwt requires IDENTITY_HEADER_NAME")
		}
		service.SetTokenValidator(v)
		adapters.SetHeaderJWTLoginHeader(headerName)
	default:
		// user_identities.provider is a foreign key into the identity_providers
		// catalog. Verify the configured provider is registered now so an
		// unseeded name fails at startup with a precise error instead of a raw
		// FK violation at the user's first login.
		registered, err := store.ProviderRegistered(ctx, authProvider)
		if err != nil {
			return nil, fmt.Errorf("verify identity provider registration: %w", err)
		}
		if !registered {
			return nil, fmt.Errorf(
				"identity provider %q is not registered in identity_providers; add a database migration seeding it", authProvider)
		}
		if authProvider == "workos" {
			// SSO administration is a WorkOS-specific optional adapter. Other
			// identity providers cannot accidentally activate it by exposing a
			// similarly named management credential.
			service.SetSSOManagementAPIKey(identityEnv("IDENTITY_MANAGEMENT_API_KEY"))
		}
		oauthPolicy, err := buildOAuthRequestPolicy(authProvider)
		if err != nil {
			return nil, fmt.Errorf("configure OAuth request policy: %w", err)
		}
		service.SetOAuthRequestPolicy(oauthPolicy)
		service.SetTokenValidator(v)
		service.SetCodeExchanger(ex)

		// Per-org identity provider registry (issue #107). Orgs with an active
		// row in org_identity_providers resolve to their own stack; every other
		// org falls back to this global default (v, ex). Stacks build lazily on
		// first use and are cache-invalidated when their configuration changes.
		service.SetIdentityProviderRegistry(
			newIdentityProviderRegistry(store, vaultClient, authProvider, v, ex))
	}

	// Audit persistence and matching webhook fan-out share one database
	// transaction. There is no process-local queue to saturate or lose on crash.
	// AUDIT_SINK=both additionally tees each org-scoped audit row to an external
	// warehouse, fed asynchronously from the durable outbox — Postgres stays the
	// atomic source of truth (an external destination cannot join its tx).
	auditSinkMode, externalAuditSink, err := configuredAuditSink()
	if err != nil {
		return nil, err
	}
	var auditEmitterOpts []business.DurableAuditEmitterOption
	if auditSinkMode == auditSinkBoth {
		auditEmitterOpts = append(auditEmitterOpts, business.WithExternalTee())
	}
	// Every org-scoped audit record publishes its external domain event in the
	// same transaction; that event is what the relay fans out to the endpoints
	// subscribed to its type.
	auditEmitterOpts = append(auditEmitterOpts, business.WithDomainEventTransport(eventTransport))
	auditEmitter, err := business.NewDurableAuditEmitter(store, store, auditEmitterOpts...)
	if err != nil {
		return nil, err
	}
	service.SetAuditEmitter(auditEmitter)
	// Refuse to serve behind an emitter that cannot write on the caller's
	// transaction: every security mutation commits its audit row and webhook
	// fan-out inside its own transaction, and an emitter without EmitTx would let
	// those mutations succeed unrecorded.
	if err := service.VerifyAuditWiring(); err != nil {
		return nil, err
	}

	var auditExportWorker *jobs.Worker
	if auditSinkMode == auditSinkBoth {
		// The tee carries org-scoped events only. Control-plane / platform-admin
		// audit events (NULL org) are Postgres-only: the job platform reserves
		// global-scope enqueue for the privileged worker pool, which opens its own
		// transaction and so cannot commit atomically with the audit row. Surface
		// this so operators don't assume the warehouse holds platform events.
		w.Warn("AUDIT_SINK=both tees only org-scoped audit events to the external sink; control-plane/platform-admin (NULL-org) events remain Postgres-only")
		auditExportHandler, err := business.NewAuditExportJobHandler(externalAuditSink)
		if err != nil {
			return nil, err
		}
		auditExportWorker, err = jobs.NewWorker(jobs.WorkerConfig{
			Store:      jobStore,
			Queue:      business.AuditExportQueue,
			Handler:    auditExportHandler,
			RetryDelay: business.AuditExportRetryDelay,
		})
		if err != nil {
			return nil, err
		}
	}

	// Reconcile the audit event-type registry projection from the code catalog
	// and provision the current + upcoming monthly partitions so audit writes
	// always have a target. Best-effort: a transient failure here must not
	// block boot; the retention tick re-provisions partitions on its cycle.
	if err := store.WithControlPlane(ctx, func(ctx context.Context) error {
		return store.SyncAuditEventTypes(ctx, business.AuditEventCatalog())
	}); err != nil {
		wool.Get(ctx).Warn("audit event-type registry sync failed", wool.ErrField(err))
	}
	if err := store.WithControlPlane(ctx, func(ctx context.Context) error {
		return store.EnsureAuditPartitions(ctx, 3)
	}); err != nil {
		wool.Get(ctx).Warn("audit partition provisioning failed", wool.ErrField(err))
	}

	// Every outbound path shares the generated generic job runtime. This
	// separate pool can only read endpoint configuration and project outcomes.
	webhookSender := business.NewWebhookSender(vaultClient, webhookPolicy)
	webhookProjectionPool, err := infra.NewWebhookProjectionPool(ctx)
	if err != nil {
		return nil, fmt.Errorf("configure outbound webhook projection database pool: %w", err)
	}
	webhookJobHandler, err := business.NewOutboundWebhookJobHandler(
		infra.NewPostgresWebhookProjection(webhookProjectionPool), webhookSender,
	)
	if err != nil {
		webhookProjectionPool.Close()
		return nil, err
	}
	webhookWorker, err := jobs.NewWorker(jobs.WorkerConfig{
		Store: jobStore, Queue: business.OutboundWebhookQueue,
		Handler: webhookJobHandler, RetryDelay: business.OutboundWebhookRetryDelay,
	})
	if err != nil {
		webhookProjectionPool.Close()
		return nil, err
	}

	entitlementChecker := business.NewDefaultEntitlementChecker(store)
	service.SetEntitlementChecker(entitlementChecker)

	// Cache wiring — optional. When the `cache` dependency is declared in
	// service.codefly.yaml and Redis is reachable, org-membership lookups
	// get a 30s TTL cache backed by Redis (per-tenant keyed as
	// "orgmember:<orgID>:<userID>"). When the dep is absent or Redis is
	// unreachable, NewRedisCache returns nil and the app runs without
	// caching — zero behavior change, just slower auth checks.
	var closeCache func() error
	rateLimiterWired := false
	if redisCache, c, rerr := infra.NewRedisCache(ctx); rerr == nil && redisCache != nil {
		orgCache := cache.NewOrgMembershipCache(redisCache)
		adapters.WithOrgMembershipCache(orgCache)
		service.SetMembershipInvalidator(adapters.NewCacheInvalidator())
		// Wire Redis-backed access-token revocation. Without this,
		// Logout only kills the refresh chain — old access tokens
		// remain valid until natural expiry (15 min default).
		minter.SetRevoker(cache.NewTokenRevoker(redisCache))
		// Redis-backed OAuth-state one-shot list so a captured state can't be
		// replayed within its TTL across replicas (the in-memory default only
		// covers a single process).
		stateSigner.SetNonceConsumer(cache.NewOAuthNonceConsumer(redisCache))
		// Per-org / per-API-key rate limiting. Falls back to
		// allow-all if redisCache is nil (no Redis available).
		adapters.WithRateLimiter(cache.NewRateLimiter(redisCache))
		rateLimiterWired = true
		closeCache = c
	}
	if anonymousEndpointsUnprotected(abuseDisabled, rateLimiterWired) {
		w.Warn("ANONYMOUS ENDPOINTS UNPROTECTED — abuse protection is disabled AND no Redis rate limiter is wired, so Authenticate/RegisterUser/JoinWaitlist/SendMagicLink have NO app-layer throttle; enable ABUSE_PROTECTION_MODE=turnstile or wire the cache dependency before serving production traffic")
	}

	adapters.WithService(service)
	custodyServer, err := configuredExecutionCustody(store, vaultClient, minter, minter.KeyID(), priv, rateLimiterWired, revocationFailOpen)
	if err != nil {
		return nil, err
	}

	// Local development surfaces the underlying Authenticate failure reason for
	// debugging; every deployed environment returns generic auth errors so the
	// identity/enumeration oracle stays closed (#208).
	adapters.SetExposeAuthErrorDetail(codefly.IsLocal())

	// Separate shared-secret guards for internal RPC admission and forwarded
	// gateway identity. Empty values fail closed; production deploys provide
	// independent high-entropy values to both accounts and auth-gateway.
	adapters.SetInternalToken(workspaceEnv("internal-auth", "CODEFLY_INTERNAL_TOKEN"))
	// A previous internal token stays valid alongside the current one during an
	// overlapping rotation window, so callers can be migrated without a flag day.
	adapters.SetInternalTokenRotation(workspaceEnv("internal-auth", "CODEFLY_INTERNAL_TOKEN_PREVIOUS"))
	adapters.SetGatewayToken(workspaceEnv("internal-auth", "CODEFLY_GATEWAY_TOKEN"))
	// The datasource content-ticket signer is keyed from the same internal secret,
	// domain-separated, so a change-set job's opaque content ticket verifies at
	// redemption without a second key to provision.
	service.SetDatasourceTicketKey([]byte(workspaceEnv("internal-auth", "CODEFLY_INTERNAL_TOKEN")))

	centralEnforcement, err := configuredCentralEnforcement()
	if err != nil {
		return nil, err
	}
	adapters.SetCentralEnforcementMode(centralEnforcement)

	// /v1/status — public health probe surface. Probes run in parallel
	// with a 2s budget each; overall status is the worst result. The
	// FE /status page reads this; k8s liveness/readiness can too.
	adapters.RegisterStatusProbe(adapters.StatusProbe{
		Name: "postgres",
		Check: func(ctx context.Context) error {
			return store.Pool().Ping(ctx)
		},
	})
	if vaultClient != nil {
		adapters.RegisterStatusProbe(adapters.StatusProbe{
			Name:  "vault",
			Check: vaultClient.Health,
		})
	}
	adapters.RegisterHTTPRoute("/v1/status", adapters.NewStatusHTTPHandler(service))

	// Email production and transport are split by the generic outbox. Request
	// paths render templates and enqueue exact messages in their product
	// transaction; this worker is the only owner of the provider adapter.
	fromAddr := applicationEnv("EMAIL_FROM")
	if fromAddr == "" {
		fromAddr = "no-reply@localhost"
	}
	appBase, err := configuredApplicationBaseURL()
	if err != nil {
		return nil, err
	}
	templateStore := infra.NewPostgresTemplateStore(store)
	requestEmailOutbox, err := email.NewOutbox(store, templateStore, fromAddr)
	if err != nil {
		return nil, err
	}
	service.SetEmailOutbox(requestEmailOutbox, appBase)
	workerEmailOutbox, err := email.NewOutbox(jobStore, templateStore, fromAddr)
	if err != nil {
		return nil, err
	}
	emailSender, err := configuredEmailSender(ctx)
	if err != nil {
		return nil, err
	}
	if resend, ok := emailSender.(*email.ResendSender); ok {
		path, resendWebhook, err := resend.DeliveryWebhook(jobStore)
		if err != nil {
			return nil, err
		}
		adapters.RegisterHTTPRoute(path, resendWebhook)
	}
	emailJobHandler, err := email.NewJobHandler(emailSender)
	if err != nil {
		return nil, err
	}
	emailWorker, err := jobs.NewWorker(jobs.WorkerConfig{
		Store: jobStore, Queue: email.DeliveryQueue,
		Handler: emailJobHandler, RetryDelay: email.DeliveryRetryDelay,
	})
	if err != nil {
		return nil, err
	}

	// Selecting the free plan is a first-party operation and must remain
	// available when Stripe is not configured (the default local/test setup).
	billingHTTPHandler := adapters.NewBillingHTTPHandler(service)
	adapters.RegisterHTTPRoute("/v1/billing/free-plan", billingHTTPHandler)

	// Billing: when Stripe is configured, wire its webhook plus the
	// authenticated checkout and portal endpoints. The auth-gateway's public-path
	// allowlist covers the webhook; user-facing actions are authenticated via
	// forwarded identity headers.
	var stripeWebhookWorker *jobs.Worker
	var billingWorkerPool interface{ Close() }
	billingProvider := strings.ToLower(strings.TrimSpace(os.Getenv("BILLING_PROVIDER")))
	switch billingProvider {
	case "", "disabled":
		if os.Getenv("STRIPE_API_KEY") != "" || os.Getenv("STRIPE_WEBHOOK_SECRET") != "" {
			return nil, fmt.Errorf("billing: Stripe credentials are present while BILLING_PROVIDER is disabled")
		}
	case "stripe":
		stripeKey := strings.TrimSpace(os.Getenv("STRIPE_API_KEY"))
		whSecret := strings.TrimSpace(os.Getenv("STRIPE_WEBHOOK_SECRET"))
		if stripeKey == "" || whSecret == "" {
			return nil, fmt.Errorf("billing: STRIPE_API_KEY and STRIPE_WEBHOOK_SECRET are required when BILLING_PROVIDER=stripe")
		}
		stripeClient, err := billing.New(billing.Config{
			APIKey:  stripeKey,
			BaseURL: strings.TrimSpace(os.Getenv("STRIPE_API_BASE")),
		})
		if err != nil {
			return nil, fmt.Errorf("billing: %w", err)
		}
		billingBaseURL, err := configuredBillingBaseURL()
		if err != nil {
			return nil, err
		}
		workerPool, err := infra.NewBillingWorkerPool(ctx)
		if err != nil {
			return nil, fmt.Errorf("billing: configure worker database pool: %w", err)
		}
		billingWorkerPool = workerPool
		workerStore := pgbilling.New(workerPool)
		service.SetBillingRedirects(business.BillingRedirects{
			CheckoutSuccessURL: billingBaseURL + "/admin/billing/success?session_id={CHECKOUT_SESSION_ID}",
			CheckoutCancelURL:  billingBaseURL + "/admin/billing",
			PortalReturnURL:    billingBaseURL + "/admin/billing",
		})

		billingNotifier := &billingNotifier{
			outbox:        workerEmailOutbox,
			notifications: service,
			billingURL:    billingBaseURL + "/admin/billing",
		}

		adapters.RegisterHTTPRoute("/v1/billing/webhook", billing.NewHandler(billing.HandlerDeps{
			Producer:      jobStore,
			WebhookSecret: whSecret,
		}))
		stripeWebhookJobHandler, err := billing.NewStripeWebhookJobHandler(
			billing.NewProcessor(billing.ProcessorDeps{
				Store:    workerStore,
				Client:   stripeClient,
				Notifier: billingNotifier,
			}),
		)
		if err != nil {
			workerPool.Close()
			billingWorkerPool = nil
			return nil, err
		}
		stripeWebhookWorker, err = jobs.NewWorker(jobs.WorkerConfig{
			Store:      jobStore,
			Queue:      billing.StripeWebhookQueue,
			Handler:    stripeWebhookJobHandler,
			RetryDelay: billing.StripeWebhookRetryDelay,
		})
		if err != nil {
			workerPool.Close()
			billingWorkerPool = nil
			return nil, err
		}
		service.SetBillingClient(stripeClient)
		adapters.RegisterHTTPRoute("/v1/billing/checkout", billingHTTPHandler)
		adapters.RegisterHTTPRoute("/v1/billing/portal", billingHTTPHandler)
	default:
		return nil, fmt.Errorf("BILLING_PROVIDER must be disabled or stripe")
	}

	// Datasource ingestion (issues #274/#275): the leased worker that performs
	// off-request repo pulls runs whenever datasources are usable. It leases sync
	// requests enqueued by DatasourceService.SyncSource and walks the repo without
	// a request deadline, so a large repo can't time out the RPC and gets retry
	// backoff long enough to outlast a GitHub rate-limit window.
	datasourceSyncWorker, err := jobs.NewWorker(jobs.WorkerConfig{
		Store:      jobStore,
		Queue:      business.DatasourceSyncRequestQueue,
		Handler:    service.NewDatasourceSyncJobHandler(),
		RetryDelay: business.DatasourceSyncRetryDelay,
	})
	if err != nil {
		return nil, err
	}

	// Privacy export/deletion (issue #539): the leased worker that drives a
	// configured privacy adapter. It runs whether or not one is wired — the
	// starter ships none — so a job enqueued by a runtime that had an adapter
	// dead-letters visibly here instead of sitting pending after the adapter is
	// removed.
	privacyWorker, err := jobs.NewWorker(jobs.WorkerConfig{
		Store:      jobStore,
		Queue:      business.PrivacyWorkflowQueue,
		Handler:    service.NewPrivacyJobHandler(),
		RetryDelay: business.PrivacyWorkflowRetryDelay,
	})
	if err != nil {
		return nil, err
	}

	// The change-set compiler (issue #487): a leased worker that turns each raw
	// GitHub delivery — and each periodic/forced reconcile request — into a set of
	// per-file ingest ops, holding the source's decrypted token so all GitHub
	// calls carry it. The queue's per-source FIFO ordering key keeps one delivery
	// in flight per source, so a source's cursor is read and advanced without a
	// second delivery racing it.
	datasourceDeliveryWorker, err := jobs.NewWorker(jobs.WorkerConfig{
		Store:      jobStore,
		Queue:      business.DatasourceDeliveryQueue,
		Handler:    service.NewDatasourceDeliveryJobHandler(),
		RetryDelay: business.DatasourceSyncRetryDelay,
	})
	if err != nil {
		return nil, err
	}

	// The GitHub App installation reconciler (issue #691): it leases each
	// verified App-level delivery and re-derives the affected sources' access
	// from GitHub, rather than acting on what the delivery claimed.
	datasourceInstallationWorker, err := jobs.NewWorker(jobs.WorkerConfig{
		Store:      jobStore,
		Queue:      business.DatasourceInstallationQueue,
		Handler:    service.NewDatasourceInstallationJobHandler(),
		RetryDelay: business.DatasourceSyncRetryDelay,
	})
	if err != nil {
		return nil, err
	}

	// The inbound GitHub push webhook is an unauthenticated, un-rate-limited edge
	// that resolves a per-source signing secret from the credential store (a
	// control-plane DB read) on every request. It is opt-in per deployment so a
	// deployment not using datasources exposes no such surface; once enabled, a
	// source added through the SDK is live with no redeploy. Receipt verifies
	// X-Hub-Signature-256 and persists the raw delivery to the jobs inbox under
	// the GitHub delivery id; the documents ingest service consumes it — saas owns
	// connection, documents owns ingest.
	if strings.EqualFold(strings.TrimSpace(os.Getenv("DATASOURCE_GITHUB_WEBHOOK_ENABLED")), "true") {
		adapters.RegisterHTTPRoute(datasource.GitHubWebhookPath, datasource.NewHandler(
			datasource.GitHubWebhookPath,
			datasource.HandlerDeps{Producer: jobStore, Sources: datasourceSourceResolver{svc: service}},
		))
		w.Info("GitHub datasource webhook enabled")
	}

	// The App's own lifecycle deliveries arrive at a second, App-wide endpoint.
	// `installation` and `installation_repositories` are delivered only to the
	// App registration's webhook URL and signed with the registration's own
	// secret, so neither the per-source path nor a per-source secret can receive
	// them. Mounting is gated on an actual registration, so a deployment that
	// registered no App exposes no such surface.
	if service.GitHubAppWebhookConfigured() {
		adapters.RegisterHTTPRoute(datasource.GitHubAppWebhookPath, datasource.NewAppHandler(
			datasource.AppHandlerDeps{Producer: jobStore, Registration: service},
		))
		w.Info("GitHub App lifecycle webhook enabled")
	} else if service.GitHubAppConfigured() {
		// Half a registration is the dangerous shape: sources mint App tokens and
		// look healthy, while GitHub's lifecycle deliveries land on a route that
		// does not exist. Revocation then stays invisible for the life of a
		// cached token with nothing anywhere to say why.
		w.Warn("GitHub App registered without a webhook secret; installation lifecycle events cannot be verified and will not be received")
	}

	// Start background data retention goroutine. Runs once on startup and
	// then every 24 hours, deleting records older than their configured
	// retention period.
	retentionCtx, retentionCancel := context.WithCancel(ctx)
	go func() {
		rw := wool.Get(retentionCtx).In("retention")
		runRetention := func() {
			if deleted, err := service.RunRetention(retentionCtx); err != nil {
				rw.Warn("scheduled run failed", wool.ErrField(err))
			} else {
				for k, v := range deleted {
					if v > 0 {
						rw.Info("deleted records", wool.Field("count", v), wool.Field("kind", k))
					}
				}
			}
		}
		// Single-use replay markers expire with their token (≤ 15 min), so they
		// are swept far more often than the daily retention pass or they would
		// pile up for a day before reclamation.
		sweepReplay := func() {
			if n, err := service.PurgeExpiredWorkContextReplays(retentionCtx); err != nil {
				rw.Warn("replay marker sweep failed", wool.ErrField(err))
			} else if n > 0 {
				rw.Info("deleted records", wool.Field("count", n), wool.Field("kind", "work_context_replay"))
			}
		}

		// An export artifact stays reachable only for its authorized window; the
		// sweep asks the adapter to delete the stored object and drops the
		// reference once that window has closed.
		sweepPrivacyArtifacts := func() {
			if n, err := service.PurgeExpiredPrivacyArtifacts(retentionCtx); err != nil {
				rw.Warn("expired privacy artifact sweep failed", wool.ErrField(err))
			} else if n > 0 {
				rw.Info("deleted records", wool.Field("count", n), wool.Field("kind", "privacy_export_artifact"))
			}
		}

		// Datasource reconcile (issue #487 §6): the production safety net for lost
		// webhooks and for local development without a public tunnel. Each sweep
		// enqueues a reconcile job for every active GitHub source whose schedule has
		// elapsed; the job resolves the head and snapshots only if it moved, so the
		// sweep does no GitHub work itself.
		sweepReconcile := func() {
			if n, err := service.RunDatasourceReconcile(retentionCtx); err != nil {
				rw.Warn("datasource reconcile sweep failed", wool.ErrField(err))
			} else if n > 0 {
				rw.Info("enqueued datasource reconciles", wool.Field("count", n))
			}
		}

		// GitHub App installation re-check (issue #691): the same safety net, for
		// the half that webhooks alone cannot cover. Parking a source removes it
		// from the reconcile sweep above, so a restored installation whose
		// `unsuspend` delivery GitHub failed to hand over would leave that source
		// parked for good. This re-verifies installations that still hold one.
		// The sweep runs on the same tick, but each installation is only enqueued
		// once per re-check window, so the tick does not set the rate.
		sweepInstallationRecheck := func() {
			if n, err := service.RunGitHubInstallationRecheck(retentionCtx); err != nil {
				rw.Warn("github installation recheck sweep failed", wool.ErrField(err))
			} else if n > 0 {
				rw.Info("enqueued github installation rechecks", wool.Field("count", n))
			}
		}

		sweepCustody := func() {
			if err := store.PurgeExecutionCustody(retentionCtx, time.Now()); err != nil {
				rw.Warn("execution custody expiry sweep failed")
			}
		}

		// Run once immediately on startup.
		sweepCustody()
		runRetention()
		sweepReplay()
		sweepPrivacyArtifacts()
		sweepReconcile()
		sweepInstallationRecheck()

		retentionTicker := time.NewTicker(24 * time.Hour)
		replayTicker := time.NewTicker(time.Hour)
		reconcileTicker := time.NewTicker(time.Minute)
		defer retentionTicker.Stop()
		defer replayTicker.Stop()
		defer reconcileTicker.Stop()
		for {
			select {
			case <-retentionCtx.Done():
				return
			case <-retentionTicker.C:
				runRetention()
			case <-replayTicker.C:
				sweepReplay()
				sweepPrivacyArtifacts()
			case <-reconcileTicker.C:
				sweepCustody()
				sweepReconcile()
				sweepInstallationRecheck()
			}
		}
	}()

	if selectedFixture != "" {
		err = fixtures.Seed(ctx, service, selectedFixture)
		if err != nil {
			retentionCancel()
			return nil, err
		}
	}
	closeCustody, err := startExecutionCustody(ctx, custodyServer)
	if err != nil {
		retentionCancel()
		return nil, err
	}
	if stripeWebhookWorker != nil {
		stripeWebhookWorker.Start(ctx)
	}
	if jobOperationsMonitor != nil {
		jobOperationsMonitor.Start(ctx)
	}
	if analyticsWorker != nil {
		analyticsWorker.Start(ctx)
	}
	if auditExportWorker != nil {
		auditExportWorker.Start(ctx)
	}
	emailWorker.Start(ctx)
	webhookWorker.Start(ctx)
	datasourceSyncWorker.Start(ctx)
	privacyWorker.Start(ctx)
	datasourceDeliveryWorker.Start(ctx)
	datasourceInstallationWorker.Start(ctx)
	eventRelayWorker.Start(ctx)

	return func() {
		closeCustody()
		sw := wool.Get(ctx).In("shutdown")
		if stripeWebhookWorker != nil {
			sw.Info("stopping Stripe webhook worker")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := stripeWebhookWorker.Shutdown(shutdownCtx); err != nil {
				sw.Warn("Stripe webhook worker shutdown timed out", wool.ErrField(err))
			}
			cancel()
		}
		if analyticsWorker != nil {
			sw.Info("stopping product analytics export worker")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := analyticsWorker.Shutdown(shutdownCtx); err != nil {
				sw.Warn("product analytics worker shutdown timed out", wool.ErrField(err))
			}
			cancel()
		}
		if auditExportWorker != nil {
			sw.Info("stopping audit export worker")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := auditExportWorker.Shutdown(shutdownCtx); err != nil {
				sw.Warn("audit export worker shutdown timed out", wool.ErrField(err))
			}
			cancel()
		}
		if jobOperationsMonitor != nil {
			sw.Info("stopping durable job metrics monitor")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := jobOperationsMonitor.Shutdown(shutdownCtx); err != nil {
				sw.Warn("job metrics monitor shutdown timed out", wool.ErrField(err))
			}
			cancel()
		}
		sw.Info("stopping email delivery worker")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := emailWorker.Shutdown(shutdownCtx); err != nil {
			sw.Warn("email delivery worker shutdown timed out", wool.ErrField(err))
		}
		cancel()
		sw.Info("stopping outbound webhook worker")
		shutdownCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		if err := webhookWorker.Shutdown(shutdownCtx); err != nil {
			sw.Warn("outbound webhook worker shutdown timed out", wool.ErrField(err))
		}
		cancel()
		sw.Info("stopping privacy workflow worker")
		shutdownCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		if err := privacyWorker.Shutdown(shutdownCtx); err != nil {
			sw.Warn("privacy workflow worker shutdown timed out", wool.ErrField(err))
		}
		cancel()
		sw.Info("stopping datasource sync worker")
		shutdownCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		if err := datasourceSyncWorker.Shutdown(shutdownCtx); err != nil {
			sw.Warn("datasource sync worker shutdown timed out", wool.ErrField(err))
		}
		cancel()
		sw.Info("stopping datasource delivery worker")
		shutdownCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		if err := datasourceDeliveryWorker.Shutdown(shutdownCtx); err != nil {
			sw.Warn("datasource delivery worker shutdown timed out", wool.ErrField(err))
		}
		cancel()
		sw.Info("stopping datasource installation worker")
		shutdownCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		if err := datasourceInstallationWorker.Shutdown(shutdownCtx); err != nil {
			sw.Warn("datasource installation worker shutdown timed out", wool.ErrField(err))
		}
		cancel()
		sw.Info("stopping domain-event relay worker")
		shutdownCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		if err := eventRelayWorker.Shutdown(shutdownCtx); err != nil {
			sw.Warn("domain-event relay worker shutdown timed out", wool.ErrField(err))
		}
		cancel()
		sw.Info("closing outbound webhook projection database pool")
		webhookProjectionPool.Close()
		sw.Info("closing generic job worker database pool")
		jobWorkerPool.Close()
		if billingWorkerPool != nil {
			sw.Info("closing Stripe projection database pool")
			billingWorkerPool.Close()
		}
		sw.Info("stopping retention goroutine")
		retentionCancel()
		sw.Info("closing audit emitter")
		auditEmitter.Close()
		sw.Info("audit emitter closed")
		if closeCache != nil {
			sw.Info("closing redis cache")
			if err := closeCache(); err != nil {
				sw.Warn("redis cache close failed", wool.ErrField(err))
			} else {
				sw.Info("redis cache closed")
			}
		}
		sw.Info("closing store")
		store.Close()
		sw.Info("store closed")
		if otelProvider != nil {
			sw.Info("flushing OTEL provider")
			// Bounded shutdown — exporter has its own flush window
			// (otlptrace's batcher). 5s is a sensible cap.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := otelProvider.Shutdown(shutdownCtx); err != nil {
				sw.Warn("OTEL shutdown failed", wool.ErrField(err))
			}
		}
		if otelMetricProvider != nil {
			sw.Info("flushing OTEL metrics provider")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := otelMetricProvider.Shutdown(shutdownCtx); err != nil {
				sw.Warn("OTEL metrics shutdown failed", wool.ErrField(err))
			}
		}
	}, nil
}

func configuredAnalyticsSink() (analytics.Destination, bool, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PRODUCT_ANALYTICS_MODE"))) {
	case "", "disabled":
		return analytics.NoopSink{}, false, nil
	case "noop":
		return analytics.NoopSink{}, true, nil
	case "posthog":
		sink, err := analytics.NewPostHog(analytics.PostHogConfig{
			APIKey:         os.Getenv("POSTHOG_PROJECT_API_KEY"),
			PersonalAPIKey: os.Getenv("POSTHOG_PERSONAL_API_KEY"),
			ProjectID:      os.Getenv("POSTHOG_PROJECT_ID"),
			Host:           os.Getenv("POSTHOG_HOST"),
			APIHost:        os.Getenv("POSTHOG_API_HOST"),
		})
		if err != nil {
			return nil, false, err
		}
		return sink, true, nil
	default:
		return nil, false, fmt.Errorf("PRODUCT_ANALYTICS_MODE must be disabled, noop, or posthog")
	}
}

type auditSinkMode int

const (
	auditSinkPostgres auditSinkMode = iota
	auditSinkBoth
)

// configuredAuditSink selects the audit backend. "postgres" (default) keeps the
// durable emitter alone. "both" adds an asynchronous tee to an external
// warehouse while Postgres stays the atomic source of truth. "external" is
// rejected: an external destination cannot join the audit transaction, so it
// cannot replace the durable emitter without forfeiting audit/webhook
// atomicity — a deliberate posture we refuse to let a config value break.
func configuredAuditSink() (auditSinkMode, business.ExternalAuditSink, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AUDIT_SINK"))) {
	case "", "postgres":
		return auditSinkPostgres, nil, nil
	case "both":
		sink, err := configuredExternalAuditSink()
		if err != nil {
			return auditSinkPostgres, nil, err
		}
		return auditSinkBoth, sink, nil
	case "external":
		return auditSinkPostgres, nil, fmt.Errorf(
			"AUDIT_SINK=external is not permitted: Postgres is the atomic source of truth and an external destination cannot join its transaction; use AUDIT_SINK=both to tee to the external sink")
	default:
		return auditSinkPostgres, nil, fmt.Errorf("AUDIT_SINK must be postgres or both")
	}
}

func configuredExternalAuditSink() (business.ExternalAuditSink, error) {
	endpoint := strings.TrimSpace(os.Getenv("AUDIT_EXTERNAL_URL"))
	if endpoint == "" {
		return nil, fmt.Errorf("AUDIT_SINK=both requires AUDIT_EXTERNAL_URL for the external audit destination")
	}
	return business.NewHTTPAuditSink(business.HTTPAuditSinkConfig{
		Endpoint: endpoint,
		Token:    strings.TrimSpace(os.Getenv("AUDIT_EXTERNAL_TOKEN")),
	})
}

// anonymousEndpointsUnprotected reports whether the four anonymous endpoints
// have NO app-layer throttle: abuse protection disabled AND no rate limiter
// wired (no Redis). Either guard alone is a backstop; only the combination
// leaves them open.
func anonymousEndpointsUnprotected(abuseDisabled, rateLimiterWired bool) bool {
	return abuseDisabled && !rateLimiterWired
}

func configuredAbuseVerifier() (abuse.Verifier, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("ABUSE_PROTECTION_MODE")))
	secret := strings.TrimSpace(os.Getenv("TURNSTILE_SECRET_KEY"))
	switch mode {
	case "", "disabled":
		if secret != "" {
			return nil, fmt.Errorf("abuse: Turnstile secret is present while ABUSE_PROTECTION_MODE is disabled")
		}
		return abuse.DisabledVerifier{}, nil
	case "turnstile":
		allowed := strings.Split(os.Getenv("TURNSTILE_ALLOWED_HOSTNAMES"), ",")
		return abuse.NewTurnstileVerifier(abuse.TurnstileConfig{
			SecretKey:        secret,
			VerifyURL:        strings.TrimSpace(os.Getenv("TURNSTILE_VERIFY_URL")),
			AllowedHostnames: allowed,
		})
	default:
		return nil, fmt.Errorf("ABUSE_PROTECTION_MODE must be disabled or turnstile")
	}
}

func configuredMFAStepUpMaxAge() (time.Duration, error) {
	raw := strings.TrimSpace(workspaceEnv("security", "MFA_STEP_UP_MAX_AGE"))
	if raw == "" {
		return auth.DefaultRecentStepUpMaxAge, nil
	}
	maxAge, err := time.ParseDuration(raw)
	if err != nil || maxAge <= 0 || maxAge > 24*time.Hour {
		return 0, fmt.Errorf("MFA_STEP_UP_MAX_AGE must be a positive Go duration no greater than 24h")
	}
	return maxAge, nil
}

// configuredCentralEnforcement selects request-time central RBAC admission from
// the security configuration. "enforce" turns hard-deny on; "shadow" (and an
// unset value) keeps the classify-only fallback. Any other value fails the boot
// so a typo cannot silently leave enforcement off.
func configuredCentralEnforcement() (bool, error) {
	switch strings.ToLower(strings.TrimSpace(workspaceEnv("security", "RBAC_CENTRAL_ENFORCEMENT"))) {
	case "", "shadow":
		return false, nil
	case "enforce":
		return true, nil
	default:
		return false, fmt.Errorf(`RBAC_CENTRAL_ENFORCEMENT must be "shadow" or "enforce"`)
	}
}

func configuredSessionPolicy() (auth.SessionPolicy, error) {
	policy := auth.DefaultSessionPolicy()
	parseDuration := func(name string, fallback time.Duration) (time.Duration, error) {
		raw := strings.TrimSpace(workspaceEnv("security", name))
		if raw == "" {
			return fallback, nil
		}
		value, err := time.ParseDuration(raw)
		if err != nil {
			return 0, fmt.Errorf("%s must be a valid Go duration", name)
		}
		return value, nil
	}

	var err error
	policy.AbsoluteLifetime, err = parseDuration("SESSION_ABSOLUTE_LIFETIME", policy.AbsoluteLifetime)
	if err != nil {
		return auth.SessionPolicy{}, err
	}
	policy.IdleTimeout, err = parseDuration("SESSION_IDLE_TIMEOUT", policy.IdleTimeout)
	if err != nil {
		return auth.SessionPolicy{}, err
	}
	if raw := strings.TrimSpace(workspaceEnv("security", "SESSION_MAX_ACTIVE_DEVICES")); raw != "" {
		policy.MaxActiveDevices, err = strconv.Atoi(raw)
		if err != nil {
			return auth.SessionPolicy{}, fmt.Errorf("SESSION_MAX_ACTIVE_DEVICES must be an integer")
		}
	}
	if err := policy.Validate(); err != nil {
		return auth.SessionPolicy{}, fmt.Errorf("invalid session policy: %w", err)
	}
	if policy.AbsoluteLifetime < time.Hour || policy.AbsoluteLifetime > 365*24*time.Hour {
		return auth.SessionPolicy{}, fmt.Errorf("SESSION_ABSOLUTE_LIFETIME must be between 1h and 8760h")
	}
	if policy.IdleTimeout < 5*time.Minute {
		return auth.SessionPolicy{}, fmt.Errorf("SESSION_IDLE_TIMEOUT must be at least 5m")
	}
	if policy.MaxActiveDevices > 100 {
		return auth.SessionPolicy{}, fmt.Errorf("SESSION_MAX_ACTIVE_DEVICES must not exceed 100")
	}
	return policy, nil
}

func configuredApplicationBaseURL() (string, error) {
	raw := strings.TrimSpace(applicationEnv("APP_BASE_URL"))
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("application: APP_BASE_URL must be an exact http(s) origin")
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
		return "", fmt.Errorf("application: APP_BASE_URL must use https outside local development")
	}
	return strings.TrimSuffix(raw, "/"), nil
}

func configuredBillingBaseURL() (string, error) {
	return configuredApplicationBaseURL()
}

func configuredWebAuthn() (rpID, displayName string, origins []string, err error) {
	rpID = strings.TrimSpace(workspaceEnv("security", "WEBAUTHN_RP_ID"))
	if rpID == "" || strings.ContainsAny(rpID, "/:") {
		return "", "", nil, fmt.Errorf("WEBAUTHN_RP_ID must be a host name without scheme or port")
	}
	displayName = strings.TrimSpace(workspaceEnv("security", "WEBAUTHN_RP_DISPLAY_NAME"))
	if displayName == "" {
		displayName = "SaaS Starter"
	}
	for _, raw := range strings.Split(workspaceEnv("security", "WEBAUTHN_RP_ORIGINS"), ",") {
		origin := strings.TrimSpace(raw)
		if origin == "" {
			continue
		}
		parsed, parseErr := url.Parse(origin)
		if parseErr != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", "", nil, fmt.Errorf("WEBAUTHN_RP_ORIGINS contains invalid origin %q", origin)
		}
		origins = append(origins, strings.TrimSuffix(origin, "/"))
	}
	return rpID, displayName, origins, nil
}

// buildProviderStack returns the (TokenValidator, Exchanger) pair
// selected by the Codefly `identity` workspace configuration. Supported values:
//
//	fixture    — DevValidator reading the explicitly selected Codefly fixture.
//	             No exchanger (no OAuth code flow). Used for local iteration.
//	workos     — oidc.Validator + oidc.Exchanger preconfigured for
//	             WorkOS through the same generic identity contract.
//	oidc       — any spec-compliant OpenID Connect provider (Okta,
//	             PingFederate, Entra, Keycloak, …), configured entirely
//	             from discovery plus the IDENTITY_* contract.
//	auth0      — generic OIDC flow with Auth0 defaults.
//	google     — generic OIDC flow with Google defaults.
//
// Any other non-empty value is a generic OpenID Connect provider named by
// IDENTITY_PROVIDER (so two enterprise IdPs occupy distinct user_identities
// (provider, provider_id) namespaces) but only when the operator opts in with
// IDENTITY_GENERIC_OIDC=true. Empty, incomplete, and undeclared-unknown
// configurations return an error so the service cannot start with an ambiguous
// authentication boundary.
// workspaceEnv reads a key from a named Codefly workspace configuration,
// including its secret namespace, and falls back to a plain process variable
// for deployments that do not use Codefly's configuration provider.
func workspaceEnv(configuration, key string) string {
	if value, err := codefly.For(codefly.Context()).WorkspaceValue(configuration, key); err == nil && value != "" {
		return value
	}
	return os.Getenv(key)
}

func observabilityEnabled() bool {
	return strings.TrimSpace(workspaceEnv("observability", "OTEL_EXPORTER_OTLP_ENDPOINT")) != ""
}

// newDurableJobMetricsMonitor builds the durable job-operations metrics monitor
// only when OTEL metrics are enabled (metricsEnabled mirrors a non-nil
// otelMetricProvider, i.e. observabilityEnabled()). When metrics are disabled the
// global meter is a no-op, so a monitor would poll the job store every interval
// only to record into instruments nothing can read; returning a nil monitor lets
// the caller's Start/Shutdown nil-checks skip that background work entirely.
func newDurableJobMetricsMonitor(metricsEnabled bool, source jobs.Operations) (*jobs.OperationsMonitor, error) {
	if !metricsEnabled {
		return nil, nil
	}
	return jobs.NewOperationsMonitor(
		source,
		otel.Meter("github.com/codefly-dev/module-saas-starter/job-operations"),
		30*time.Second,
	)
}

// identityEnv is intentionally Codefly-only. Local dogfood, tests, and
// deployments all select a workspace configuration profile; raw process
// variables must not become a second, divergent identity authority.
func identityEnv(key string) string {
	value, _ := codefly.For(codefly.Context()).WorkspaceValue("identity", key)
	return value
}

// applicationEnv is also Codefly-only. Local product origins and bootstrap
// identity must come from the selected workspace configuration, never from an
// ambient shell file that can disagree with the browser runtime.
func applicationEnv(key string) string {
	value, _ := codefly.For(codefly.Context()).WorkspaceValue("application", key)
	return value
}

func configuredAuthProvider(selectedFixture string) string {
	provider := strings.ToLower(strings.TrimSpace(identityEnv("IDENTITY_PROVIDER")))
	switch provider {
	case "fixture", "dev":
		if selectedFixture == "" {
			return "fixture"
		}
		return "dev"
	default:
		return provider
	}
}

func hasConfiguredValue(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !strings.EqualFold(value, "REPLACE_ME")
}

func configuredOAuthRedirectURIs() []string {
	raw := identityEnv("IDENTITY_ALLOWED_REDIRECT_URIS")
	parts := strings.Split(raw, ",")
	redirectURIs := make([]string, 0, len(parts))
	for _, part := range parts {
		if redirectURI := strings.TrimSpace(part); redirectURI != "" {
			redirectURIs = append(redirectURIs, redirectURI)
		}
	}
	return redirectURIs
}

func buildOAuthRequestPolicy(provider string) (*auth.OAuthRequestPolicy, error) {
	return auth.NewOAuthRequestPolicy(provider, configuredOAuthRedirectURIs())
}

// buildDiscoveredOIDCStack configures an identity provider entirely from
// workspace configuration plus the provider's own OpenID metadata.
//
// The issuer, key set and token endpoint are facts the provider publishes at
// /.well-known/openid-configuration, so they are discovered rather than
// compiled in. Hardcoding them per provider is how this service ended up
// rejecting every WorkOS token with "issuer mismatch" after a successful code
// exchange — the constant was wrong in Go and no configuration could fix it.
//
// Discovery is skipped only when the operator has pinned everything it would
// supply: both IDENTITY_JWKS_URL and IDENTITY_TOKEN_URL, with IDENTITY_ISSUER as
// the expected `iss`. That is the escape hatch for air-gapped environments that
// cannot reach the well-known endpoint — otherwise a partial pin still discovers
// the rest, and any discovery outage fails startup closed rather than guessing.
func buildDiscoveredOIDCStack(provider string) (auth.TokenValidator, business.CodeExchanger, error) {
	// WorkOS validates its own access token, which binds to the application via a
	// non-standard client_id claim rather than aud == client id (see the oidc
	// validator and the WorkOS exchanger). Defaulting the audience to the client
	// id here would reject every WorkOS access token, so the binding stays
	// operator-configured (Audience or ClientIDClaim) as it is today.
	validator, tokenURL, clientID, clientSecret, err := discoverOIDCValidator(provider, false)
	if err != nil {
		return nil, nil, err
	}
	exchanger, err := workosauth.NewExchanger(workosauth.Config{
		TokenURL:     tokenURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Validator:    validator,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("initialize %s exchanger: %w", provider, err)
	}
	return validator, exchanger, nil
}

// buildGenericOIDCStack configures any spec-compliant OpenID Connect provider
// (Okta, PingFederate, Azure AD/Entra, Keycloak, …) from discovery plus the
// Codefly `identity` workspace configuration. It shares WorkOS's discovery and
// JWKS validation but pairs them with the standard OAuth 2.0 code-grant
// exchanger rather than the WorkOS authenticate adapter, which reads the
// verified email from a WorkOS-specific response shape no other IdP returns.
//
// provider is the configured IDENTITY_PROVIDER value; it is recorded on each
// identity as user_identities.provider. Two distinct enterprise IdPs avoid
// colliding in that namespace by selecting distinct IDENTITY_PROVIDER values
// (e.g. "okta", "ping"), each routed here. Using the same string the browser
// sends and the OAuth request policy enforces is required: authenticateWithCode
// rejects a login whose token provider disagrees with the request provider.
func buildGenericOIDCStack(provider string) (auth.TokenValidator, business.CodeExchanger, error) {
	// The generic stack validates a standard OIDC id_token (preferred over the
	// access token in authenticateWithCode), whose aud is the client id, so a
	// minimally-configured provider can default its audience binding to it.
	validator, tokenURL, clientID, clientSecret, err := discoverOIDCValidator(provider, true)
	if err != nil {
		return nil, nil, err
	}
	exchanger, err := oidc.NewExchanger(oidc.ExchangerConfig{
		TokenURL:     tokenURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("initialize %s exchanger: %w", provider, err)
	}
	return validator, oidc.AsBusinessExchanger(exchanger), nil
}

// discoverOIDCValidator builds the JWKS validator and resolves the token
// endpoint shared by every discovery-driven provider. provider is the
// configured IDENTITY_PROVIDER value: it is written to Claims.Provider (and thus
// user_identities.provider) and named in error messages. It is deliberately the
// same string the browser sends and the OAuth request policy enforces, so the
// two can never disagree at login.
func discoverOIDCValidator(provider string, defaultAudienceToClientID bool) (validator auth.TokenValidator, tokenURL, clientID, clientSecret string, err error) {
	clientID = identityEnv("IDENTITY_CLIENT_ID")
	clientSecret = identityEnv("IDENTITY_CLIENT_SECRET")
	issuer := identityEnv("IDENTITY_ISSUER")
	if !hasConfiguredValue(clientID) || !hasConfiguredValue(clientSecret) {
		return nil, "", "", "", fmt.Errorf(
			"identity provider %s requires IDENTITY_CLIENT_ID and IDENTITY_CLIENT_SECRET", provider)
	}
	if !hasConfiguredValue(issuer) {
		return nil, "", "", "", fmt.Errorf(
			"identity provider %s requires IDENTITY_ISSUER to discover provider metadata", provider)
	}

	// Start from any explicitly pinned endpoints; discovery fills only the gaps.
	expectedIssuer := issuer
	jwksURL := identityEnv("IDENTITY_JWKS_URL")
	tokenURL = identityEnv("IDENTITY_TOKEN_URL")
	if !hasConfiguredValue(jwksURL) || !hasConfiguredValue(tokenURL) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		discovered, err := oidc.Discover(ctx, issuer, nil)
		if err != nil {
			return nil, "", "", "", fmt.Errorf("discover %s provider metadata: %w", provider, err)
		}
		expectedIssuer = discovered.Issuer
		if !hasConfiguredValue(jwksURL) {
			jwksURL = discovered.JWKSURI
		}
		if !hasConfiguredValue(tokenURL) {
			tokenURL = discovered.TokenEndpoint
		}
	}

	cfg := oidc.Config{
		ProviderName:  provider,
		Issuer:        expectedIssuer,
		JWKSURL:       jwksURL,
		Audience:      identityEnv("IDENTITY_AUDIENCE"),
		OrgClaim:      identityEnvOrDefault("IDENTITY_ORG_CLAIM", "organization_id"),
		ClientIDClaim: identityEnv("IDENTITY_CLIENT_ID_CLAIM"),
		ClientID:      clientID,
		// Providers that return the verified profile in the token response
		// rather than in the signed token declare it here.
		AllowMissingEmail: identityEnv("IDENTITY_EMAIL_FROM_TOKEN_RESPONSE") == "true",
	}
	if claim := identityEnv("IDENTITY_EMAIL_CLAIM"); claim != "" {
		cfg.EmailClaim = claim
	}

	// Standard OIDC binds an id_token to its relying party through `aud` ==
	// client id. A minimally-configured provider supplies neither an explicit
	// IDENTITY_AUDIENCE nor a non-standard IDENTITY_CLIENT_ID_CLAIM, so default
	// the audience binding to the client id: without it oidc.New fails closed
	// ("an audience binding is required"), and demanding the non-standard
	// client_id claim rejects id_tokens (e.g. WorkOS AuthKit) that never carry it.
	// Only the generic id_token path opts in — WorkOS validates an access token
	// whose aud is not the client id, so it keeps requiring an explicit binding.
	if defaultAudienceToClientID && !hasConfiguredValue(cfg.Audience) && !hasConfiguredValue(cfg.ClientIDClaim) {
		cfg.Audience = clientID
	}

	v, err := oidc.New(cfg)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("initialize %s validator: %w", provider, err)
	}

	if strings.TrimSpace(tokenURL) == "" {
		return nil, "", "", "", fmt.Errorf(
			"identity provider %s published no token endpoint; set IDENTITY_TOKEN_URL", provider)
	}
	return v, tokenURL, clientID, clientSecret, nil
}

func identityEnvOrDefault(key, fallback string) string {
	if value := identityEnv(key); hasConfiguredValue(value) {
		return value
	}
	return fallback
}

func buildProviderStack(provider, selectedFixture string) (auth.TokenValidator, business.CodeExchanger, error) {
	switch provider {
	case "dev":
		if selectedFixture == "" {
			return nil, nil, fmt.Errorf("development authentication requires an explicit Codefly SDK-selected fixture")
		}
		fixturePath, err := fixtures.FixturePath(selectedFixture)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve development fixture: %w", err)
		}
		v, err := devvalidator.New(fixturePath)
		if err != nil {
			return nil, nil, fmt.Errorf("initialize development fixture validator: %w", err)
		}
		return v, nil, nil

	case "workos":
		return buildDiscoveredOIDCStack(provider)

	case "oidc":
		return buildGenericOIDCStack(provider)

	case "auth0":
		domain := identityEnv("IDENTITY_DOMAIN")
		audience := identityEnv("IDENTITY_AUDIENCE")
		clientID := identityEnv("IDENTITY_CLIENT_ID")
		clientSecret := identityEnv("IDENTITY_CLIENT_SECRET")
		if !hasConfiguredValue(domain) || !hasConfiguredValue(clientID) || !hasConfiguredValue(clientSecret) || !hasConfiguredValue(audience) {
			return nil, nil, fmt.Errorf("identity provider auth0 requires IDENTITY_DOMAIN, IDENTITY_AUDIENCE, IDENTITY_CLIENT_ID, and IDENTITY_CLIENT_SECRET")
		}
		v, err := oidc.New(oidc.Auth0Config(domain, audience))
		if err != nil {
			return nil, nil, fmt.Errorf("initialize Auth0 validator: %w", err)
		}
		ex, err := oidc.NewExchanger(oidc.ExchangerConfig{
			TokenURL:     fmt.Sprintf("https://%s/oauth/token", domain),
			ClientID:     clientID,
			ClientSecret: clientSecret,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("initialize Auth0 exchanger: %w", err)
		}
		return v, oidc.AsBusinessExchanger(ex), nil

	case "google":
		clientID := identityEnv("IDENTITY_CLIENT_ID")
		clientSecret := identityEnv("IDENTITY_CLIENT_SECRET")
		if !hasConfiguredValue(clientID) || !hasConfiguredValue(clientSecret) {
			return nil, nil, fmt.Errorf("identity provider google requires IDENTITY_CLIENT_ID and IDENTITY_CLIENT_SECRET")
		}
		v, err := oidc.New(oidc.GoogleConfig(clientID))
		if err != nil {
			return nil, nil, fmt.Errorf("initialize Google validator: %w", err)
		}
		ex, err := oidc.NewExchanger(oidc.ExchangerConfig{
			TokenURL:     "https://oauth2.googleapis.com/token",
			ClientID:     clientID,
			ClientSecret: clientSecret,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("initialize Google exchanger: %w", err)
		}
		return v, oidc.AsBusinessExchanger(ex), nil

	case "header-jwt":
		v, err := buildHeaderJWTValidator()
		if err != nil {
			return nil, nil, err
		}
		return v, nil, nil

	case "fixture":
		return nil, nil, fmt.Errorf("identity provider fixture requires an explicit Codefly fixture")
	case "":
		return nil, nil, fmt.Errorf("IDENTITY_PROVIDER is required in the Codefly identity workspace configuration")
	default:
		// A non-preset name is a generic OpenID Connect provider only when the
		// operator explicitly declares it one. Without that opt-in an unrecognized
		// value fails startup closed — so a typo of a preset (e.g. "wrokos") is
		// rejected here instead of silently building a generic stack that would
		// mismatch the intended provider's token shape and fail at first login.
		if identityEnv("IDENTITY_GENERIC_OIDC") != "true" {
			return nil, nil, fmt.Errorf(
				"unsupported identity provider %q; set IDENTITY_GENERIC_OIDC=true to configure it as a generic OpenID Connect provider", provider)
		}
		return buildGenericOIDCStack(provider)
	}
}

// buildHeaderJWTValidator configures the gateway-pre-authenticated validator
// from the Codefly identity configuration. Audience is mandatory; JWKS is
// mandatory unless the operator has deliberately opted into perimeter-trust
// decode via IDENTITY_PERIMETER_TRUST_DECODE.
func buildHeaderJWTValidator() (auth.TokenValidator, error) {
	v, err := headerjwt.New(headerjwt.Config{
		ProviderName:         identityEnvOrDefault("IDENTITY_PROVIDER_NAME", "header-jwt"),
		JWKSURL:              identityEnv("IDENTITY_JWKS_URL"),
		Audience:             identityEnv("IDENTITY_AUDIENCE"),
		Issuer:               identityEnv("IDENTITY_ISSUER"),
		SubjectClaim:         identityEnv("IDENTITY_SUBJECT_CLAIM"),
		EmailClaim:           identityEnv("IDENTITY_EMAIL_CLAIM"),
		EmailVerifiedClaim:   identityEnv("IDENTITY_EMAIL_VERIFIED_CLAIM"),
		NameClaims:           identityEnvList("IDENTITY_NAME_CLAIMS"),
		GroupClaim:           identityEnv("IDENTITY_GROUP_CLAIM"),
		AllowedGroups:        identityEnvList("IDENTITY_ALLOWED_GROUPS"),
		PerimeterTrustDecode: identityEnv("IDENTITY_PERIMETER_TRUST_DECODE") == "true",
	})
	if err != nil {
		return nil, fmt.Errorf("initialize header-jwt validator: %w", err)
	}
	return v, nil
}

// identityEnvList reads a comma-separated identity configuration value into a
// trimmed, non-empty slice.
func identityEnvList(key string) []string {
	raw := identityEnv(key)
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// configuredEmailSender makes provider selection explicit. Production never
// silently downgrades to a log sink because one Resend value is missing. Each
// factory validates its own secrets and fails closed; adding a provider is one
// Register call rather than a new switch case.
func configuredEmailSender(ctx context.Context) (email.Sender, error) {
	registry := email.NewRegistry()
	registry.Register("log", logEmailFactory)
	registry.Register("resend", resendEmailFactory)

	name := strings.TrimSpace(os.Getenv("EMAIL_PROVIDER"))
	if name == "" {
		name = "log"
	}
	return registry.Select(ctx, name)
}

func logEmailFactory(ctx context.Context) (email.Sender, error) {
	if os.Getenv("RESEND_API_KEY") != "" || os.Getenv("RESEND_WEBHOOK_SECRET") != "" {
		return nil, fmt.Errorf("email: Resend credentials are present while EMAIL_PROVIDER is log")
	}
	w := wool.Get(ctx).In("pickEmailSender")
	return email.NewLogSender(func(format string, args ...any) {
		w.Info(fmt.Sprintf(format, args...))
	}), nil
}

func resendEmailFactory(_ context.Context) (email.Sender, error) {
	key := strings.TrimSpace(os.Getenv("RESEND_API_KEY"))
	webhookSecret := strings.TrimSpace(os.Getenv("RESEND_WEBHOOK_SECRET"))
	if key == "" || webhookSecret == "" {
		return nil, fmt.Errorf("email: RESEND_API_KEY and RESEND_WEBHOOK_SECRET are required when EMAIL_PROVIDER=resend")
	}
	return email.NewResendSender(email.ResendConfig{
		APIKey:        key,
		BaseURL:       strings.TrimSpace(os.Getenv("RESEND_API_BASE")),
		WebhookSecret: webhookSecret,
	})
}

// previousSigningKeys returns any rotated-out signing keys the minter should
// still accept for verification, so access tokens signed by them keep verifying
// during an overlapping rotation window. JWT_PREVIOUS_PUBLIC_KEYS is a
// comma-separated list of base64 Ed25519 public keys; empty (the steady state)
// yields none. A malformed entry is logged and skipped rather than failing
// startup.
func previousSigningKeys(ctx context.Context) []ed25519core.PublicKey {
	var keys []ed25519core.PublicKey
	for _, encoded := range strings.Split(workspaceEnv("internal-auth", "JWT_PREVIOUS_PUBLIC_KEYS"), ",") {
		encoded = strings.TrimSpace(encoded)
		if encoded == "" {
			continue
		}
		pub, err := decodeEd25519PublicKey(encoded)
		if err != nil {
			wool.Get(ctx).In("previousSigningKeys").Warn("ignoring malformed previous signing key", wool.ErrField(err))
			continue
		}
		keys = append(keys, pub)
	}
	return keys
}

// decodeEd25519PublicKey accepts a standard or raw-url base64 Ed25519 public
// key. Operators paste keys in either form; both decode to the same 32 bytes.
func decodeEd25519PublicKey(encoded string) (ed25519core.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode public key: %w", err)
		}
	}
	if len(raw) != ed25519core.PublicKeySize {
		return nil, fmt.Errorf("wrong public key size: got %d want %d", len(raw), ed25519core.PublicKeySize)
	}
	return ed25519core.PublicKey(raw), nil
}

// devFixtureAuthProvider reports whether authProvider is one of the local
// fixture-backed modes. Only these may fall back to an ephemeral signing key;
// with any real identity provider the key must load from Vault.
func devFixtureAuthProvider(authProvider string) bool {
	return authProvider == "fixture" || authProvider == "dev"
}

// requireLocalForDevFixtureProvider refuses to start with the dev or fixture
// identity provider outside the local environment. Those providers accept
// unauthenticated identities by design; selecting one in a deployed environment
// (via IDENTITY_PROVIDER=dev/fixture) would turn the whole authentication
// boundary off, so it fails closed at startup instead.
func requireLocalForDevFixtureProvider(authProvider string, isLocal bool) error {
	if devFixtureAuthProvider(authProvider) && !isLocal {
		return fmt.Errorf("identity provider %q is only permitted in the local environment", authProvider)
	}
	return nil
}

// loadSigningKey returns the Ed25519 private key used to sign access and
// refresh tokens.
//
// The key must persist across restarts and be identical across replicas: it
// signs JWTs, seeds the OAuth-state signer, and is the public key the gateway's
// ext_authz check and permissions plugin pin. Production loads it from Vault KV v2 and refuses
// to boot if that load fails — an ephemeral key would make each replica sign
// differently, break existing sessions, and desynchronise the pinned key. This
// fails closed rather than fail-open-to-broken.
//
// allowEphemeral is set only in dev/fixture mode, where a freshly generated key
// lets `codefly run service frontend --fixture dev-admin` work on a machine with
// no Vault. The fallback logs a warning.
func loadSigningKey(ctx context.Context, allowEphemeral bool) (ed25519core.PrivateKey, error) {
	connection, connectionErr := vaultconnection.Load(ctx)
	if connectionErr == nil {
		vaultToken, tokenErr := connection.Token()
		if tokenErr != nil {
			return nil, tokenErr
		}
		priv, err := ed25519minter.LoadKeyFromVault(ctx, ed25519minter.VaultKeyLoaderConfig{
			Address: connection.Address, Token: vaultToken, HTTPClient: connection.Client,
			AllowInsecureHTTP: workspaceEnv("vault", "VAULT_ALLOW_INSECURE_HTTP") == "true",
		})
		if err == nil {
			return priv, nil
		}
		if !allowEphemeral {
			return nil, fmt.Errorf("load signing key from Vault: %w", err)
		}
		wool.Get(ctx).In("loadSigningKey").Warn("could not load signing key from Vault — falling back to ephemeral", wool.ErrField(err))
	} else if !allowEphemeral {
		return nil, fmt.Errorf("load signing key: Vault address and token are required outside dev/fixture mode")
	}
	_, priv, err := ed25519minter.GenerateKey()
	return priv, err
}

// billingNotifier converts a completed billing projection into channel-specific
// delivery commands.
type billingNotifier struct {
	outbox        *email.Outbox
	notifications *business.Service
	billingURL    string
}

func (n *billingNotifier) EnqueueBillingEmail(ctx context.Context, message billing.BillingEmail) error {
	if n == nil || n.outbox == nil {
		return fmt.Errorf("billing: email notifier is not configured")
	}
	variables := make(map[string]string, len(message.Variables)+1)
	for key, value := range message.Variables {
		variables[key] = value
	}
	variables["billing_url"] = n.billingURL
	return n.outbox.EnqueueTemplate(ctx, email.TemplateRequest{
		DeliveryKey: message.DeliveryKey,
		Scope:       email.TenantScope(message.OrganizationID),
		Source:      "saas.billing",
		Template:    message.Template,
		To:          message.To,
		Variables:   variables,
	})
}

func (n *billingNotifier) CreateBillingNotification(
	ctx context.Context,
	message billing.BillingNotification,
) error {
	if n == nil || n.notifications == nil {
		return fmt.Errorf("billing: in-app notifier is not configured")
	}
	_, err := n.notifications.CreateNotification(ctx, business.CreateNotificationInput{
		UserID:         message.RecipientID,
		OrgID:          message.OrganizationID,
		Title:          message.Title,
		Body:           message.Body,
		Type:           "billing",
		ActionURL:      message.ActionURL,
		Category:       business.NotificationCategoryBilling,
		IdempotencyKey: message.DeliveryKey,
	})
	return err
}

func configureModuleIdentity(service *business.Service) error {
	secrets, err := business.ParseRegistrationSecrets(workspaceEnv("federation", "MODULE_IDENTITY_SECRETS"))
	if err != nil {
		return fmt.Errorf("read module identity secrets: %w", err)
	}
	service.SetModuleIdentitySecrets(secrets)
	return nil
}
