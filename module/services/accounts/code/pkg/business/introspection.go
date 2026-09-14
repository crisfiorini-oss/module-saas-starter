package business

import (
	"context"
	"sort"

	"github.com/codefly-dev/core/wool"

	gen "accounts/pkg/gen/saas/accounts/v1"
	"accounts/pkg/relationcatalog"
)

// ServiceVersion is the semver of THIS service's API surface (the
// api service of the saas-starter module). Bump on proto-breaking
// changes; clients can branch on it via GetServiceInfo.
//
// Module-level version is a separate concern owned by the module
// declaration (module.codefly.yaml), not by this service.
const ServiceVersion = "0.4.0"

// GetServiceInfo returns the machine-readable catalog of THIS
// service: its RPC surface, RBAC vocabulary, RLS-protected tables,
// and accepted API-key scopes.
//
// Each codefly service owns its own proto and exposes its own
// IntrospectionService. A "module-level" view of saas-starter is an
// AGGREGATION concern: a CLI/gateway/aggregating host walks every service in
// the module and merges each service's GetServiceInfo response.
// That aggregator is intentionally out of scope here.
//
// Drift resistance: RPCs, HTTP routes, and enforcement policy are derived from
// the protobuf descriptor graph. Adding a method without a complete
// saas.policy.v1.method_policy option leaves it unclassified, so interceptors
// deny it and the completeness test fails. Only editorial descriptions remain
// in rpcDescriptions until P1-DOC-001 makes source comments compiler-readable.
//
// The redaction pass at the end strips platform_admin / mfa-tier
// RPCs for unauthenticated callers, and the RLS catalog with them
// (the catalog is exposed publicly at GET /v1/.well-known/service-info;
// no need to advertise the privileged attack surface to anonymous
// probes). The relation inventory names every user-scoped relation and
// the column that scopes it, and its notes describe the mechanisms
// behind each boundary — evidence for an authenticated auditor, a
// schema map for an anonymous one. Authenticate for it.
func (s *Service) GetServiceInfo(ctx context.Context, _ *gen.GetServiceInfoRequest) (*gen.GetServiceInfoResponse, error) {
	rpcs := buildRPCList()
	rlsTables := serviceRLSTables
	if !callerIsAuthenticated(ctx) {
		rpcs = redactPrivilegedRPCs(rpcs)
		rlsTables = nil
	}
	return &gen.GetServiceInfoResponse{
		Capabilities: &gen.ServiceCapabilities{
			Info:        serviceInfo,
			Rpcs:        rpcs,
			Permissions: servicePermissions,
			RlsTables:   rlsTables,
			Scopes:      serviceScopes,
		},
	}, nil
}

var serviceInfo = &gen.ServiceInfo{
	Name:        "accounts",
	Module:      "saas-starter",
	Version:     ServiceVersion,
	Description: "Tenant-facing API for saas-starter: auth, orgs, teams, RBAC, billing, webhooks, audit. Three-layer authz (handler gates + RBAC + Postgres RLS).",
	RepoUrl:     "https://github.com/codefly-dev/saas-starter",
}

// rpcDescriptions is the only hand-maintained per-method catalog data.
// Routing and enforcement metadata comes exclusively from protobuf method
// options; descriptions remain editorial prose until source comments are
// compiled into the service catalog.
var rpcDescriptions = withWorkContextConsumerDescriptions(map[string]string{
	"AccessibleScopeService/ListMyAccessibleScopes":           "List the scope nodes the authenticated caller may act on (bearer-derived subject).",
	"APIKeyService/CreateAPIKey":                              "Mint an API key for an administered organization.",
	"APIKeyService/ListAPIKeys":                               "List org's API keys.",
	"APIKeyService/RevokeAPIKey":                              "Revoke an API key in an administered organization.",
	"APIKeyService/ValidateAPIKey":                            "Internal: plaintext key → key + org id.",
	"AuditService/AggregateAuditLog":                          "Aggregate audit events (counts, time buckets, group-by) for analytics.",
	"AuditService/ExportAuditLog":                             "Download audit log as CSV/JSON.",
	"AuditService/ListAuditEventTypes":                        "List the registered audit event-type catalog for search facets.",
	"AuditService/QueryAuditLog":                              "Read audit events (org member sees own org; platform admin sees all).",
	"AuthService/Authenticate":                                "Exchange typed OAuth-code or explicit fixture credentials for tokens.",
	"AuthService/BeginOAuth":                                  "Mint signed OAuth state for an allowlisted redirect.",
	"AuthService/BeginWebAuthnMFAChallenge":                   "Begin a WebAuthn assertion bound to an MFA login transaction.",
	"AuthService/CompleteMFAChallenge":                        "Consume a one-use MFA login transaction and issue the session.",
	"AuthService/CompleteWebAuthnMFAChallenge":                "Verify WebAuthn and atomically consume the MFA login transaction.",
	"AuthService/GetJWKS":                                     "Public JWKS for JWT signature verification.",
	"AuthService/Logout":                                      "Revoke the caller's session and its refresh-token family.",
	"AuthService/RefreshToken":                                "Exchange a refresh token for a new access token, rotating the refresh token.",
	"AuthService/SwitchOrganization":                          "Exchange the active device session for an access token scoped to another current membership.",
	"BillingService/ListInvoices":                             "List the organization's past billing invoices.",
	"BillingService/ListPublicPlans":                          "Sanitized public pricing and entitlement catalog.",
	"BillingService/OpenPortal":                               "Stripe billing-portal session; requires billing:write and recent MFA.",
	"ConsentService/AcceptTerms":                              "Record acceptance of the exact Terms version presented.",
	"ConsentService/GetStatus":                                "Read TOS acceptance state.",
	"ConsentService/UpdatePreferences":                        "Persist purpose-based optional tracking choices and withdrawals.",
	"DashboardService/CreateDashboard":                        "Create a named, user-owned dashboard from a validated spec.",
	"DashboardService/DeleteDashboard":                        "Delete a dashboard the caller owns or administers.",
	"DashboardService/GetDashboard":                           "Open one dashboard the caller owns or that is shared to the org.",
	"DashboardService/ListDashboards":                         "List the caller's own and org-shared dashboards.",
	"DashboardService/ShareDashboard":                         "Change a dashboard's visibility between private and org-shared.",
	"DashboardService/UpdateDashboard":                        "Rename or replace the spec of a dashboard the caller owns or administers.",
	"DatasourceService/AddGitHubSource":                       "Connect a GitHub repository as a datasource, storing its access token and optional webhook secret encrypted.",
	"DatasourceService/AddSource":                             "Connect a datasource for any provider, storing its config and encrypted credential.",
	"DatasourceService/BeginGitHubAppSetup":                   "Start GitHub App onboarding: mint a one-time, tenant-bound setup state and return the App's install URL.",
	"DatasourceService/CompleteGitHubAppSetup":                "Redeem a setup state once, verify the returned GitHub App installation server-side, and list the repositories it grants.",
	"DatasourceService/MigrateGitHubSourceToApp":              "Re-point a token-backed GitHub source at the deployment's GitHub App in place, keeping its identity and history.",
	"DatasourceService/DeleteSource":                          "Remove a connected datasource and its stored credentials.",
	"DatasourceService/GetDatasourceCatalog":                  "List the available datasource provider types and their connect metadata.",
	"DatasourceService/GetSource":                             "Read one connected datasource in the org.",
	"DatasourceService/ListSources":                           "List the org's connected datasources.",
	"DatasourceService/SyncSource":                            "Pull the source's current contents and enqueue ingestion deliveries.",
	"DelegationService/DecideDelegation":                      "Approve or deny a delegation request.",
	"InstallationService/InstallSolution":                     "Install a solution: compose its agent principal, scope node, standing grant, and installation row.",
	"InstallationService/UninstallSolution":                   "Uninstall a solution and reverse its composition.",
	"InstallationService/TransferInstallationOwnership":       "Reassign an installation's accountable owner of record.",
	"InstallationService/GetInstallation":                     "Get one installation and its live health.",
	"DelegationService/ListPendingDelegations":                "List pending organization delegations.",
	"DelegationService/RequestDelegation":                     "Request a scoped authority delegation.",
	"DelegationService/WaitForDelegation":                     "Stream the terminal delegation decision.",
	"GDPRService/GetDeletionStatus":                           "Status of a GDPR deletion request.",
	"GDPRService/GetExportStatus":                             "Status of a GDPR export request.",
	"GDPRService/RequestDeletion":                             "Request account deletion when a complete privacy workflow is configured. Requires MFA.",
	"GDPRService/RequestExport":                               "Request data export when a complete privacy workflow is configured.",
	"IdentityService/ResolveIdentity":                         "Internal: provider id → user/org/roles.",
	"IntrospectionService/GetServiceInfo":                     "Self-describing service catalog (this RPC).",
	"InvitationService/AcceptInvitation":                      "Accept an invite by token.",
	"InvitationService/CreateInvitation":                      "Invite a user to an org.",
	"InvitationService/InspectInvitation":                     "Resolve a privacy-limited invitation summary from a secret credential.",
	"InvitationService/InspectInvitationById":                 "Resolve an authenticated invitee's invitation summary.",
	"InvitationService/ListInvitations":                       "List pending invites for an org.",
	"InvitationService/ResendInvitation":                      "Rotate and requeue a pending invitation after its cooldown.",
	"InvitationService/RevokeInvitation":                      "Revoke a pending invite.",
	"MFAService/BeginWebAuthnRegistration":                    "Begin passkey registration with server-side ceremony state.",
	"MFAService/FinishWebAuthnRegistration":                   "Verify and persist a passkey credential.",
	"MFAService/GenerateBackupCodes":                          "Mint backup codes (one-time view).",
	"MFAService/ListDevices":                                  "List user's MFA devices.",
	"MFAService/RevokeDevice":                                 "Remove an MFA device.",
	"MFAService/SetupTOTP":                                    "Begin TOTP enrollment for the caller and return the shared secret.",
	"MFAService/VerifyTOTP":                                   "Confirm TOTP code; activate device.",
	"ModuleCapabilitiesService/EnqueueJob":                    "Enqueue durable work for a tenant- or subject-scoped queue.",
	"ModuleCapabilitiesService/ClaimJobs":                     "Lease a bounded batch of ready jobs from an allowed queue.",
	"ModuleCapabilitiesService/HeartbeatJob":                  "Renew a live job lease by its fencing token.",
	"ModuleCapabilitiesService/AckJob":                        "Complete a leased job successfully.",
	"ModuleCapabilitiesService/NackJob":                       "Fail a leased job as retryable or permanent.",
	"ModuleCapabilitiesService/NotifyUser":                    "Notify a user subject to category policy.",
	"ModuleCapabilitiesService/RequestApproval":               "Open a pending approval whose resume job the module claims.",
	"ModuleCapabilitiesService/GetApproval":                   "Read one approval request on the caller's tenant.",
	"ModuleCapabilitiesService/CancelApproval":                "Withdraw a still-open approval request.",
	"ModuleCapabilitiesService/ListReadableSourceCollections": "List source collections the verified viewer may currently read.",
	"ModuleCapabilitiesService/EmitAuditEvent":                "Emit a registered audit event on the tenant's spine.",
	"ModuleCapabilitiesService/FetchDatasourceBlob":           "Stream a datasource file blob referenced by a change set.",
	"ModuleCapabilitiesService/MintModuleRegistration":        "Issue a composed module the signed credential it registers its gateway REST prefix with.",
	"ModuleCapabilitiesService/MintModuleWorkContext":         "Issue a composed module the Work Context its service principal calls this surface with.",
	"ModuleCapabilitiesService/MintSolutionRegistration":      "Issue a solution the signed credential it registers its gateway upstream and frontend remote with.",
	"ModuleCapabilitiesService/PublishEvent":                  "Publish one domain event to the outbox for the caller's tenant.",
	"ModuleCapabilitiesService/Subscribe":                     "Create or re-affirm a durable event subscription for the caller.",
	"ModuleCapabilitiesService/Unsubscribe":                   "Revoke one of the caller's own event subscriptions.",
	"ModuleCapabilitiesService/ListSubscriptions":             "List the calling principal's live event subscriptions.",
	"ModuleCapabilitiesService/ReplayEvents":                  "Re-deliver durable events to the caller's own subscriptions.",
	"NotificationService/DeleteNotification":                  "Delete one of the caller's notifications.",
	"NotificationService/GetUnreadCount":                      "Count the caller's unread notifications.",
	"NotificationService/ListNotifications":                   "List the caller's notifications.",
	"NotificationService/MarkAllRead":                         "Mark every one of the caller's notifications as read.",
	"NotificationService/MarkRead":                            "Mark one of the caller's notifications as read.",
	"OnboardingService/CompleteStep":                          "Confirm a step only after its represented product state exists.",
	"OnboardingService/GetProgress":                           "Versioned organization activation checklist for the caller.",
	"OnboardingService/SkipStep":                              "Record an explicit skip for an optional step.",
	"OrganizationService/AddMember":                           "Add a user to an org.",
	"OrganizationService/CreateOrganization":                  "Create a new org; caller becomes owner.",
	"OrganizationService/GetOrgSettings":                      "Read the organization's branding settings.",
	"OrganizationService/GetOrganization":                     "Read one organization the caller belongs to.",
	"OrganizationService/GetOrganizationSettings":             "Read generic typed org settings (composed JSONB blob).",
	"OrganizationService/UpdateOrganizationSettings":          "Patch generic typed org settings; clear_mask resets fields.",
	"OrganizationService/ListMembers":                         "List members of an org.",
	"OrganizationService/ListOrganizations":                   "Orgs the caller belongs to.",
	"OrganizationService/RemoveMember":                        "Remove a member; last-admin guard.",
	"OrganizationService/UpdateOrgSettings":                   "Update branding (logo, color, custom domain).",
	"PermissionService/AssignRole":                            "Grant a role to a principal/team.",
	"PermissionService/CheckAccess":                           "Internal hierarchical + per-record authz decision.",
	"PermissionService/ListAccessibleScopes":                  "Internal list of scope nodes a subject may act on (list-objects companion to CheckAccess).",
	"PermissionService/CheckPermission":                       "Internal authz decision (auth-gateway caller).",
	"PermissionService/CreateRole":                            "Create a role (org-scoped or platform).",
	"PermissionService/Decide":                                "Internal principal-aware authz decision (successor to CheckPermission).",
	"PermissionService/DeleteRole":                            "Delete a custom role.",
	"PermissionService/GrantScope":                            "Grant a role at a scope node (inherits to subtree).",
	"PermissionService/ListRoleAssignments":                   "List assignments in an org.",
	"PermissionService/ListRoles":                             "List built-in + org-scoped roles.",
	"PermissionService/ListCollectionAccess":                  "Inspect collection boundaries and active inherited documents/read grants.",
	"PermissionService/ListShares":                            "List the shares on a specific record.",
	"PermissionService/RegisterScopeNode":                     "Register a scope node or place a record at one.",
	"PermissionService/RevokeRole":                            "Revoke a role assignment.",
	"PermissionService/RevokeScope":                           "Revoke a hierarchical scope grant.",
	"PermissionService/RevokeShare":                           "Revoke a per-record share.",
	"PermissionService/ShareRecord":                           "Share a record with a principal/team.",
	"PlatformAdminService/GetOrgEntitlements":                 "Plan + overrides + usage.",
	"PlatformAdminService/GetJob":                             "Payload-free job metadata, attempts, and state history.",
	"PlatformAdminService/GetJobOperations":                   "Durable queue depth, readiness, and lease-health snapshots.",
	"PlatformAdminService/GetEventOperations":                 "Domain-event type counters, outbox relay lag, and dead-letter snapshots.",
	"PlatformAdminService/ListEventSubscriptions":             "Live domain-event subscriptions across all principals.",
	"PlatformAdminService/GrantPlatformRole":                  "Grant a platform role.",
	"PlatformAdminService/ImpersonateUser":                    "Mint an impersonation session.",
	"PlatformAdminService/ListActiveSessions":                 "Active sessions for a user.",
	"PlatformAdminService/ListFeatureFlags":                   "List the legacy feature-flag migration inventory.",
	"PlatformAdminService/UpsertFeatureFlag":                  "Deprecated compatibility method; always rejects writes to the legacy feature-flag inventory.",
	"PlatformAdminService/ListJobs":                           "Seek-paginated payload-free job operations view.",
	"PlatformAdminService/ListPlatformAdmins":                 "List the platform administrators and their granted roles.",
	"PlatformAdminService/OverrideEntitlement":                "Override one entitlement limit for a single organization.",
	"PlatformAdminService/RevokePlatformRole":                 "Revoke a platform role.",
	"PlatformAdminService/RevokeSession":                      "Revoke a single session.",
	"PlatformAdminService/ReplayJob":                          "Idempotently copy dead-lettered work for another attempt.",
	"PlatformAdminService/SearchUsers":                        "Search across all users.",
	"PlatformAdminService/SuspendUser":                        "Suspend a user account.",
	"PlatformAdminService/UnsuspendUser":                      "Restore a suspended user.",
	"PrincipalService/CreateAgentPrincipal":                   "Create an agent principal in an organization.",
	"PrincipalService/DisableAgentPrincipal":                  "Reversibly suspend an agent principal.",
	"PrincipalService/EnableAgentPrincipal":                   "Lift a reversible suspension on an agent principal.",
	"PrincipalService/GetAgentPrincipal":                      "Internal agent-principal lookup.",
	"PrincipalService/GetPrincipal":                           "Internal principal lookup.",
	"PrincipalService/ListPrincipals":                         "List principals in an organization.",
	"PrincipalService/RevokePrincipal":                        "Revoke an organization or platform principal.",
	"SSOAdminService/Disable":                                 "Pause SSO; preserves WorkOS state for re-enable.",
	"SSOAdminService/GetSSO":                                  "Read org SSO state.",
	"SSOAdminService/StartSetup":                              "Mint WorkOS portal link.",
	"SolutionRegistryService/PutSolutionRegistration":         "Write or renew one half of a solution's durable runtime registration.",
	"SolutionRegistryService/DeleteSolutionRegistration":      "Deregister a solution and leave a tombstone that blocks resurrection.",
	"SolutionRegistryService/ListSolutionRegistrations":       "Read the solution registry snapshot a replica rebuilds its cache from.",
	"TeamService/AddMember":                                   "Add a user to a team.",
	"TeamService/CreateTeam":                                  "Create a team within an org.",
	"TeamService/DeleteTeam":                                  "Delete a team and its memberships.",
	"TeamService/ListMembers":                                 "List the members of one team.",
	"TeamService/ListTeams":                                   "List teams in an org.",
	"TeamService/RemoveMember":                                "Remove a user from a team.",
	"TeamService/UpdateTeam":                                  "Update a team's name or description.",
	"UserService/AddIdentity":                                 "Link an additional auth provider.",
	"UserService/DeleteUser":                                  "Soft-delete a user (self or platform admin).",
	"UserService/FindUserByIdentity":                          "Look up a user by external identity, for platform administrators.",
	"UserService/GetSelf":                                     "Authenticated user + their orgs.",
	"UserService/GetUser":                                     "Look up a user (self or platform admin).",
	"UserService/ListUserIdentities":                          "List a user's auth methods.",
	"UserService/ListUsers":                                   "Paginated user list (platform admin).",
	"UserService/RegisterUser":                                "Bootstrap a new user + personal org.",
	"UserService/UpdateUser":                                  "Update profile (self or platform admin).",
	"UserService/Version":                                     "Service version (smoke test).",
	"UsageService/ConsumeUsage":                               "Atomically consume a monthly meter with an idempotent receipt.",
	"UsageService/GetUsageHistory":                            "UTC hourly, daily, or monthly usage buckets for a bounded range.",
	"UsageService/GetUsage":                                   "Current monthly meter total and effective limit.",
	"UsageService/ListUsageMeters":                            "Customer-visible meter catalog with current totals and limits.",
	"WorkContextService/ExchangeAudience":                     "Reissue one Task and Session lineage for another audience with attenuated authority.",
	"WorkContextService/RenewWorkContext":                     "Let the current delegated actor extend its own Work Context past the TTL cap, attenuation-preserving.",
	"WorkContextService/StartChildSession":                    "Exchange a current Work Context for an attenuated child-agent Session.",
	"WorkContextService/StartInstallationTask":                "Headlessly mint a Work Context for an installation's agent principal under its owner of record.",
	"WorkContextService/StartRootSession":                     "Exchange a current Work Context for another root Session under the same Task.",
	"WorkContextService/StartTask":                            "Issue a signed Work Context for a new Task and root Session.",
	"UserSettingsService/Get":                                 "Read the caller's stored user preferences.",
	"UserSettingsService/Update":                              "Patch the caller's stored user preferences.",
	"WaitlistService/GetAcquisitionStatus":                    "Read the configured signup and waitlist mode.",
	"WaitlistService/Invite":                                  "Queue the approved signup handoff for one waitlist entry.",
	"WaitlistService/Join":                                    "Submit an enumeration-safe public waitlist request.",
	"WaitlistService/List":                                    "Search and filter the waitlist as a platform administrator.",
	"WaitlistService/Review":                                  "Approve or reject a waitlist entry with audit context.",
	"WaitlistService/Verify":                                  "Verify a waitlist email using an expiring hashed credential.",
	"WebhookService/CreateSubscription":                       "Create a public-HTTPS endpoint and reveal its encrypted-at-rest signing secret once.",
	"WebhookService/DeleteSubscription":                       "Delete a webhook subscription in the organization.",
	"WebhookService/GetDelivery":                              "Read one webhook delivery attempt and its response.",
	"WebhookService/ListDeliveries":                           "List past delivery attempts for a webhook subscription.",
	"WebhookService/ListSubscriptions":                        "List the organization's webhook subscriptions.",
	"WebhookService/ReplayDelivery":                           "Create and audit a new attempt for a past delivery using its stable event ID.",
	"WebhookService/RotateSecret":                             "Rotate the reveal-once signing secret with bounded dual-signature overlap. Requires recent MFA.",
	"WebhookService/TestWebhook":                              "Send a test ping.",
})

func withWorkContextConsumerDescriptions(descriptions map[string]string) map[string]string {
	descriptions["WorkContextService/AuthorizeEvidenceRead"] =
		"Authorize a filtered Evidence read from current tenant membership and RBAC facts."
	descriptions["WorkContextService/CheckAuthorizationRevision"] =
		"Revalidate every subject and scope in a signed Work Context against current authority."
	descriptions["WorkContextService/ConsumeSingleUse"] =
		"Claim a single-use Work Context exactly once; replays of the same context id fail closed."
	return descriptions
}

// buildRPCList enumerates every (Service, Method) and its policy from protobuf
// descriptors. Stable sort by (service, method) makes the response deterministic.
func buildRPCList() []*gen.RPCInfo {
	policies := RPCPolicies()
	out := make([]*gen.RPCInfo, 0, len(policies))
	for _, policy := range policies {
		out = append(out, &gen.RPCInfo{
			Service:      policy.Service,
			Method:       policy.Method,
			HttpMethod:   policy.HTTPMethod,
			HttpPath:     policy.HTTPPath,
			Description:  policy.Description,
			Scopes:       policy.Scopes,
			HandlerAuthz: string(policy.Tier),
			EmitsAudit:   policy.EmitsAudit,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// callerIsAuthenticated reads the wool ctx for a stamped UserAuthID.
// The auth interceptor (gRPC + Connect) populates it after token
// validation. Empty / missing → unauthenticated.
func callerIsAuthenticated(ctx context.Context) bool {
	id, ok := wool.Get(ctx).UserAuthID()
	return ok && id != ""
}

// redactPrivilegedRPCs strips RPCs whose handler authz tier is
// platform_admin or mfa from the response. They're not secret —
// anyone with the binary can grep them — but unauthenticated probes
// shouldn't get a free attack-surface map. The full list remains
// visible to authenticated callers.
func redactPrivilegedRPCs(in []*gen.RPCInfo) []*gen.RPCInfo {
	out := make([]*gen.RPCInfo, 0, len(in))
	for _, r := range in {
		if r.HandlerAuthz == "platform_admin" || r.HandlerAuthz == "mfa" || r.HandlerAuthz == "internal" {
			continue
		}
		out = append(out, r)
	}
	return out
}

// serviceRLSTables projects the RLS-protected relations out of the store
// schema's authority inventory. The tables themselves live in the store
// service's schema (via store/migrations); this api is the enforcer that wraps
// every per-tenant Store call in WithOrgTx / WithControlPlane.
//
// Drift resistance: the inventory is the same one the infrastructure hardening
// suite checks a live database against, so a relation added, dropped, or
// rescoped by a migration shows up here or fails that suite. Every relation in
// a scope that requires row-level security is enabled, forced, and carries at
// least one policy, which is what fail_closed claims.
var serviceRLSTables = func() []*gen.RLSPolicyInfo {
	inventory := relationcatalog.All()
	out := make([]*gen.RLSPolicyInfo, 0, len(inventory))
	for table, authority := range inventory {
		if !authority.Scope.RequiresRLS() {
			continue
		}
		out = append(out, &gen.RLSPolicyInfo{
			Table:       table,
			PolicyShape: authority.PolicyShape,
			FailClosed:  true,
			ScopeColumn: authority.ScopeColumn,
			Notes:       authority.Notes,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Table < out[j].Table })
	return out
}()
