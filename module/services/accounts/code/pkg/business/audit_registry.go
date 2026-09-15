package business

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// The typed audit-event registry. This Go catalog is the single source of
// truth for audit event types, mirroring the permission/entitlement catalog
// pattern in service_vocabulary.go: the audit_event_types database table and
// the generated TypeScript facet are projections of this list, never parallel
// inventories. See docs/adr/0003-typed-audit-event-registry.md.

// EventType is the audit-event discriminator (Single Table Inheritance). Every
// audit row carries one, and producers reference the registered names below.
type EventType string

// AuditCategory groups event types for search facets and analytics roll-ups.
type AuditCategory string

const (
	CategoryIdentity     AuditCategory = "identity"
	CategoryAccess       AuditCategory = "access"
	CategorySecurity     AuditCategory = "security"
	CategoryBilling      AuditCategory = "billing"
	CategoryOrganization AuditCategory = "organization"
	CategoryLifecycle    AuditCategory = "lifecycle"
	CategorySystem       AuditCategory = "system"
)

// FieldKind is the declared type of one payload field. Payloads are validated
// against these at the emit choke point; the JSON Schema projection stored in
// audit_event_types.payload_schema is generated from the same fields.
type FieldKind string

const (
	FieldString      FieldKind = "string"
	FieldUUID        FieldKind = "uuid"
	FieldInt         FieldKind = "int"
	FieldBool        FieldKind = "bool"
	FieldEnum        FieldKind = "enum"
	FieldStringArray FieldKind = "string_array"
)

// PayloadField declares one field of a typed audit payload. PII marks a field
// as personally identifying: it is stripped from every export path so audit
// destinations (the customer's S3 bucket, CSV/JSON downloads) never receive it.
type PayloadField struct {
	Name     string
	Kind     FieldKind
	Required bool
	Enum     []string
	PII      bool
}

// AuditEventTypeRow is a row of the audit_event_types projection table, read
// back by the parity test and the query/UI facet.
type AuditEventTypeRow struct {
	Name       string
	Namespace  string
	Version    int
	Category   string
	Owner      string
	Deprecated bool
}

// AuditNamespace is this module's event namespace: the first segment of every
// event type it mints. A composed workspace hosts several modules against one
// audit spine, so the namespace — not the owning service — is what keeps two
// modules from minting the same event_type. It matches the saas.* protobuf
// package family and the domain-event naming law in EVENTS.md.
const AuditNamespace = "saas"

// AuditDurability declares how an event type's record must reach the log. It is
// the classification the emit choke points and the durability gate enforce, and
// every registered definition carries one — a new event type cannot be added
// without deciding which it is.
type AuditDurability string

const (
	// DurabilityTransactional marks a privileged write: a change to who can do
	// what, or the issue of a credential that grants it. Its audit row and
	// webhook fan-out are written on a transaction the caller's success depends
	// on (Service.emitTx / emitEntryTx), so the record and the change it
	// describes commit together — and a failed audit write fails the operation
	// rather than returning success with no record.
	DurabilityTransactional AuditDurability = "transactional"
	// DurabilityObservational marks a record of something no domain transaction
	// owns: an authentication outcome, a denial, a read, or an outcome produced
	// by an external provider. It is emitted on the emitter's own transaction
	// (Service.emit) precisely so it survives a rolled-back domain write.
	DurabilityObservational AuditDurability = "observational"
)

// AuditEventDefinition is one registered event type. Namespace is the collision
// key (always the leading segment of Type); Owner names the service that emits
// it, which is a different axis entirely. Durability says how the record must
// be committed.
type AuditEventDefinition struct {
	Type        EventType
	Namespace   string
	Version     int
	Category    AuditCategory
	Owner       string
	Description string
	Durability  AuditDurability
	Fields      []PayloadField
}

// mutation registers a privileged write (DurabilityTransactional); observation
// registers a record no domain transaction owns (DurabilityObservational).
// There is deliberately no durability-less constructor: the classification is
// what the durability gate reads, so a new event type has to state it.
func mutation(t EventType, cat AuditCategory, desc string, fields ...PayloadField) AuditEventDefinition {
	return def(t, DurabilityTransactional, cat, desc, fields...)
}

func observation(t EventType, cat AuditCategory, desc string, fields ...PayloadField) AuditEventDefinition {
	return def(t, DurabilityObservational, cat, desc, fields...)
}

// def is the terse constructor for a definition with a v1 payload schema owned
// by accounts. Almost every event today carries no structured payload; the
// fields declared here are the contract producers fill in as payloads are
// enriched.
func def(t EventType, dur AuditDurability, cat AuditCategory, desc string, fields ...PayloadField) AuditEventDefinition {
	return AuditEventDefinition{
		Type: t, Namespace: AuditNamespace, Version: 1, Category: cat,
		Owner: "accounts", Description: desc, Durability: dur, Fields: fields,
	}
}

// revised marks a definition whose payload or field meaning changed after the
// type was published. `type` is immutable (see EVENTS.md), so the version is
// the only signal that separates rows written under the old contract from rows
// written under the new one — and it is the signal
// TestAuditCatalog_TypesCarryNoVersionSuffix points producers at. Bumping it
// costs no migration: SyncAuditEventTypes upserts the projection at boot and
// normalize stamps schema_version from here.
func revised(d AuditEventDefinition, version int) AuditEventDefinition {
	d.Version = version
	return d
}

func str(name string) PayloadField { return PayloadField{Name: name, Kind: FieldString} }
func strs(name string) PayloadField {
	return PayloadField{Name: name, Kind: FieldStringArray}
}
func uid(name string) PayloadField { return PayloadField{Name: name, Kind: FieldUUID} }
func enum(name string, values ...string) PayloadField {
	return PayloadField{Name: name, Kind: FieldEnum, Enum: values}
}
func pii(f PayloadField) PayloadField { f.PII = true; return f }

// Registered event types. The constants are the typed vocabulary producers use;
// grouping mirrors the categories.
const (
	EventUserRegistered  EventType = "saas.user.registered"
	EventUserCreated     EventType = "saas.user.created"
	EventUserUpdated     EventType = "saas.user.updated"
	EventUserDeleted     EventType = "saas.user.deleted"
	EventUserSuspended   EventType = "saas.user.suspended"
	EventUserUnsuspended EventType = "saas.user.unsuspended"
	EventUserIdentityAdd EventType = "saas.user.identity_added"
	EventSettingsUpdated EventType = "saas.settings.updated"
	EventConsentTerms    EventType = "saas.consent.terms_accepted"
	EventConsentPrefs    EventType = "saas.consent.preferences_updated"

	EventAPIKeyCreated               EventType = "saas.api_key.created"
	EventModuleRegistrationMint      EventType = "saas.module.registration_minted"
	EventModuleWorkContextMint       EventType = "saas.module.work_context_minted"
	EventSolutionRegistrationMint    EventType = "saas.solution.registration_minted"
	EventSolutionRegistrationUpdated EventType = "saas.solution.registration_updated"
	EventSolutionRegistrationDeleted EventType = "saas.solution.registration_deleted"
	EventAPIKeyRevoked               EventType = "saas.api_key.revoked"
	EventRoleCreated                 EventType = "saas.role.created"
	EventRoleUpdated                 EventType = "saas.role.updated"
	EventRoleDeleted                 EventType = "saas.role.deleted"
	EventRoleAssigned                EventType = "saas.role.assigned"
	EventRoleRevoked                 EventType = "saas.role.revoked"
	EventSessionRevoked              EventType = "saas.session.revoked"
	EventInvitationCreated           EventType = "saas.invitation.created"
	EventInvitationAccepted          EventType = "saas.invitation.accepted"
	EventInvitationRevoked           EventType = "saas.invitation.revoked"
	EventInvitationResent            EventType = "saas.invitation.resent"
	EventDelegationRequested         EventType = "saas.delegation.requested"
	EventDelegationApproved          EventType = "saas.delegation.approved"
	EventDelegationDenied            EventType = "saas.delegation.denied"
	EventDelegationAutoApproved      EventType = "saas.delegation.auto_approved"
	EventApprovalAsked               EventType = "saas.approval.asked"
	EventApprovalApproved            EventType = "saas.approval.approved"
	EventApprovalDenied              EventType = "saas.approval.denied"
	EventApprovalTimeout             EventType = "saas.approval.timeout"
	EventApprovalEscalated           EventType = "saas.approval.escalated"
	EventApprovalCancelled           EventType = "saas.approval.cancelled"
	EventPrincipalCreated            EventType = "saas.principal.created"
	EventPrincipalRevoked            EventType = "saas.principal.revoked"
	EventPrincipalDisabled           EventType = "saas.principal.disabled"
	EventPrincipalEnabled            EventType = "saas.principal.enabled"

	EventScopeNodeRegistered EventType = "saas.scope.node_registered"
	EventScopeGranted        EventType = "saas.scope.granted"
	EventScopeRevoked        EventType = "saas.scope.revoked"
	EventRecordShared        EventType = "saas.record.shared"
	EventRecordShareRevoked  EventType = "saas.record.share_revoked"

	EventInstallationCreated              EventType = "saas.installation.created"
	EventInstallationRevoked              EventType = "saas.installation.revoked"
	EventInstallationOwnershipTransferred EventType = "saas.installation.ownership_transferred"

	EventWorkContextTaskStarted  EventType = "saas.work_context.task_started"
	EventWorkContextRootSession  EventType = "saas.work_context.root_session_started"
	EventWorkContextChildSession EventType = "saas.work_context.child_session_started"
	EventWorkContextAudienceExch EventType = "saas.work_context.audience_exchanged"
	EventWorkContextRenewed      EventType = "saas.work_context.renewed"

	EventAuthLogin             EventType = "saas.auth.login"
	EventAuthMagicLinkLogin    EventType = "saas.auth.magic_link_login"
	EventAuthSSOJitProvisioned EventType = "saas.auth.sso_jit_provisioned"
	EventAuthOrgSwitched       EventType = "saas.auth.organization_switched"
	EventAuthMFAChallengeStart EventType = "saas.auth.mfa_challenge_started"
	EventAuthMFAChallengeDone  EventType = "saas.auth.mfa_challenge_completed"
	EventMFATOTPSetupStarted   EventType = "saas.mfa.totp_setup_started"
	EventMFATOTPVerified       EventType = "saas.mfa.totp_verified"
	EventMFAWebAuthnRegStarted EventType = "saas.mfa.webauthn_registration_started"
	EventMFAWebAuthnRegistered EventType = "saas.mfa.webauthn_registered"
	EventMFAWebAuthnUsed       EventType = "saas.mfa.webauthn_used"
	EventMFABackupGenerated    EventType = "saas.mfa.backup_codes_generated"
	EventMFABackupUsed         EventType = "saas.mfa.backup_code_used"
	EventMFADeviceRevoked      EventType = "saas.mfa.device_revoked"
	EventPlatformRoleGranted   EventType = "saas.platform.role_granted"
	EventPlatformRoleRevoked   EventType = "saas.platform.role_revoked"
	EventPlatformImpersonated  EventType = "saas.platform.user_impersonated"

	EventBillingCheckoutStarted EventType = "saas.billing.checkout_started"
	EventBillingPortalOpened    EventType = "saas.billing.portal_opened"
	EventBillingFreePlan        EventType = "saas.billing.free_plan_selected"
	EventEntitlementOverride    EventType = "saas.entitlement.override"

	EventOrgCreated                EventType = "saas.org.created"
	EventOrgMemberAdded            EventType = "saas.org.member_added"
	EventOrgMemberRemoved          EventType = "saas.org.member_removed"
	EventOrgSettingsUpdated        EventType = "saas.org.settings_updated"
	EventOrgGenericSettingsUpdated EventType = "saas.org.generic_settings_updated"
	EventTeamCreated               EventType = "saas.team.created"
	EventTeamUpdated               EventType = "saas.team.updated"
	EventTeamDeleted               EventType = "saas.team.deleted"
	EventTeamMemberAdded           EventType = "saas.team.member_added"
	EventTeamMemberRemoved         EventType = "saas.team.member_removed"
	EventSSOSetupStarted           EventType = "saas.sso.setup.started"
	EventSSODisabled               EventType = "saas.sso.disabled"
	EventOnboardingStepDone        EventType = "saas.onboarding.step_completed"
	EventOnboardingStepSkip        EventType = "saas.onboarding.step_skipped"
	EventActivationAchieved        EventType = "saas.activation.achieved"

	EventWaitlistJoined    EventType = "saas.waitlist.joined"
	EventWaitlistPending   EventType = "saas.waitlist.pending"
	EventWaitlistVerified  EventType = "saas.waitlist.verified"
	EventWaitlistReviewed  EventType = "saas.waitlist.reviewed"
	EventWaitlistApproved  EventType = "saas.waitlist.approved"
	EventWaitlistInvited   EventType = "saas.waitlist.invited"
	EventWaitlistConverted EventType = "saas.waitlist.converted"
	EventWaitlistRejected  EventType = "saas.waitlist.rejected"
	EventGDPRExportReq     EventType = "saas.gdpr.export_requested"
	EventGDPRDeletionReq   EventType = "saas.gdpr.deletion_requested"
	EventGDPRDeletionDone  EventType = "saas.gdpr.deletion_completed"

	EventWebhookCreated       EventType = "saas.webhook.created"
	EventWebhookDeleted       EventType = "saas.webhook.deleted"
	EventWebhookReplayed      EventType = "saas.webhook.replayed"
	EventWebhookSecretRotated EventType = "saas.webhook.secret_rotated"
	EventJobReplayed          EventType = "saas.job.replayed"

	EventDatasourceSourceAdded          EventType = "saas.datasource.source.added"
	EventDatasourceSyncCompleted        EventType = "saas.datasource.sync.completed"
	EventDatasourceCredentialUpdated    EventType = "saas.datasource.credential.updated"
	EventDatasourceSyncFailed           EventType = "saas.datasource.sync.failed"
	EventDatasourceSourceSynced         EventType = "saas.datasource.source.synced"
	EventDatasourceSourceRemoved        EventType = "saas.datasource.source.removed"
	EventDatasourceChangeSetCompiled    EventType = "saas.datasource.change_set_compiled"
	EventDatasourceForcePushReconciled  EventType = "saas.datasource.force_push_reconciled"
	EventDatasourceBranchDeleted        EventType = "saas.datasource.branch_deleted"
	EventDatasourceSnapshotTooLarge     EventType = "saas.datasource.snapshot_too_large"
	EventDatasourceSourceRecovered      EventType = "saas.datasource.source.recovered"
	EventDatasourceSourceAccessLost     EventType = "saas.datasource.source.access_lost"
	EventDatasourceSourceAccessRestored EventType = "saas.datasource.source.access_restored"
	EventDatasourceBlobFetched          EventType = "saas.datasource.blob_fetched"

	EventDatasourceGitHubAppSetupStarted   EventType = "saas.datasource.github_app.setup_started"
	EventDatasourceGitHubAppSetupCompleted EventType = "saas.datasource.github_app.setup_completed"
	EventFeatureFlagUpdated                EventType = "saas.feature_flag.updated"

	// Domain-event pub/sub (issue #493). A subscription is a standing grant of
	// delivery, so its create and revoke are audited on the tenant spine; a
	// replay is an operator action that re-delivers history. Per-publish is not
	// audited — the domain_events relation is itself the record of every publish.
	EventEventSubscriptionCreated EventType = "saas.event.subscription_created"
	EventEventSubscriptionRevoked EventType = "saas.event.subscription_revoked"
	EventEventReplayed            EventType = "saas.event.replayed"

	EventDashboardCreated EventType = "saas.dashboard.created"
	EventDashboardUpdated EventType = "saas.dashboard.updated"
	EventDashboardDeleted EventType = "saas.dashboard.deleted"
	EventDashboardShared  EventType = "saas.dashboard.shared"

	// Document lifecycle vocabulary emitted by a consuming solution through the
	// module-facing EmitAuditEvent (issue #463). Every event carries the tenant
	// (org_id), actor (actor_id), and entry (resource_id) columns plus a solution
	// scope and the entry version in its payload, so a solution keeps one audit
	// spine per tenant instead of a second trail.
	EventDocumentIngested           EventType = "saas.document.ingested"
	EventDocumentRead               EventType = "saas.document.read"
	EventDocumentSearch             EventType = "saas.document.search"
	EventDocumentVersionMinted      EventType = "saas.document.version_minted"
	EventDocumentRenamed            EventType = "saas.document.renamed"
	EventDocumentDeleted            EventType = "saas.document.deleted"
	EventDocumentQuarantined        EventType = "saas.document.quarantined"
	EventDocumentQuarantineReleased EventType = "saas.document.quarantine_released"
	EventDocumentSubscribed         EventType = "saas.document.subscribed"
	EventDocumentUnsubscribed       EventType = "saas.document.unsubscribed"
)

var auditEventCatalog = []AuditEventDefinition{
	mutation(EventUserRegistered, CategoryIdentity, "A new user account was registered.",
		enum("signup_method", "password", "sso", "magic_link"), pii(str("email"))),
	mutation(EventUserCreated, CategoryIdentity, "A user was provisioned by an administrator.", pii(str("email"))),
	mutation(EventUserUpdated, CategoryIdentity, "A user profile was updated."),
	mutation(EventUserDeleted, CategoryIdentity, "A user account was deleted."),
	// A suspension is allowed to leave an organization with no administrator —
	// containing a compromised account outranks that — so the organizations it
	// did leave that way are part of the record rather than a reason to refuse.
	mutation(EventUserSuspended, CategoryIdentity, "A user account was suspended.",
		strs("organizations_without_administrator")),
	mutation(EventUserUnsuspended, CategoryIdentity, "A user account was reinstated."),
	mutation(EventUserIdentityAdd, CategoryIdentity, "An external identity was linked to a user.", str("provider")),
	observation(EventSettingsUpdated, CategoryIdentity, "A user's personal settings changed."),
	mutation(EventConsentTerms, CategoryIdentity, "A user accepted the terms of service.", str("version")),
	mutation(EventConsentPrefs, CategoryIdentity, "A user updated their consent preferences."),

	mutation(EventAPIKeyCreated, CategoryAccess, "An API key was minted.", uid("key_id"), PayloadField{Name: "scopes", Kind: FieldStringArray}),
	mutation(EventModuleRegistrationMint, CategoryAccess, "A composed module was issued a gateway registration credential.", str("prefix")),
	mutation(EventModuleWorkContextMint, CategoryAccess, "A composed module was issued a Work Context for its service principal.", str("prefix"), str("tenant")),
	mutation(EventSolutionRegistrationMint, CategoryAccess, "A solution was issued a gateway and frontend registration credential.", str("solution_id")),
	mutation(EventSolutionRegistrationUpdated, CategoryAccess, "A solution registered or replaced one half of its runtime registration.", str("solution_id"), str("publisher"), str("half"), PayloadField{Name: "revision", Kind: FieldInt}),
	mutation(EventSolutionRegistrationDeleted, CategoryAccess, "A solution registration was removed and tombstoned.", str("solution_id"), str("publisher"), PayloadField{Name: "revision", Kind: FieldInt}),
	mutation(EventAPIKeyRevoked, CategoryAccess, "An API key was revoked.", uid("key_id")),
	mutation(EventRoleCreated, CategoryAccess, "A role was created.", str("name")),
	mutation(EventRoleUpdated, CategoryAccess, "A role was updated."),
	mutation(EventRoleDeleted, CategoryAccess, "A role was deleted."),
	mutation(EventRoleAssigned, CategoryAccess, "A role was assigned to a principal.", uid("role_id"), uid("subject_id")),
	mutation(EventRoleRevoked, CategoryAccess, "A role assignment was revoked.", uid("role_id")),
	mutation(EventSessionRevoked, CategoryAccess, "A session was revoked."),
	mutation(EventInvitationCreated, CategoryAccess, "An organization invitation was created.", pii(str("email"))),
	mutation(EventInvitationAccepted, CategoryAccess, "An organization invitation was accepted."),
	mutation(EventInvitationRevoked, CategoryAccess, "An organization invitation was revoked."),
	mutation(EventInvitationResent, CategoryAccess, "An organization invitation was resent."),
	mutation(EventDelegationRequested, CategoryAccess, "A delegation grant was requested."),
	mutation(EventDelegationApproved, CategoryAccess, "A delegation grant was approved."),
	mutation(EventDelegationDenied, CategoryAccess, "A delegation grant was denied."),
	mutation(EventDelegationAutoApproved, CategoryAccess, "A delegation grant was auto-approved by policy."),
	mutation(EventApprovalAsked, CategoryAccess, "An approval request was opened for a gated action.", str("resource"), str("action")),
	mutation(EventApprovalApproved, CategoryAccess, "An approval request reached quorum and was approved.", str("resource"), str("action")),
	mutation(EventApprovalDenied, CategoryAccess, "An approval request was denied."),
	mutation(EventApprovalTimeout, CategoryAccess, "An approval request expired before reaching quorum."),
	mutation(EventApprovalEscalated, CategoryAccess, "An approval request was escalated to a wider approver set."),
	mutation(EventApprovalCancelled, CategoryAccess, "An approval request was cancelled before a decision.", str("reason")),
	mutation(EventPrincipalCreated, CategoryAccess, "An agent principal was created.", str("agent_identifier")),
	mutation(EventPrincipalRevoked, CategoryAccess, "A principal was revoked.", str("reason")),
	mutation(EventPrincipalDisabled, CategoryAccess, "An agent principal was disabled.", str("reason")),
	mutation(EventPrincipalEnabled, CategoryAccess, "An agent principal was re-enabled."),
	mutation(EventScopeNodeRegistered, CategoryAccess, "A scope node was registered.", str("scope_path"), str("kind")),
	mutation(EventScopeGranted, CategoryAccess, "A role was granted at a scope node.", uid("role_id"), uid("subject_id"), str("scope_path")),
	mutation(EventScopeRevoked, CategoryAccess, "A scope grant was revoked.", uid("role_id"), str("scope_path")),
	mutation(EventInstallationCreated, CategoryAccess, "A solution was installed: an agent principal, solution scope node, standing grant, and installation row were composed.",
		uid("agent_principal_id"), str("solution_identifier"), uid("role_id"), uid("owner_principal_id")),
	mutation(EventInstallationRevoked, CategoryAccess, "A solution was uninstalled: its agent principal and standing grant were revoked and its scope node soft-deleted.",
		str("solution_identifier")),
	mutation(EventInstallationOwnershipTransferred, CategoryAccess, "An installation's owner of record was reassigned.",
		uid("owner_principal_id")),
	mutation(EventRecordShared, CategoryAccess, "A record was shared with a principal or team.", uid("role_id"), uid("subject_id")),
	mutation(EventRecordShareRevoked, CategoryAccess, "A record share was revoked.", uid("role_id"), uid("subject_id")),
	mutation(EventWorkContextTaskStarted, CategoryAccess, "A signed Work Context was issued for a new agent task and root session."),
	mutation(EventWorkContextRootSession, CategoryAccess, "A new root agent session was started under an existing task."),
	mutation(EventWorkContextChildSession, CategoryAccess, "An attenuated child agent session was started."),
	mutation(EventWorkContextAudienceExch, CategoryAccess, "A Work Context task and session lineage was reissued for another audience."),
	mutation(EventWorkContextRenewed, CategoryAccess, "A delegated actor renewed its Work Context past the signing TTL cap."),

	observation(EventAuthLogin, CategorySecurity, "A user authenticated.", str("method")),
	observation(EventAuthMagicLinkLogin, CategorySecurity, "A user authenticated via magic link."),
	mutation(EventAuthSSOJitProvisioned, CategorySecurity, "A user was just-in-time provisioned via SSO.", str("provider")),
	observation(EventAuthOrgSwitched, CategorySecurity, "A user switched active organization."),
	observation(EventAuthMFAChallengeStart, CategorySecurity, "An MFA challenge was started."),
	observation(EventAuthMFAChallengeDone, CategorySecurity, "An MFA challenge was completed.", enum("factor", "totp", "webauthn", "backup_code")),
	mutation(EventMFATOTPSetupStarted, CategorySecurity, "TOTP enrollment was started."),
	mutation(EventMFATOTPVerified, CategorySecurity, "A TOTP device was verified."),
	mutation(EventMFAWebAuthnRegStarted, CategorySecurity, "WebAuthn registration was started."),
	mutation(EventMFAWebAuthnRegistered, CategorySecurity, "A WebAuthn credential was registered."),
	observation(EventMFAWebAuthnUsed, CategorySecurity, "A WebAuthn credential was used to authenticate."),
	mutation(EventMFABackupGenerated, CategorySecurity, "MFA backup codes were generated."),
	observation(EventMFABackupUsed, CategorySecurity, "An MFA backup code was consumed."),
	mutation(EventMFADeviceRevoked, CategorySecurity, "An MFA device was revoked."),
	mutation(EventPlatformRoleGranted, CategorySecurity, "A platform role was granted."),
	mutation(EventPlatformRoleRevoked, CategorySecurity, "A platform role was revoked."),
	mutation(EventPlatformImpersonated, CategorySecurity, "A platform admin impersonated a user."),

	observation(EventBillingCheckoutStarted, CategoryBilling, "A billing checkout session was started."),
	observation(EventBillingPortalOpened, CategoryBilling, "The billing portal was opened."),
	observation(EventBillingFreePlan, CategoryBilling, "The free plan was selected."),
	mutation(EventEntitlementOverride, CategoryBilling, "An entitlement override was set.", str("key")),

	mutation(EventOrgCreated, CategoryOrganization, "An organization was created.", str("name")),
	mutation(EventOrgMemberAdded, CategoryOrganization, "A member was added to an organization."),
	mutation(EventOrgMemberRemoved, CategoryOrganization, "A member was removed from an organization."),
	mutation(EventOrgSettingsUpdated, CategoryOrganization, "Organization branding settings were updated."),
	mutation(EventOrgGenericSettingsUpdated, CategoryOrganization, "Organization generic (typed) settings were updated."),
	mutation(EventTeamCreated, CategoryOrganization, "A team was created.", str("name")),
	mutation(EventTeamUpdated, CategoryOrganization, "A team was updated."),
	mutation(EventTeamDeleted, CategoryOrganization, "A team was deleted."),
	mutation(EventTeamMemberAdded, CategoryOrganization, "A member was added to a team."),
	mutation(EventTeamMemberRemoved, CategoryOrganization, "A member was removed from a team."),
	mutation(EventSSOSetupStarted, CategoryOrganization, "SSO configuration was started."),
	mutation(EventSSODisabled, CategoryOrganization, "SSO was disabled for an organization."),
	observation(EventOnboardingStepDone, CategoryOrganization, "An onboarding step was completed.", str("step")),
	observation(EventOnboardingStepSkip, CategoryOrganization, "An onboarding step was skipped.", str("step")),
	observation(EventActivationAchieved, CategoryOrganization, "An organization reached activation."),

	observation(EventDashboardCreated, CategoryOrganization, "A dashboard was created."),
	observation(EventDashboardUpdated, CategoryOrganization, "A dashboard was updated."),
	observation(EventDashboardDeleted, CategoryOrganization, "A dashboard was deleted."),
	observation(EventDashboardShared, CategoryOrganization, "A dashboard's visibility was changed."),

	observation(EventWaitlistJoined, CategoryLifecycle, "A prospect joined the waitlist.", pii(str("email"))),
	observation(EventWaitlistPending, CategoryLifecycle, "A waitlist entry moved to pending."),
	observation(EventWaitlistVerified, CategoryLifecycle, "A waitlist entry was verified."),
	observation(EventWaitlistReviewed, CategoryLifecycle, "A waitlist entry was reviewed by an administrator."),
	observation(EventWaitlistApproved, CategoryLifecycle, "A waitlist entry was approved."),
	observation(EventWaitlistInvited, CategoryLifecycle, "A waitlist entry was invited."),
	observation(EventWaitlistConverted, CategoryLifecycle, "A waitlist entry converted to a user."),
	observation(EventWaitlistRejected, CategoryLifecycle, "A waitlist entry was rejected."),
	mutation(EventGDPRExportReq, CategoryLifecycle, "A GDPR data export was requested."),
	mutation(EventGDPRDeletionReq, CategoryLifecycle, "A GDPR deletion was requested."),
	mutation(EventGDPRDeletionDone, CategoryLifecycle, "A GDPR deletion completed."),

	revised(mutation(EventWebhookCreated, CategorySystem, "A webhook subscription was created.", webhookAdminFields...), webhookAdminVersion),
	revised(mutation(EventWebhookDeleted, CategorySystem, "A webhook subscription was deleted.", webhookAdminFields...), webhookAdminVersion),
	revised(mutation(EventWebhookReplayed, CategorySystem, "A webhook delivery was replayed.", webhookAdminFields...), webhookAdminVersion),
	mutation(EventDatasourceSourceAdded, CategorySystem, "A GitHub datasource was connected.", str("repo")),
	mutation(EventDatasourceGitHubAppSetupStarted, CategorySystem, "GitHub App setup was started for an organization."),
	mutation(EventDatasourceGitHubAppSetupCompleted, CategorySystem, "A GitHub App installation was verified and bound to an organization.",
		str("installation_id")),
	observation(EventDatasourceSourceSynced, CategorySystem, "A datasource sync was requested.", str("job_id"), str("repo")),
	revised(mutation(EventDatasourceCredentialUpdated, CategorySystem, "A datasource credential was validated and replaced.",
		str("repo"), enum("credential_kind", "pat", "app")), 2),
	mutation(EventDatasourceSourceRemoved, CategorySystem, "A datasource was removed."),
	observation(EventDatasourceSyncCompleted, CategorySystem, "A datasource ingestion job completed.", sourceSyncFields...),
	observation(EventDatasourceSyncFailed, CategorySystem, "A datasource ingestion attempt failed and may retry.", sourceSyncFields...),
	observation(EventDatasourceChangeSetCompiled, CategorySystem, "A GitHub delivery was compiled into a change set.",
		str("base"), str("head"), PayloadField{Name: "ops", Kind: FieldInt}, enum("mode", "compare", "snapshot"), str("delivery_id")),
	observation(EventDatasourceForcePushReconciled, CategorySystem, "A GitHub force push or divergence was reconciled with a snapshot.",
		str("head"), str("delivery_id")),
	observation(EventDatasourceBranchDeleted, CategorySystem, "A GitHub branch-deletion delivery was acknowledged without removing documents.",
		str("ref"), str("delivery_id")),
	observation(EventDatasourceSnapshotTooLarge, CategorySystem, "A datasource snapshot manifest exceeded the ingest payload limit; the source was degraded pending operator reset.",
		str("head"), PayloadField{Name: "bytes", Kind: FieldInt}, PayloadField{Name: "limit", Kind: FieldInt}, str("delivery_id")),
	observation(EventDatasourceSourceRecovered, CategorySystem, "A degraded datasource source snapshotted within the ingest limit again and was returned to active.",
		str("head"), str("delivery_id")),
	observation(EventDatasourceSourceAccessLost, CategorySystem,
		"A GitHub App installation stopped granting a source access to its repository; the source was degraded until access returns.",
		str("repo"), str("installation_id"), enum("reason", DatasourceAccessLostRepositoryUnavailable, DatasourceAccessLostSuspended)),
	observation(EventDatasourceSourceAccessRestored, CategorySystem,
		"A GitHub App installation granted a source access to its repository again and the source was returned to active.",
		str("repo"), str("installation_id"),
		enum("restored_from", DatasourceAccessLostRepositoryUnavailable, DatasourceAccessLostSuspended)),
	observation(EventDatasourceBlobFetched, CategorySystem, "A module fetched a datasource blob's bytes over FetchDatasourceBlob.",
		str("repo"), str("blob_sha"), PayloadField{Name: "bytes", Kind: FieldInt}),
	revised(mutation(EventWebhookSecretRotated, CategorySystem, "A webhook signing secret was rotated.", webhookAdminFields...), webhookAdminVersion),
	observation(EventJobReplayed, CategorySystem, "A background job was replayed."),
	mutation(EventFeatureFlagUpdated, CategorySystem, "A legacy feature flag was updated."),
	mutation(EventEventSubscriptionCreated, CategorySystem, "A domain-event subscription was created.",
		uid("subscription_id"), uid("subscriber_principal_id"), str("type_pattern"), str("queue")),
	mutation(EventEventSubscriptionRevoked, CategorySystem, "A domain-event subscription was revoked.", uid("subscription_id")),
	mutation(EventEventReplayed, CategorySystem, "Domain events were replayed to a subscriber.",
		str("type"), PayloadField{Name: "redelivered", Kind: FieldInt}),
	observation(EventDocumentRead, CategoryAccess, "A document read returned evidence or an explicit outcome.", documentReadFields...),
	observation(EventDocumentSearch, CategoryAccess, "A collection search returned evidence or an explicit outcome.", documentReadFields...),
	mutation(EventDocumentIngested, CategoryLifecycle, "A document was ingested into a solution.", documentFields...),
	mutation(EventDocumentVersionMinted, CategoryLifecycle, "A new document version was minted.", documentFields...),
	mutation(EventDocumentRenamed, CategoryLifecycle, "A document was renamed.", documentFields...),
	mutation(EventDocumentDeleted, CategoryLifecycle, "A document was deleted.", documentFields...),
	mutation(EventDocumentQuarantined, CategoryLifecycle, "A document was quarantined.", documentFields...),
	mutation(EventDocumentQuarantineReleased, CategoryLifecycle, "A document was released from quarantine.", documentFields...),
	mutation(EventDocumentSubscribed, CategoryLifecycle, "A subscription to a document was created.", documentFields...),
	mutation(EventDocumentUnsubscribed, CategoryLifecycle, "A subscription to a document was removed.", documentFields...),
}

// webhookAdminVersion is version 2 of the webhook administration events: the
// version at which actor_id became the initiating user rather than the
// organization the change was made in, and `delegated_by` appeared. The value
// of actor_id changed meaning under a name that could not change, so the
// version is what tells a v1 row (actor_id is an org) from a v2 row (actor_id
// is a user) — in the audit table and in the webhook fan-out alike. Without it
// the release boundary exists only in prose, and an append-only trail cannot be
// re-dated later.
const webhookAdminVersion = 2

// webhookAdminFields is the shared payload of the webhook administration
// events. The initiator itself is the row's actor_id/actor_type; `delegated_by`
// records the RFC 8693 `act` parties that called on the initiator's behalf,
// immediate delegate first, and is absent on a direct call. It is a list
// because a delegation chain nests: recording only its head would discard every
// intermediary, and the chain lives nowhere but the request's token.
var webhookAdminFields = []PayloadField{
	strs("delegated_by"),
}

// documentFields is the shared payload of every document.* event. `solution`
// and `version` name the write; `boundary` is the data boundary (scope node) it
// landed in; actor/owner principal ids and `initiator` (a provenance string,
// e.g. a webhook delivery id) make a solution-owned write attributable (#473).
var sourceSyncFields = []PayloadField{str("solution"), str("job_id"), str("repo"), str("commit"), PayloadField{Name: "processed", Kind: FieldInt}, PayloadField{Name: "new_versions", Kind: FieldInt}, PayloadField{Name: "deleted", Kind: FieldInt}, PayloadField{Name: "failed", Kind: FieldInt}, str("reason"), str("code"), str("trigger"), PayloadField{Name: "attempt", Kind: FieldInt}, PayloadField{Name: "retryable", Kind: FieldBool}}

var documentFields = []PayloadField{
	str("solution"),
	str("version"),
	str("boundary"),
	uid("actor_principal_id"),
	uid("owner_principal_id"),
	str("initiator"),
}

// Observed read telemetry never carries query text, excerpts or credentials.
var documentReadFields = func() []PayloadField {
	fields := append([]PayloadField(nil), documentFields...)
	for i := range fields {
		if fields[i].Name == "boundary" {
			fields[i].Required = true
		}
	}
	return append(fields,
		PayloadField{Name: "correlation_id", Kind: FieldString, Required: true},
		PayloadField{Name: "outcome", Kind: FieldEnum, Required: true, Enum: []string{"returned", "empty", "denied", "failed"}},
		PayloadField{Name: "result_count", Kind: FieldInt}, PayloadField{Name: "duration_ms", Kind: FieldInt})
}()

// auditEventIndex resolves an event type to its definition. Built once.
var auditEventIndex = func() map[EventType]AuditEventDefinition {
	m := make(map[EventType]AuditEventDefinition, len(auditEventCatalog))
	for _, d := range auditEventCatalog {
		if _, dup := m[d.Type]; dup {
			panic(fmt.Sprintf("audit registry: duplicate event type %q", d.Type))
		}
		if d.Durability != DurabilityTransactional && d.Durability != DurabilityObservational {
			panic(fmt.Sprintf("audit registry: event type %q has no durability classification", d.Type))
		}
		m[d.Type] = d
	}
	return m
}()

// IsTransactionalAuditEvent reports whether an event type must be written on a
// transaction the caller's success depends on. Unregistered types are not
// transactional: the module-facing surface accepts caller-supplied types and
// writes them through emitEntryTx regardless.
func IsTransactionalAuditEvent(t EventType) bool {
	d, ok := auditEventIndex[t]
	return ok && d.Durability == DurabilityTransactional
}

// AuditEventCatalog returns the registered event definitions sorted by type,
// so DB seeding and the generated facet are deterministic.
func AuditEventCatalog() []AuditEventDefinition {
	out := append([]AuditEventDefinition(nil), auditEventCatalog...)
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// LookupAuditEvent returns the definition for an event type and whether it is
// registered.
func LookupAuditEvent(t EventType) (AuditEventDefinition, bool) {
	d, ok := auditEventIndex[t]
	return d, ok
}

// ValidatePayload checks a payload against the registered schema for the event
// type. It returns an error describing the first problem (unknown type, unknown
// field, missing required field, wrong kind, bad enum value).
//
// Callers treat the result as advisory: an audit record is never dropped
// because validation failed — the security event is more valuable than schema
// purity — but the error is logged so drift surfaces. See DurableAuditEmitter.
func ValidatePayload(t EventType, payload map[string]any) error {
	d, ok := auditEventIndex[t]
	if !ok {
		return fmt.Errorf("audit: unregistered event type %q", t)
	}
	fields := make(map[string]PayloadField, len(d.Fields))
	for _, f := range d.Fields {
		fields[f.Name] = f
	}
	for name := range payload {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("audit: event %q has no registered field %q", t, name)
		}
	}
	for _, f := range d.Fields {
		v, present := payload[f.Name]
		if !present {
			if f.Required {
				return fmt.Errorf("audit: event %q missing required field %q", t, f.Name)
			}
			continue
		}
		if err := validateField(t, f, v); err != nil {
			return err
		}
	}
	return nil
}

func validateField(t EventType, f PayloadField, v any) error {
	if (t == EventDocumentRead || t == EventDocumentSearch) && f.Required {
		if value, ok := v.(string); !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("audit: event %q field %q requires a nonempty string", t, f.Name)
		}
	}
	switch f.Kind {
	case FieldString, FieldUUID:
		if _, ok := v.(string); !ok {
			return fmt.Errorf("audit: event %q field %q expects a string", t, f.Name)
		}
	case FieldEnum:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("audit: event %q field %q expects a string", t, f.Name)
		}
		for _, allowed := range f.Enum {
			if s == allowed {
				return nil
			}
		}
		return fmt.Errorf("audit: event %q field %q value %q not in enum %v", t, f.Name, s, f.Enum)
	case FieldInt:
		switch v.(type) {
		case int, int32, int64, float64:
		default:
			return fmt.Errorf("audit: event %q field %q expects an int", t, f.Name)
		}
	case FieldBool:
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("audit: event %q field %q expects a bool", t, f.Name)
		}
	case FieldStringArray:
		if _, ok := v.([]string); ok {
			return nil
		}
		arr, ok := v.([]any)
		if !ok {
			return fmt.Errorf("audit: event %q field %q expects a string array", t, f.Name)
		}
		for _, e := range arr {
			if _, ok := e.(string); !ok {
				return fmt.Errorf("audit: event %q field %q expects a string array", t, f.Name)
			}
		}
	}
	return nil
}

// RedactPayload returns a copy of payload with every field the registry marks
// PII removed. Used on every export path so downstream audit sinks never
// receive personally identifying fields. An unregistered type is redacted
// whole (fail closed): without a schema we cannot tell which fields are safe.
func RedactPayload(t EventType, payload map[string]any) map[string]any {
	if len(payload) == 0 {
		return payload
	}
	d, ok := auditEventIndex[t]
	if !ok {
		return map[string]any{}
	}
	piiFields := make(map[string]struct{})
	for _, f := range d.Fields {
		if f.PII {
			piiFields[f.Name] = struct{}{}
		}
	}
	if len(piiFields) == 0 {
		return payload
	}
	out := make(map[string]any, len(payload))
	for k, v := range payload {
		if _, redacted := piiFields[k]; redacted {
			continue
		}
		out[k] = v
	}
	return out
}

// PayloadSchemaJSON is the marshaled JSON Schema stored in
// audit_event_types.payload_schema by the DB projection.
func (d AuditEventDefinition) PayloadSchemaJSON() []byte {
	b, err := json.Marshal(d.payloadJSONSchema())
	if err != nil {
		return []byte("{}")
	}
	return b
}

// payloadJSONSchema renders a definition's fields as a JSON Schema object, the
// portable form stored in audit_event_types.payload_schema.
func (d AuditEventDefinition) payloadJSONSchema() map[string]any {
	properties := make(map[string]any, len(d.Fields))
	var required []string
	for _, f := range d.Fields {
		prop := map[string]any{}
		switch f.Kind {
		case FieldUUID:
			prop["type"] = "string"
			prop["format"] = "uuid"
		case FieldEnum:
			prop["type"] = "string"
			prop["enum"] = f.Enum
		case FieldInt:
			prop["type"] = "integer"
		case FieldBool:
			prop["type"] = "boolean"
		case FieldStringArray:
			prop["type"] = "array"
			prop["items"] = map[string]any{"type": "string"}
		default:
			prop["type"] = "string"
		}
		if f.PII {
			prop["x-pii"] = true
		}
		properties[f.Name] = prop
		if f.Required {
			required = append(required, f.Name)
		}
	}
	schema := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}
