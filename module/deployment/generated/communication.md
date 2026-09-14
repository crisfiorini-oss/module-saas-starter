# Event communication

_Generated from `event-catalog.json` by module-compose. DO NOT EDIT._

Every domain event type, who publishes it, and who consumes it. The machine-readable projection is [`asyncapi.json`](./asyncapi.json).

## installation.created

- **Publisher:** installation
- **Visibility:** internal
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Partition:** `{tenant_id}`
- **Retention:** 30d
- **Consumers:** _none_

## installation.revoked

- **Publisher:** installation
- **Visibility:** internal
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Partition:** `{tenant_id}`
- **Retention:** 30d
- **Consumers:** _none_

## reference.console.viewed

- **Publisher:** reference
- **Visibility:** tenant
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Partition:** `{tenant_id}`
- **Retention:** 30d
- **Consumers:**
  - reference (queue `reference.ingest`, delivery unordered)

## saas.activation.achieved

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.api_key.created

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.api_key.revoked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.approval.approved

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.approval.asked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.approval.cancelled

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.approval.denied

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.approval.escalated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.approval.timeout

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.auth.login

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.auth.magic_link_login

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.auth.mfa_challenge_completed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.auth.mfa_challenge_started

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.auth.organization_switched

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.auth.sso_jit_provisioned

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.billing.checkout_started

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.billing.free_plan_selected

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.billing.portal_opened

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.consent.preferences_updated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.consent.terms_accepted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.dashboard.created

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.dashboard.deleted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.dashboard.shared

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.dashboard.updated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.blob_fetched

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.branch_deleted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.change_set_compiled

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.credential.updated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.force_push_reconciled

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.snapshot_too_large

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.source.access_lost

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.source.access_restored

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.source.added

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.source.recovered

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.source.removed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.source.synced

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.sync.completed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.datasource.sync.failed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.delegation.approved

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.delegation.auto_approved

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.delegation.denied

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.delegation.requested

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.document.deleted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.document.ingested

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.document.quarantine_released

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.document.quarantined

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.document.read

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.document.renamed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.document.search

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.document.subscribed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.document.unsubscribed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.document.version_minted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.entitlement.override

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.event.replayed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.event.subscription_created

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.event.subscription_revoked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.feature_flag.updated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.gdpr.deletion_completed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.gdpr.deletion_requested

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.gdpr.export_requested

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.installation.created

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.installation.ownership_transferred

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.installation.revoked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.invitation.accepted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.invitation.created

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.invitation.resent

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.invitation.revoked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.job.replayed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.mfa.backup_code_used

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.mfa.backup_codes_generated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.mfa.device_revoked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.mfa.totp_setup_started

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.mfa.totp_verified

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.mfa.webauthn_registered

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.mfa.webauthn_registration_started

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.mfa.webauthn_used

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.module.registration_minted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.module.work_context_minted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.onboarding.step_completed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.onboarding.step_skipped

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.org.created

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.org.generic_settings_updated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.org.member_added

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.org.member_removed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.org.settings_updated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.platform.role_granted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.platform.role_revoked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.platform.user_impersonated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.principal.created

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.principal.disabled

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.principal.enabled

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.principal.revoked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.record.share_revoked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.record.shared

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.role.assigned

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.role.created

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.role.deleted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.role.revoked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.role.updated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.scope.granted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.scope.node_registered

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.scope.revoked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.session.revoked

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.settings.updated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.solution.registration_deleted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.solution.registration_minted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.solution.registration_updated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.sso.disabled

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.sso.setup.started

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.team.created

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.team.deleted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.team.member_added

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.team.member_removed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.team.updated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.user.created

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.user.deleted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.user.identity_added

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.user.registered

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.user.suspended

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.user.unsuspended

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.user.updated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.waitlist.approved

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.waitlist.converted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.waitlist.invited

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.waitlist.joined

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.waitlist.pending

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.waitlist.rejected

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.waitlist.reviewed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.waitlist.verified

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.webhook.created

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.webhook.deleted

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.webhook.replayed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.webhook.secret_rotated

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.work_context.audience_exchanged

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.work_context.child_session_started

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.work_context.renewed

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.work_context.root_session_started

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## saas.work_context.task_started

- **Publisher:** saas
- **Visibility:** external
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Retention:** 30d
- **Consumers:** _none_

## scope.granted

- **Publisher:** scope
- **Visibility:** tenant
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Partition:** `{tenant_id}`
- **Retention:** 30d
- **Consumers:** _none_

## scope.revoked

- **Publisher:** scope
- **Visibility:** tenant
- **Schema:** `saas/events/v1/events.proto#EventEnvelope` (major v1)
- **Partition:** `{tenant_id}`
- **Retention:** 30d
- **Consumers:** _none_
