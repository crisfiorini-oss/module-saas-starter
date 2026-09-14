package business

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// eventsEmittedOutsideRPC is the deliberate classification of every registered
// event no proto method policy declares: background jobs, the waitlist state
// machine, the role-catalog reconciler, and the module-facing EmitAuditEvent a
// consuming solution calls. Adding an event forces a choice — declare it on the
// RPC that emits it, or list it here — so the catalog can never grow a name
// nothing can reach.
var eventsEmittedOutsideRPC = []EventType{
	EventActivationAchieved,
	EventApprovalApproved,
	EventApprovalAsked,
	EventApprovalCancelled,
	EventApprovalDenied,
	EventApprovalEscalated,
	EventApprovalTimeout,
	EventAuthMagicLinkLogin,
	EventAuthSSOJitProvisioned,
	EventBillingCheckoutStarted,
	EventBillingFreePlan,
	EventDatasourceBlobFetched,
	EventDatasourceBranchDeleted,
	EventDatasourceChangeSetCompiled,
	// SyncDatasourceSource emits this only when replacing a credential; the
	// RPC policy declares the sync-request event common to every invocation.
	EventDatasourceCredentialUpdated,
	EventDatasourceForcePushReconciled,
	EventDatasourceSnapshotTooLarge,
	EventDatasourceSyncCompleted,
	EventDatasourceSyncFailed,
	// The App-level installation reconciler emits these from its leased job:
	// the transition originates in a third party's GitHub account, not in any
	// request a tenant made.
	EventDatasourceSourceAccessLost,
	EventDatasourceSourceAccessRestored,
	EventDatasourceSourceRecovered,
	EventDocumentDeleted,
	EventDocumentIngested,
	// Module-authenticated document readers emit these observations.
	EventDocumentRead,
	EventDocumentSearch,
	EventDocumentQuarantineReleased,
	EventDocumentQuarantined,
	EventDocumentRenamed,
	EventDocumentSubscribed,
	EventDocumentUnsubscribed,
	EventDocumentVersionMinted,
	// Domain-event pub/sub (issue #493). These are emitted inside the producer's
	// transaction through emitTx rather than by the declarative RPC emission, so
	// the audit record commits or rolls back with the subscription change itself;
	// the RPCs correspondingly declare AUDIT_EMISSION_NONE. Subscription creation
	// also happens with no RPC in the picture at all, when install materializes a
	// catalog `consumes` entry (events_materialize.go).
	EventEventReplayed,
	EventEventSubscriptionCreated,
	EventEventSubscriptionRevoked,
	EventGDPRDeletionDone,
	EventRoleUpdated,
	EventUserCreated,
	EventWaitlistApproved,
	EventWaitlistConverted,
	EventWaitlistJoined,
	EventWaitlistPending,
	EventWaitlistRejected,
	EventWaitlistVerified,
}

// policyDeclaredEvents collects every audit event named by a method policy on
// the same descriptor set rpc_policy.go lints, so the proto declarations and the
// Go catalog are read from one place rather than maintained as two lists.
func policyDeclaredEvents() map[EventType][]string {
	declared := make(map[EventType][]string)
	for _, service := range accountServiceDescriptors() {
		for i := 0; i < service.Methods().Len(); i++ {
			method := service.Methods().Get(i)
			policy, _ := descriptorMethodPolicy(method)
			for _, event := range policy.GetAudit().GetEvents() {
				full := string(service.FullName()) + "/" + string(method.Name())
				declared[EventType(event)] = append(declared[EventType(event)], full)
			}
		}
	}
	return declared
}

// A method policy declaring an event the catalog does not know is a name that
// can never be emitted: it passes the auditEventName format check, so nothing
// else catches it, and the webhook subscriptions a customer creates against it
// silently never fire.
func TestAuditPolicyEventsAreRegistered(t *testing.T) {
	declared := policyDeclaredEvents()
	require.NotEmpty(t, declared, "expected the accounts descriptors to declare audit events")
	for event, methods := range declared {
		_, ok := auditEventIndex[event]
		require.Truef(t, ok,
			"method policy on %v declares audit event %q, which is not in the registry", methods, event)
	}
}

// The reverse direction: the catalog is exactly the events some RPC declares
// plus the ones emitted outside the RPC path, and the two sets are disjoint.
func TestEveryRegisteredEventIsReachable(t *testing.T) {
	declared := policyDeclaredEvents()

	outside := make(map[EventType]struct{}, len(eventsEmittedOutsideRPC))
	for _, event := range eventsEmittedOutsideRPC {
		_, dup := outside[event]
		require.Falsef(t, dup, "duplicate entry %q in eventsEmittedOutsideRPC", event)
		outside[event] = struct{}{}
		_, registered := auditEventIndex[event]
		require.Truef(t, registered, "eventsEmittedOutsideRPC lists %q, which is not in the registry", event)
		require.NotContainsf(t, declared, event,
			"%q is declared by a method policy, so it must not also be listed as emitted outside RPC", event)
	}

	for _, d := range auditEventCatalog {
		_, byPolicy := declared[d.Type]
		_, byOther := outside[d.Type]
		require.Truef(t, byPolicy || byOther,
			"registered event %q is emitted by nothing: declare it on the RPC that emits it "+
				"or add it to eventsEmittedOutsideRPC", d.Type)
	}
}
