// Package business — the module-facing platform capability surface (issue #463).
//
// A sibling module on its own database cannot join the saas-starter transaction
// or reach the in-process job store, so it uses this surface to enqueue and
// lease durable jobs, notify users, request approvals, and emit typed audit
// events. The RPC adapter authenticates the caller from the forwarded Work
// Context and hands these methods a ModuleCaller; every method here re-derives
// authority from the per-principal registry, so the guard is enforced once, in
// one place, regardless of transport.
//
// The producer contract is at-least-once with idempotency keys: the caller
// cannot commit its outbox row inside the saas mutation the way the in-process
// producer does, so it retries against the (direction, scope, queue, source,
// idempotency_key) uniqueness and request_fingerprint dedupe described in
// module/JOBS.md.
package business

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"accounts/pkg/datasource/github"
	"accounts/pkg/eventcatalog"
	"accounts/pkg/events"
	gen "accounts/pkg/gen/saas/accounts/v1"
	jobsv1 "accounts/pkg/gen/saas/jobs/v1"
	"accounts/pkg/jobs"

	"github.com/codefly-dev/core/wool"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ModulePrincipalGrant declares what a module service principal may do on the
// capability surface. Queues bounds the queues it may enqueue to and claim from;
// Namespaces bounds the event namespaces it may publish into (the leading dotted
// segment of an event type); Resources names the permission resource types the
// module's own content is governed by, which is how the host authorizes reads of
// content it does not itself hold; CrossTenant lets it act on tenants other than
// its bound org and enqueue global (inbox-worker) jobs — the authority an inbox
// worker needs to service every tenant's deliveries on its queue. Tenant is the
// org a single-tenant module is bound to, which its minted Work Context carries;
// a cross-tenant module names the tenant per mint instead.
type ModulePrincipalGrant struct {
	Prefix      string
	Queues      []string
	Namespaces  []string
	Resources   []string
	CrossTenant bool
	Tenant      string
}

func (g ModulePrincipalGrant) allowsQueue(queue string) bool {
	for _, q := range g.Queues {
		if q == queue {
			return true
		}
	}
	return false
}

// allowsResource reports whether the principal's own content is governed by the
// given permission resource type. The registry is the allowlist, so a module
// that declares no resources may place nothing (fail-closed).
func (g ModulePrincipalGrant) allowsResource(resource string) bool {
	for _, r := range g.Resources {
		if r == resource {
			return true
		}
	}
	return false
}

// allowsNamespace reports whether the principal may publish an event whose
// namespace is the given leading segment. The registry is the allowlist, so an
// empty Namespaces denies every publish (fail-closed).
func (g ModulePrincipalGrant) allowsNamespace(namespace string) bool {
	for _, n := range g.Namespaces {
		if n == namespace {
			return true
		}
	}
	return false
}

// ModulePrincipalRegistry maps a module service principal id to its grant.
type ModulePrincipalRegistry map[string]ModulePrincipalGrant

// ContentResources is the union of the permission resource types every composed
// module declares its content under, sorted and deduplicated.
//
// The host owns permissions but holds no domain content, so it cannot name the
// resource a collection's documents, rows or models are governed by — only the
// composition knows which modules it composed. Reading the union from the
// declared registry is what keeps that knowledge out of this module: nothing
// here spells a consumer's noun, and a composition that declares none gets an
// empty set, which authorizes nothing (fail-closed).
func (r ModulePrincipalRegistry) ContentResources() []string {
	seen := make(map[string]struct{})
	for _, grant := range r {
		for _, resource := range grant.Resources {
			if resource != "" {
				seen[resource] = struct{}{}
			}
		}
	}
	resources := make([]string, 0, len(seen))
	for resource := range seen {
		resources = append(resources, resource)
	}
	slices.Sort(resources)
	return resources
}

// ModulePrincipalID is the service principal a composed module acts as. It is
// derived from the module's registration prefix — the same identity the
// registration broker binds as the credential's `sub` — so a composition
// declares a module's authority under the name it already federates with rather
// than inventing an opaque id, and every side computes the same value without
// coordinating. A UUID is what the identity columns downstream (the actor-chain
// journal, audit actors) are typed as.
func ModulePrincipalID(prefix string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://codefly.dev/module-principal/"+prefix)).String()
}

// ParseModulePrincipalRegistry decodes the deployment-provided registry of
// module service principals. The document its JSON describes is a map of module
// prefix to {"queues": [...], "namespaces": [...], "resources": [...],
// "cross_tenant": bool, "tenant": "<org uuid>"}, indexed here by the principal id
// derived from that prefix. An empty string yields an empty registry, which
// denies every caller (fail-closed).
func ParseModulePrincipalRegistry(raw string) (ModulePrincipalRegistry, error) {
	if raw == "" {
		return ModulePrincipalRegistry{}, nil
	}
	var wire map[string]struct {
		Queues      []string `json:"queues"`
		Namespaces  []string `json:"namespaces"`
		Resources   []string `json:"resources"`
		CrossTenant bool     `json:"cross_tenant"`
		Tenant      string   `json:"tenant"`
	}
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		return nil, err
	}
	registry := make(ModulePrincipalRegistry, len(wire))
	for prefix, grant := range wire {
		// A principal id is a valid module prefix by pattern, so an entry still
		// keyed the way the registry used to be — by the opaque principal id —
		// would otherwise parse into a principal no module can ever be, and every
		// call would be denied for a reason that names the caller rather than the
		// stale configuration.
		if err := uuid.Validate(prefix); err == nil {
			return nil, fmt.Errorf("module principal registry is keyed by module prefix, not principal id: %q", prefix)
		}
		if !registrationIdentityPattern.MatchString(prefix) || len(prefix) > 63 {
			return nil, fmt.Errorf("module principal registry has invalid module prefix %q", prefix)
		}
		// The tenant is sealed into a signed capability and compared against
		// organization ids, so a malformed one cannot be caught downstream: it
		// signs, then silently matches no tenant and drops the org from its own
		// audit record.
		if err := uuid.Validate(grant.Tenant); err != nil {
			return nil, fmt.Errorf("module principal %q must declare its tenant as an organization id: %w", prefix, err)
		}
		registry[ModulePrincipalID(prefix)] = ModulePrincipalGrant{
			Prefix:      prefix,
			Queues:      grant.Queues,
			Namespaces:  grant.Namespaces,
			Resources:   grant.Resources,
			CrossTenant: grant.CrossTenant,
			Tenant:      grant.Tenant,
		}
	}
	return registry, nil
}

// ModuleCaller is the authenticated module service principal, as the RPC adapter
// derived it from the forwarded Work Context.
type ModuleCaller struct {
	PrincipalID string // the acting service principal (subject) id
	BoundOrg    string // the tenant the principal is bound to
}

// grant resolves the caller's declared authority. An unknown principal is
// denied — the registry is the allowlist, so a nil/empty registry fails closed.
func (s *Service) moduleGrant(caller ModuleCaller) (ModulePrincipalGrant, error) {
	if caller.PrincipalID == "" {
		return ModulePrincipalGrant{}, status.Error(codes.Unauthenticated, "module caller identity required")
	}
	grant, ok := s.modulePrincipals[caller.PrincipalID]
	if !ok {
		return ModulePrincipalGrant{}, status.Errorf(codes.PermissionDenied, "principal %s is not a registered module principal", caller.PrincipalID)
	}
	return grant, nil
}

// ModuleContentResources reports the permission resource types the content of
// one composed module is governed by. prefix is the module's registration
// prefix — the name a composition declares its principal under, and the audience
// a capability minted for that module carries.
//
// The host owns permissions but holds no domain content, so it cannot name the
// resource a collection's records are governed by; only the composition knows
// which modules it composed. Reading the answer from the declared registry is
// what keeps that knowledge out of this module, and an audience that names no
// registered module — or one that declares no content — resolves to nothing
// rather than to an invented authority (fail-closed).
//
// This is the per-caller counterpart of ContentResources, which takes the union
// because its caller is an org administrator rather than one module.
func (s *Service) ModuleContentResources(prefix string) ([]string, error) {
	grant, registered := s.modulePrincipals[ModulePrincipalID(prefix)]
	if !registered || len(grant.Resources) == 0 {
		return nil, status.Error(codes.PermissionDenied, "capability audience declares no module content")
	}
	return grant.Resources, nil
}

// authorizeTenant resolves the tenant a call targets. A call may only name its
// own bound tenant unless the principal holds a cross-tenant grant.
func authorizeTenant(caller ModuleCaller, grant ModulePrincipalGrant, requested string) error {
	if requested == caller.BoundOrg {
		return nil
	}
	if grant.CrossTenant {
		return nil
	}
	return status.Errorf(codes.PermissionDenied, "principal %s may not act on tenant %s", caller.PrincipalID, requested)
}

// requireTenantMember verifies a user/subject actually belongs to the named
// tenant before the surface acts on it, so a module bound to tenant A cannot
// target a user or subject in tenant B (which the tenant guard alone does not
// prevent — org membership is a separate fact). The membership read runs under
// the control-plane role because organization_members is RLS-scoped and the
// caller carries no tenant GUC of its own.
func (s *Service) requireTenantMember(ctx context.Context, tenant, userID string) error {
	var member bool
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		var e error
		member, e = s.store.OrgMemberExists(ctx, tenant, userID)
		return e
	}); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	if !member {
		return status.Errorf(codes.PermissionDenied, "user %s is not a member of tenant %s", userID, tenant)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

// ModuleEnqueueJob appends durable work on behalf of a module. tenant is the
// authoritative tenant the caller claims to act on: org-scoped work must name
// that same tenant, and subject-scoped work must target a member of it, so the
// job's scope can never reach a tenant the caller was not authorized for. Tenant-
// and subject-scoped work goes through the request-scoped producer inside a
// matching transaction so the security-definer enqueue verifies the scope;
// global inbox work requires the cross-tenant grant and uses the privileged
// worker producer.
func (s *Service) ModuleEnqueueJob(ctx context.Context, caller ModuleCaller, tenant string, req *jobsv1.EnqueueJobRequest) (*jobsv1.EnqueueJobResponse, error) {
	w := wool.Get(ctx).In("ModuleEnqueueJob")
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return nil, err
	}
	job := req.GetJob()
	if job == nil {
		return nil, status.Error(codes.InvalidArgument, "job is required")
	}
	if !grant.allowsQueue(job.GetQueue()) {
		return nil, status.Errorf(codes.PermissionDenied, "principal %s may not use queue %q", caller.PrincipalID, job.GetQueue())
	}

	scope := job.GetScope()
	var resp *jobsv1.EnqueueJobResponse
	switch {
	case scope.GetOrganizationId() != "":
		orgID := scope.GetOrganizationId()
		// The scope's org must be the tenant the caller is authorized for; a
		// mismatch would let an authorized tenant name smuggle work into another.
		if orgID != tenant {
			return nil, status.Error(codes.InvalidArgument, "job organization scope must equal the request tenant")
		}
		if err := authorizeTenant(caller, grant, tenant); err != nil {
			return nil, err
		}
		err = s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
			resp, err = s.moduleProducer.EnqueueJob(ctx, req)
			return err
		})
	case scope.GetSubjectId() != "":
		if err := authorizeTenant(caller, grant, tenant); err != nil {
			return nil, err
		}
		// A subject-scoped job names a user; without this the tenant guard is a
		// no-op (WithUserTx sets current_user_id to the subject, so the security-
		// definer's subject==current_user_id check is tautological). Bind the
		// subject to the authorized tenant explicitly.
		if err := s.requireTenantMember(ctx, tenant, scope.GetSubjectId()); err != nil {
			return nil, err
		}
		err = s.store.WithUserTx(ctx, scope.GetSubjectId(), func(ctx context.Context) error {
			resp, err = s.moduleProducer.EnqueueJob(ctx, req)
			return err
		})
	case scope.GetGlobal():
		if !grant.CrossTenant {
			return nil, status.Errorf(codes.PermissionDenied, "principal %s may not enqueue global work", caller.PrincipalID)
		}
		// Global/inbox work bypasses the request-scoped producer: the privileged
		// worker store opens its own short transaction, the only path allowed to
		// append global or inbox rows (module/JOBS.md authority model).
		globalProducer, ok := s.moduleJobStore.(jobs.Producer)
		if !ok {
			return nil, status.Error(codes.Internal, "module job store cannot enqueue global work")
		}
		resp, err = globalProducer.EnqueueJob(ctx, req)
	default:
		return nil, status.Error(codes.InvalidArgument, "job scope is required")
	}
	if err != nil {
		return nil, moduleJobError(w, err)
	}
	return resp, nil
}

// ModuleClaimJobs leases a bounded batch from one queue the principal owns.
// Claiming a queue reads every scope on it — global work and every tenant's
// org- and subject-scoped jobs (the claim selects by queue with no tenant
// filter) — so a claimed payload can belong to any tenant. That makes claiming
// an inherently cross-tenant, inbox-worker operation: it requires the cross-
// tenant grant, not merely the queue grant. Without this a tenant-bound
// principal could read other tenants' confidential job payloads off a shared
// queue (e.g. datasource, which carries every tenant's ingest jobs).
func (s *Service) ModuleClaimJobs(ctx context.Context, caller ModuleCaller, req *jobsv1.ClaimJobsRequest) (*jobsv1.ClaimJobsResponse, error) {
	w := wool.Get(ctx).In("ModuleClaimJobs")
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return nil, err
	}
	if !grant.allowsQueue(req.GetQueue()) {
		return nil, status.Errorf(codes.PermissionDenied, "principal %s may not claim queue %q", caller.PrincipalID, req.GetQueue())
	}
	if !grant.CrossTenant {
		return nil, status.Errorf(codes.PermissionDenied, "principal %s may not claim queue %q: claiming reads across tenants and requires a cross-tenant grant", caller.PrincipalID, req.GetQueue())
	}
	resp, err := s.moduleJobStore.Claim(ctx, req)
	if err != nil {
		return nil, moduleJobError(w, err)
	}
	return resp, nil
}

// ModuleHeartbeatJob renews a live lease. The fencing token is the authority: a
// caller without the current, unexpired token cannot renew.
func (s *Service) ModuleHeartbeatJob(ctx context.Context, caller ModuleCaller, req *jobsv1.HeartbeatJobRequest) (*jobsv1.HeartbeatJobResponse, error) {
	w := wool.Get(ctx).In("ModuleHeartbeatJob")
	if _, err := s.moduleGrant(caller); err != nil {
		return nil, err
	}
	resp, err := s.moduleJobStore.Heartbeat(ctx, req)
	if err != nil {
		return nil, moduleJobError(w, err)
	}
	return resp, nil
}

// ModuleAckJob completes a leased job successfully.
func (s *Service) ModuleAckJob(ctx context.Context, caller ModuleCaller, req *jobsv1.CompleteJobRequest) error {
	w := wool.Get(ctx).In("ModuleAckJob")
	if _, err := s.moduleGrant(caller); err != nil {
		return err
	}
	if err := s.moduleJobStore.Complete(ctx, req); err != nil {
		return moduleJobError(w, err)
	}
	return nil
}

// ModuleNackJob fails a leased job: retryable reschedules (or dead-letters when
// the attempt budget is exhausted); otherwise it dead-letters immediately.
func (s *Service) ModuleNackJob(ctx context.Context, caller ModuleCaller, lease *jobsv1.JobLeaseReference, failure *jobsv1.JobFailure, retryable bool, retryAt *timestamppb.Timestamp) error {
	w := wool.Get(ctx).In("ModuleNackJob")
	if _, err := s.moduleGrant(caller); err != nil {
		return err
	}
	if retryable {
		if retryAt == nil {
			return status.Error(codes.InvalidArgument, "retry_at is required for a retryable nack")
		}
		if _, err := s.moduleJobStore.Retry(ctx, &jobsv1.RetryJobRequest{Lease: lease, Failure: failure, RetryAt: retryAt}); err != nil {
			return moduleJobError(w, err)
		}
		return nil
	}
	if err := s.moduleJobStore.DeadLetter(ctx, &jobsv1.DeadLetterJobRequest{Lease: lease, Failure: failure}); err != nil {
		return moduleJobError(w, err)
	}
	return nil
}

// moduleJobError maps the product-neutral job sentinels onto gRPC codes so the
// module sees a stable, transport-independent contract.
func moduleJobError(w *wool.Wool, err error) error {
	switch {
	case errors.Is(err, jobs.ErrInvalidCommand), errors.Is(err, jobs.ErrOrderingKeyTooLong):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, jobs.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, jobs.ErrLeaseLost):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, jobs.ErrJobNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, jobs.ErrTransactionRequired):
		return status.Error(codes.Internal, err.Error())
	}
	return w.Wrap(err)
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

// ModuleNotifyUserInput is a named struct rather than a long positional string
// list so a call site cannot silently transpose title/body/type/category.
type ModuleNotifyUserInput struct {
	Tenant         string
	UserID         string
	Title          string
	Body           string
	Type           string
	ActionURL      string
	Category       string
	IdempotencyKey string
}

// ModuleNotifyUserResult reports whether the notification was delivered or
// suppressed by category policy, plus the row id when delivered.
type ModuleNotifyUserResult struct {
	NotificationID string
	Delivered      bool
}

// ModuleNotifyUser routes a notification through the same category policy
// internal callers use. The target user must belong to the named tenant:
// notifications are user-scoped, so the tenant guard alone does not stop a
// module bound to tenant A from notifying a user in tenant B.
func (s *Service) ModuleNotifyUser(ctx context.Context, caller ModuleCaller, in ModuleNotifyUserInput) (ModuleNotifyUserResult, error) {
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return ModuleNotifyUserResult{}, err
	}
	if err := authorizeTenant(caller, grant, in.Tenant); err != nil {
		return ModuleNotifyUserResult{}, err
	}
	if _, err := notificationCategoryIsMandatory(NotificationCategory(in.Category)); err != nil {
		return ModuleNotifyUserResult{}, status.Errorf(codes.InvalidArgument, "invalid notification category %q", in.Category)
	}
	if err := s.requireTenantMember(ctx, in.Tenant, in.UserID); err != nil {
		return ModuleNotifyUserResult{}, err
	}
	notification, err := s.CreateNotification(ctx, CreateNotificationInput{
		UserID:         in.UserID,
		OrgID:          in.Tenant,
		Title:          in.Title,
		Body:           in.Body,
		Type:           in.Type,
		ActionURL:      in.ActionURL,
		Category:       NotificationCategory(in.Category),
		IdempotencyKey: in.IdempotencyKey,
	})
	if err != nil {
		return ModuleNotifyUserResult{}, err
	}
	if notification == nil {
		return ModuleNotifyUserResult{Delivered: false}, nil
	}
	return ModuleNotifyUserResult{NotificationID: notification.ID, Delivered: true}, nil
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

// ModuleRequestApprovalInput is the module-facing half of the approval
// primitive: it opens a pending request whose resume outbox job the module
// consumes on its own queue once the request is approved.
type ModuleRequestApprovalInput struct {
	Tenant        string
	Resource      string
	Action        string
	Subject       map[string]any
	RequestedBy   string
	Quorum        int
	ApproverSet   []string
	AllowSelf     bool
	ResumeQueue   string
	ResumeTopic   string
	ResumePayload map[string]any
	ExpiresAt     *time.Time
	EscalateAt    *time.Time
}

// ModuleRequestApproval creates a pending approval on the caller's tenant. The
// resume queue must be one the principal may claim, so a decision cannot direct
// work onto a queue the module does not own.
func (s *Service) ModuleRequestApproval(ctx context.Context, caller ModuleCaller, in ModuleRequestApprovalInput) (string, error) {
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return "", err
	}
	if err := authorizeTenant(caller, grant, in.Tenant); err != nil {
		return "", err
	}
	if !grant.allowsQueue(in.ResumeQueue) {
		return "", status.Errorf(codes.PermissionDenied, "principal %s may not resume onto queue %q", caller.PrincipalID, in.ResumeQueue)
	}
	id, err := s.CreateApprovalRequest(ctx, &CreateApprovalRequestInput{
		OrgID:       in.Tenant,
		Resource:    in.Resource,
		Action:      in.Action,
		Subject:     in.Subject,
		RequestedBy: in.RequestedBy,
		Quorum:      in.Quorum,
		Policy:      ApprovalPolicy{ApproverSet: in.ApproverSet, AllowSelf: in.AllowSelf},
		ResumeRef:   ResumeRef{Queue: in.ResumeQueue, Topic: in.ResumeTopic, Payload: in.ResumePayload},
		ExpiresAt:   in.ExpiresAt,
		EscalateAt:  in.EscalateAt,
	})
	if err != nil {
		return "", moduleApprovalError(err)
	}
	return id, nil
}

// ModuleGetApproval returns one approval request on the caller's tenant.
func (s *Service) ModuleGetApproval(ctx context.Context, caller ModuleCaller, tenant, id string) (*ApprovalRequest, error) {
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return nil, err
	}
	if err := authorizeTenant(caller, grant, tenant); err != nil {
		return nil, err
	}
	approval, err := s.GetApprovalRequest(ctx, tenant, id)
	if err != nil {
		return nil, moduleApprovalError(err)
	}
	return approval, nil
}

// ModuleCancelApproval withdraws a still-open approval request.
func (s *Service) ModuleCancelApproval(ctx context.Context, caller ModuleCaller, tenant, id, reason string) error {
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return err
	}
	if err := authorizeTenant(caller, grant, tenant); err != nil {
		return err
	}
	if err := s.CancelApprovalRequest(ctx, tenant, id, reason); err != nil {
		return moduleApprovalError(err)
	}
	return nil
}

// moduleApprovalError maps approval-engine errors onto gRPC codes by their typed
// StoreError. An untyped error is an internal fault, NOT bad client input: the
// previous blanket InvalidArgument told a module its request was malformed even
// when the database failed, so it would retry the same request forever.
func moduleApprovalError(err error) error {
	var se *StoreError
	if errors.As(err, &se) {
		switch se.StoreErrorType {
		case ErrTypeValidation:
			return status.Error(codes.InvalidArgument, err.Error())
		case ErrTypeNotFound:
			return status.Error(codes.NotFound, err.Error())
		case ErrTypeConflict:
			return status.Error(codes.FailedPrecondition, err.Error())
		case ErrTypePermission:
			return status.Error(codes.PermissionDenied, err.Error())
		}
	}
	return status.Error(codes.Internal, err.Error())
}

// enqueueApprovalResume appends the resume outbox job for an approved request.
// It runs inside the Decide transaction (moduleProducer is request-scoped), so
// the approved transition and the resume job commit atomically. The approval id
// is the idempotency key: a retried decision resolves to the same durable job
// rather than resuming the gated action twice. No-op when no resume queue is
// declared or the producer is not wired.
//
// The payload stamps the outcome so the module's handler need not read it back:
// decision, and decider — the single approver whose vote completed quorum, not
// the full approver set. When quorum > 1 the other approvers are recoverable
// from approval_decisions via the stamped approval_id.
func (s *Service) enqueueApprovalResume(ctx context.Context, req *ApprovalRequest, decision ApprovalDecisionKind, decider string) error {
	if req.ResumeRef.Queue == "" {
		return nil
	}
	// A request that declares a resume queue MUST get its resume job or the whole
	// decision aborts: silently approving without enqueuing the resume strands the
	// gated action with no signal, which is exactly the loss this primitive exists
	// to prevent. Fail the decision instead of dropping the resume.
	if s.moduleProducer == nil {
		return fmt.Errorf("approval %s declares resume queue %q but the module producer is not wired", req.ID, req.ResumeRef.Queue)
	}
	payload, err := json.Marshal(map[string]any{
		"approval_id": req.ID,
		"decision":    string(decision),
		"decider":     decider,
		"resource":    req.Resource,
		"action":      req.Action,
		"subject":     req.Subject,
		"payload":     req.ResumeRef.Payload,
	})
	if err != nil {
		return err
	}
	topic := req.ResumeRef.Topic
	if topic == "" {
		topic = "approval.resumed"
	}
	_, err = s.moduleProducer.EnqueueJob(ctx, &jobsv1.EnqueueJobRequest{
		Job: &jobsv1.NewJob{
			Direction:      jobsv1.JobDirection_JOB_DIRECTION_OUTBOX,
			Scope:          &jobsv1.JobScope{Value: &jobsv1.JobScope_OrganizationId{OrganizationId: req.OrgID}},
			Queue:          req.ResumeRef.Queue,
			Topic:          topic,
			Source:         "approvals",
			IdempotencyKey: "approval-resume:" + req.ID,
			SchemaVersion:  1,
			Payload:        payload,
			ContentType:    "application/json",
			MaxAttempts:    24,
		},
	})
	return err
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// ModuleEmitAuditEvent emits a registered audit event onto the tenant's audit
// spine. The event type must be registered in the code-owned catalog;
// unregistered types are rejected, not stored free-form. An empty tenant emits a
// system-scoped event and requires the cross-tenant grant.
func (s *Service) ModuleEmitAuditEvent(ctx context.Context, caller ModuleCaller, tenant, eventType, actor, solution, entryID, idempotencyKey string, fields *structpb.Struct) error {
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return err
	}
	if tenant == "" {
		if !grant.CrossTenant {
			return status.Errorf(codes.PermissionDenied, "principal %s may not emit system-scoped audit events", caller.PrincipalID)
		}
	} else if err := authorizeTenant(caller, grant, tenant); err != nil {
		return err
	}
	payload := make(map[string]any)
	for k, v := range fields.AsMap() {
		payload[k] = v
	}
	// The scope solution wins over any client-supplied "solution" field: the
	// scope is the trusted value, and it is set last so a field cannot shadow it.
	payload["solution"] = solution
	// Enforce the registered schema at the boundary: an unregistered type or an
	// unknown/mistyped field is rejected, not stored free-form. (Downstream
	// registry validation is only advisory; this is where the module's typed-
	// fields contract is actually enforced.)
	if err := ValidatePayload(EventType(eventType), payload); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	// The emission IS the operation the module requested, so a failed write must
	// surface as an error — not the fire-and-forget emit(), which swallows the
	// error and would report success while the event was silently lost.
	emit := func(ctx context.Context) error {
		entry := s.buildAuditEntry(ctx, actor, "agent", EventType(eventType), solution, entryID, tenant, payload)
		entry.IdempotencyKey = idempotencyKey
		return s.emitEntryTx(ctx, entry)
	}
	if tenant == "" {
		if err := s.store.WithControlPlane(ctx, emit); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		return nil
	}
	if err := s.store.WithOrgTx(ctx, tenant, emit); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	return nil
}

// ---------------------------------------------------------------------------
// Record placement
// ---------------------------------------------------------------------------

// ModulePlaceRecord binds one of the calling module's records to a node of the
// tenant's scope tree and returns that node's id. Placement is what makes a
// record resolvable at all: CheckAccess and ListAccessibleScopes read a record's
// true scope from its own registered node and accept no caller-supplied path, so
// a record that was never placed is denied to every subject.
//
// The authority bound is the resource vocabulary the composition declared for
// this principal. A module may place a record only under a resource type its own
// grant names, so it can neither introduce a type it holds no grant for nor
// re-point a record another module owns.
func (s *Service) ModulePlaceRecord(ctx context.Context, caller ModuleCaller, tenant, scopePath, kind, label, resourceType, resourceID string) (string, error) {
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return "", err
	}
	if !grant.allowsResource(resourceType) {
		return "", status.Errorf(codes.PermissionDenied, "principal %s may not place records of resource type %q", caller.PrincipalID, resourceType)
	}
	if err := authorizeTenant(caller, grant, tenant); err != nil {
		return "", err
	}

	offered := &gen.ScopeNode{
		Id:           NewIDString(),
		OrgId:        tenant,
		ScopePath:    scopePath,
		Kind:         kind,
		Label:        label,
		ResourceType: resourceType,
		ResourceId:   resourceID,
	}
	var nodeID string
	if err := s.store.WithOrgTx(ctx, tenant, func(ctx context.Context) error {
		placed, err := s.store.PlaceRecordNode(ctx, offered)
		if err != nil {
			return err
		}
		nodeID = placed.Id
		if placed.Id != offered.Id {
			// Already placed — the retry this surface's at-least-once contract
			// expects, unless the caller named a different path. A record resolves
			// through exactly one node, so moving it would silently rewrite who can
			// reach it; that is an authorization change, not a placement.
			if placed.ScopePath != scopePath {
				return status.Errorf(codes.FailedPrecondition, "record is already placed at scope %q", placed.ScopePath)
			}
			return nil
		}
		return s.emitTx(ctx, caller.PrincipalID, "agent", EventScopeNodeRegistered, "scope_node", placed.Id, tenant,
			map[string]any{"scope_path": placed.ScopePath, "kind": placed.Kind})
	}); err != nil {
		return "", err
	}
	return nodeID, nil
}

// ---------------------------------------------------------------------------
// Datasource blobs
// ---------------------------------------------------------------------------

// ModuleFetchDatasourceBlob returns the bytes of a GitHub blob referenced by a
// datasource change set, so the documents module can pull the content a delivery
// omitted inline. It supersedes the signed content ticket: the module already
// claims the datasource queue to receive the change set, and claiming that queue
// is an inherently cross-tenant inbox operation (every tenant's ingest jobs land
// on it), so a principal trusted to claim it is trusted to fetch the blobs those
// jobs reference — no per-blob ticket is minted.
//
// Authorization is the caller's datasource-queue grant plus the source row's own
// org, NOT a request-supplied tenant: the source is loaded by id and the fetch
// is authorized against that source's org, so a cross-tenant claimer reaches any
// source while a hypothetical org-bound principal reaches only its own. The blob
// is re-fetched with the source's decrypted token and never leaves accounts;
// anything over maxContentTicketBytes is refused rather than buffered.
func (s *Service) ModuleFetchDatasourceBlob(ctx context.Context, caller ModuleCaller, sourceID, blobSHA string) ([]byte, string, error) {
	w := wool.Get(ctx).In("ModuleFetchDatasourceBlob")
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return nil, "", err
	}
	if !grant.allowsQueue(datasourceIngestQueue) {
		return nil, "", status.Errorf(codes.PermissionDenied, "principal %s may not fetch datasource blobs: the %q queue grant is required", caller.PrincipalID, datasourceIngestQueue)
	}
	if s.datasourceCipher == nil || s.newGitHubClient == nil {
		return nil, "", status.Error(codes.FailedPrecondition, "datasource connector is not configured")
	}
	source, err := s.store.GetDatasourceSourceByID(ctx, sourceID)
	if err != nil {
		return nil, "", status.Error(codes.Internal, w.Wrapf(err, "load source").Error())
	}
	if source == nil || source.Provider != DatasourceProviderGitHub {
		return nil, "", status.Errorf(codes.NotFound, "datasource source %s not found", sourceID)
	}
	if err := authorizeTenant(caller, grant, source.OrgID); err != nil {
		return nil, "", err
	}
	client, err := s.githubClientForSource(ctx, source)
	if err != nil {
		// A revoked installation or an unreadable credential is a precondition the
		// tenant must repair, not an internal fault; reporting it as Internal tells
		// a module caller to retry something that can never succeed.
		var failure *jobs.ProcessingError
		if errors.As(err, &failure) {
			if failure.Retryable {
				return nil, "", status.Error(codes.Unavailable, failure.Failure.Message)
			}
			return nil, "", status.Error(codes.FailedPrecondition, failure.Failure.Message)
		}
		return nil, "", status.Error(codes.Internal, w.Wrapf(err, "authenticate to github").Error())
	}
	// Trust boundary: blobSHA is caller-supplied and NOT re-validated against the
	// change set that referenced it. Authorization is enforced at the repository
	// grain — the caller is authorized against source.OrgID, and the SHA is read
	// only from that source's own repo (source.Repo) with that source's own token,
	// so a module can never reach another tenant's repository through this call.
	// Within the authorized repo, a git blob SHA is a content-addressed,
	// unguessable (SHA-1/-256) capability that accounts only ever hands a module
	// via an in-scope change-set payload, so an in-scope caller cannot fabricate a
	// SHA for out-of-scope content it was not already given. Re-deriving the tree
	// to prove the SHA is reachable from the source's branch would reintroduce the
	// per-fetch ticket this RPC exists to remove and break the intended lag between
	// a module's cursor and the repo head, so the repo-grained check is the
	// boundary by design.
	content, err := client.GetBlob(ctx, source.Repo, blobSHA, maxContentTicketBytes)
	if err != nil {
		if errors.Is(err, github.ErrFileTooLarge) {
			return nil, "", status.Errorf(codes.FailedPrecondition, "blob exceeds the %d-byte fetch limit", maxContentTicketBytes)
		}
		return nil, "", status.Error(codes.Internal, w.Wrapf(err, "fetch blob").Error())
	}
	// Record the data access on the source's own tenant spine. Each fetch is a
	// distinct access event (no idempotency key), and a transient audit-write
	// failure must not fail the read the module needs, so this is the
	// fire-and-forget emit rather than a transactional one.
	s.emit(ctx, caller.PrincipalID, "agent", EventDatasourceBlobFetched, "datasource", source.ID, source.OrgID,
		map[string]any{"repo": source.Repo, "blob_sha": blobSHA, "bytes": len(content)})
	return content, http.DetectContentType(content), nil
}

// Domain events (pub/sub, issue #493)
// ---------------------------------------------------------------------------

// moduleTx surfaces the ambient pgx transaction the Store opened for this
// request (WithOrgTx / WithControlPlane both carry it on ctx) so the events
// transport can join it — the transactional-outbox rule. It is typed as the
// port's opaque TxHandle, so the business layer never imports the concrete
// driver; a nil handle (no active tx) makes the transport open its own, which
// is only the test/simple-caller path, never a tenant publish.
func moduleTx(ctx context.Context) events.TxHandle {
	return ctx.Value("tx") //nolint:staticcheck // shared transaction context key with the Store layer
}

// mapPublishError narrows the transport's sentinel publish errors to gRPC codes:
// a reused id carrying a different fact is a caller contract violation, and an
// unroutable envelope is invalid input; anything else is an internal fault.
func mapPublishError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, events.ErrIdempotencyConflict):
		return status.Error(codes.FailedPrecondition, "event id reused with a different envelope")
	case errors.Is(err, events.ErrInvalidEnvelope):
		return status.Error(codes.InvalidArgument, "event envelope is not routable: id, type, and source are required")
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// ModulePublishEvent appends one domain event to the transactional outbox for
// the caller's tenant and returns the accepted envelope id. Authority is
// namespace + tenant: the event type's namespace (the segment before the first
// dot) must be one the principal declares, and the event is published for a
// tenant the caller may act on, and the type must be declared in the composed
// catalog. The insert joins the WithOrgTx transaction so
// the security-definer publish gate re-checks tenant == current_org under the
// app_tenant role; the relay fans the event out to matching subscriptions after
// commit. Publishing is deliberately not audited per-event — the durable event
// of record is itself the trail — so only subscription changes and replays emit
// audit events.
func (s *Service) ModulePublishEvent(ctx context.Context, caller ModuleCaller, tenant string, envelope *events.EventEnvelope) (string, error) {
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return "", err
	}
	if s.eventTransport == nil {
		return "", status.Error(codes.Internal, "event transport is not configured")
	}
	if envelope == nil {
		return "", status.Error(codes.InvalidArgument, "envelope is required")
	}
	if tenant == "" {
		return "", status.Error(codes.InvalidArgument, "tenant is required")
	}
	if err := authorizeTenant(caller, grant, tenant); err != nil {
		return "", err
	}
	namespace := eventcatalog.Namespace(envelope.GetType())
	if !grant.allowsNamespace(namespace) {
		return "", status.Errorf(codes.PermissionDenied, "principal %s may not publish events in namespace %q", caller.PrincipalID, namespace)
	}
	// The authorized tenant wins over any tenant id the client wrote into the
	// envelope: a caller cannot smuggle another tenant's scope past the namespace
	// gate. The DB gate re-checks it under the app_tenant role regardless.
	envelope.TenantId = tenant
	// Publish authority (the namespace grant) is deployment configuration, while
	// the catalog is compiled into this binary, so the two can disagree: a
	// principal may hold a namespace whose types this build was never composed
	// with. Refusing the publish is the only way that disagreement is visible.
	// Accepting it would silently drop the type's whole contract — its declared
	// partition, its visibility, its retention — and the producer that declared
	// it needs ordering would get none, with nothing anywhere reporting why.
	declared, inCatalog := eventcatalog.LookupPublished(envelope.GetType())
	if !inCatalog {
		return "", status.Errorf(codes.FailedPrecondition, "event type %q is not declared in this deployment's event catalog; add it to the module's events contribution and recompose", envelope.GetType())
	}
	// The declared partition template is the ordering domain, and it is what a
	// caller that omits the key gets. Ordering is not free — publish_domain_event
	// holds a transaction-scoped advisory lock on the partition until the
	// producing transaction commits — so a type that declares no partition
	// publishes unordered rather than inheriting one it never promised. A key the
	// caller set deliberately (e.g. per-aggregate ordering within a tenant) wins
	// over the declaration.
	if envelope.GetPartitionKey() == "" {
		envelope.PartitionKey = eventcatalog.ResolvePartition(declared.Partition, tenant, envelope.GetBoundaryId())
	}

	if err := s.store.WithOrgTx(ctx, tenant, func(ctx context.Context) error {
		return s.eventTransport.Publish(ctx, moduleTx(ctx), envelope)
	}); err != nil {
		return "", mapPublishError(err)
	}
	return envelope.GetId(), nil
}

// ModuleSubscribe creates, or idempotently re-affirms, a durable subscription
// delivering events matching typePattern onto queue for the calling principal.
// Authority is the queue grant plus two visibility rules. A solution principal
// may never subscribe a pattern that matches an internal published event, so
// internal events stay intra-platform; and it may never subscribe the platform's
// own namespace, whose types are the audit spine published for outbound webhook
// delivery — the compliance record of every action in the tenant, including the
// ones taken against the module itself. A re-subscribe of the same (principal,
// pattern, queue) returns the existing live row and emits no second audit event.
func (s *Service) ModuleSubscribe(ctx context.Context, caller ModuleCaller, typePattern, queue, delivery string) (*EventSubscription, error) {
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return nil, err
	}
	if !grant.allowsQueue(queue) {
		return nil, status.Errorf(codes.PermissionDenied, "principal %s may not use queue %q", caller.PrincipalID, queue)
	}
	// An internal-visibility event is never delivered to a tenant-scoped
	// subscriber: reject a pattern that would match any internal published type.
	for _, internalType := range eventcatalog.InternalPublishedTypes() {
		if events.Matches(typePattern, internalType) {
			return nil, status.Errorf(codes.PermissionDenied, "type pattern %q matches internal event %q, which is not subscribable", typePattern, internalType)
		}
	}
	// The platform namespace is external so an org's own endpoints may receive it
	// over a webhook the org configured. That is a tenant's grant over its own
	// records, not a capability a module inherits by declaring a queue.
	if eventcatalog.Namespace(typePattern) == auditEventsNamespace {
		return nil, status.Errorf(codes.PermissionDenied, "type pattern %q is in the platform namespace, which is not subscribable", typePattern)
	}
	// Ordered delivery is only meaningful over a type that declares a partition;
	// without one the relay hands deliveries out unordered and says nothing. A
	// subscriber that asked for FIFO has to be told here, at subscribe time,
	// rather than discovering the reordering in production.
	if delivery == string(events.DeliveryOrdered) {
		for _, unorderedType := range eventcatalog.UnorderedPublishedTypesInNamespace(eventcatalog.Namespace(typePattern)) {
			if events.Matches(typePattern, unorderedType) {
				return nil, status.Errorf(codes.FailedPrecondition, "type pattern %q matches event %q, which declares no partition; ordered delivery cannot be provided for it", typePattern, unorderedType)
			}
		}
	}

	var created *EventSubscription
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		sub, inserted, e := s.store.CreateEventSubscription(ctx, &EventSubscription{
			SubscriberPrincipalID: caller.PrincipalID,
			TypePattern:           typePattern,
			Queue:                 queue,
			Delivery:              delivery,
			CreatedBy:             caller.PrincipalID,
		})
		if e != nil {
			return e
		}
		created = sub
		if !inserted {
			return nil // idempotent re-affirm of an existing subscription: no new audit event
		}
		return s.emitTx(ctx, caller.PrincipalID, "agent", EventEventSubscriptionCreated, "event_subscription", sub.ID, "", map[string]any{
			"subscription_id":         sub.ID,
			"subscriber_principal_id": sub.SubscriberPrincipalID,
			"type_pattern":            sub.TypePattern,
			"queue":                   sub.Queue,
		})
	}); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return created, nil
}

// ModuleUnsubscribe revokes one of the caller's own subscriptions. The revoke is
// scoped by subscriber principal, so a caller can only revoke what it owns;
// revoking an unknown or already-revoked subscription is NotFound and emits no
// audit event.
func (s *Service) ModuleUnsubscribe(ctx context.Context, caller ModuleCaller, subscriptionID string) error {
	if _, err := s.moduleGrant(caller); err != nil {
		return err
	}
	var revoked bool
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		ok, e := s.store.RevokeEventSubscription(ctx, subscriptionID, caller.PrincipalID)
		if e != nil {
			return e
		}
		revoked = ok
		if !ok {
			return nil
		}
		return s.emitTx(ctx, caller.PrincipalID, "agent", EventEventSubscriptionRevoked, "event_subscription", subscriptionID, "", map[string]any{
			"subscription_id": subscriptionID,
		})
	}); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	if !revoked {
		return status.Errorf(codes.NotFound, "subscription %s not found for principal %s", subscriptionID, caller.PrincipalID)
	}
	return nil
}

// ModuleListSubscriptions returns the calling principal's live subscriptions.
func (s *Service) ModuleListSubscriptions(ctx context.Context, caller ModuleCaller) ([]*EventSubscription, error) {
	if _, err := s.moduleGrant(caller); err != nil {
		return nil, err
	}
	var subscriptions []*EventSubscription
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		var e error
		subscriptions, e = s.store.ListEventSubscriptions(ctx, caller.PrincipalID)
		return e
	}); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return subscriptions, nil
}

// ModuleReplayEvents re-delivers durable events of one type for the caller's
// tenant, created at or after since, only to the caller's own subscriptions.
// Each redelivery carries a fresh idempotency key so a consumer that already
// acknowledged the event still receives the replay. The replay itself is
// audited (a control-plane action) but the individual redeliveries are not.
func (s *Service) ModuleReplayEvents(ctx context.Context, caller ModuleCaller, tenant, eventType string, since time.Time) (int, error) {
	grant, err := s.moduleGrant(caller)
	if err != nil {
		return 0, err
	}
	if s.eventTransport == nil {
		return 0, status.Error(codes.Internal, "event transport is not configured")
	}
	if tenant == "" {
		return 0, status.Error(codes.InvalidArgument, "tenant is required")
	}
	if err := authorizeTenant(caller, grant, tenant); err != nil {
		return 0, err
	}
	redelivered, err := s.eventTransport.Replay(ctx, events.ReplaySelector{
		Type:                  eventType,
		TenantID:              tenant,
		Since:                 since,
		SubscriberPrincipalID: caller.PrincipalID,
	})
	if err != nil {
		return 0, status.Error(codes.Internal, err.Error())
	}
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		return s.emitTx(ctx, caller.PrincipalID, "agent", EventEventReplayed, "domain_event", eventType, "", map[string]any{
			"type":        eventType,
			"redelivered": redelivered,
		})
	}); err != nil {
		return 0, status.Error(codes.Internal, err.Error())
	}
	return redelivered, nil
}
