package adapters

import (
	"context"
	"errors"
	"time"

	"accounts/pkg/business"
	gen "accounts/pkg/gen/saas/accounts/v1"
	jobsv1 "accounts/pkg/gen/saas/jobs/v1"

	codefly "github.com/codefly-dev/sdk-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ModuleCapabilitiesServer serves the module-facing capability surface (issue
// #463) on the accounts internal listener. It authenticates the caller from the
// forwarded Work Context and delegates every capability to the shared
// business.Service, which enforces the per-principal grant.
type ModuleCapabilitiesServer struct {
	gen.UnsafeModuleCapabilitiesServiceServer
}

// moduleCapabilitiesSingleton is shared between the raw-gRPC internal listener
// and the Connect listener, mirroring the other cross-protocol singletons.
var moduleCapabilitiesSingleton = &ModuleCapabilitiesServer{}

// ModuleCapabilitiesSingleton returns the shared server instance.
func ModuleCapabilitiesSingleton() *ModuleCapabilitiesServer { return moduleCapabilitiesSingleton }

// moduleCaller resolves the authenticated module service principal from the Work
// Context the caller forwards. The identity is taken from the signed capability
// rather than from request metadata, so a caller that reaches this listener
// cannot name a principal it was never issued.
func moduleCaller(ctx context.Context) (business.ModuleCaller, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return business.ModuleCaller{}, status.Error(codes.Unauthenticated, "module work context required")
	}
	values := md.Get(codefly.WorkContextHeaderName)
	if len(values) == 0 || values[0] == "" {
		return business.ModuleCaller{}, status.Error(codes.Unauthenticated, "module work context required")
	}
	return WorkContextSingleton().VerifyModuleWorkContext(values[0])
}

// MintModuleWorkContext issues that Work Context. Like MintModuleRegistration it
// takes none itself — this is where a module obtains its identity, so it
// authenticates with the identity secret its composition provisioned and the
// principal it acts as is derived from the prefix that secret is bound to.
func (s *ModuleCapabilitiesServer) MintModuleWorkContext(ctx context.Context, req *gen.ModuleMintWorkContextRequest) (*gen.ModuleMintWorkContextResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	authority, err := service.ModuleAuthorizeWorkContext(req.GetPrefix(), req.GetSecret())
	if err != nil {
		if errors.Is(err, business.ErrModuleRegistrationDenied) {
			return nil, status.Error(codes.PermissionDenied, "module work context denied")
		}
		return nil, err
	}
	// The declared tenant is checked against the database before anything is
	// signed. Everything upstream validates its *form* only, and the capability
	// seals the tenant, so an id that names no organization would mint cleanly
	// and then bind every call to a tenant that is not there — silently, since
	// the audit and event tables carry no foreign key to organizations. Fail
	// closed here instead: a module cannot act on a tenant that does not exist.
	if err := service.VerifyModuleTenant(ctx, authority); err != nil {
		if errors.Is(err, business.ErrModuleTenantUnknown) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, err
	}
	// The signer lives on the Work Context authority, which owns this cluster's
	// signing key; this RPC lives here so the gateway can broker it from the same
	// minimal-import proto as the registration exchange.
	token, signed, err := WorkContextSingleton().StartModuleTask(authority)
	if err != nil {
		if errors.Is(err, ErrWorkContextAuthorityUnconfigured) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, mapWorkContextError(err)
	}
	// The record is written only once the capability exists, and the capability is
	// withheld when the record cannot be committed.
	if err := service.RecordModuleWorkContextMint(ctx, req.GetPrefix(), authority); err != nil {
		return nil, err
	}
	return &gen.ModuleMintWorkContextResponse{
		Token:       token.Encoded(),
		ExpiresAt:   timestamppb.New(time.Unix(signed.GetExpiresAtUnix(), 0).UTC()),
		PrincipalId: authority.PrincipalID,
		Tenant:      authority.Tenant,
	}, nil
}

// MintModuleRegistration issues the credential a composed module presents to the
// gateway to federate its REST prefix. Unlike every other method here it takes
// no Work Context: a module registers at startup, before any user request
// exists, so the caller is authorized by its own registration secret rather than
// by a forwarded principal. The internal-credential gate on this listener still
// applies.
func (s *ModuleCapabilitiesServer) MintModuleRegistration(ctx context.Context, req *gen.ModuleMintRegistrationRequest) (*gen.ModuleMintRegistrationResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	token, expiresAt, err := service.ModuleMintRegistration(ctx, req.GetPrefix(), req.GetSecret())
	if err != nil {
		if errors.Is(err, business.ErrModuleRegistrationDenied) {
			return nil, status.Error(codes.PermissionDenied, "module registration denied")
		}
		return nil, err
	}
	return &gen.ModuleMintRegistrationResponse{
		Token:     token,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

// MintSolutionRegistration issues the credential a solution presents to the
// gateway and to the frontend to register, update, or delete its upstream and
// its Module-Federation remote. Like MintModuleRegistration it takes no Work
// Context and authorizes on the solution's own registration secret, declared
// separately from the module secrets.
func (s *ModuleCapabilitiesServer) MintSolutionRegistration(ctx context.Context, req *gen.SolutionMintRegistrationRequest) (*gen.SolutionMintRegistrationResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	token, expiresAt, err := service.SolutionMintRegistration(ctx, req.GetSolutionId(), req.GetSecret())
	if err != nil {
		if errors.Is(err, business.ErrSolutionRegistrationDenied) {
			return nil, status.Error(codes.PermissionDenied, "solution registration denied")
		}
		return nil, err
	}
	return &gen.SolutionMintRegistrationResponse{
		Token:     token,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

func (s *ModuleCapabilitiesServer) EnqueueJob(ctx context.Context, req *gen.ModuleEnqueueJobRequest) (*gen.ModuleEnqueueJobResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := service.ModuleEnqueueJob(ctx, caller, req.GetTenant(), &jobsv1.EnqueueJobRequest{Job: req.GetJob()})
	if err != nil {
		return nil, err
	}
	return &gen.ModuleEnqueueJobResponse{JobId: resp.GetJobId(), Disposition: resp.GetDisposition()}, nil
}

func (s *ModuleCapabilitiesServer) ClaimJobs(ctx context.Context, req *gen.ModuleClaimJobsRequest) (*gen.ModuleClaimJobsResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := service.ModuleClaimJobs(ctx, caller, &jobsv1.ClaimJobsRequest{
		Queue:         req.GetQueue(),
		WorkerId:      req.GetWorkerId(),
		Limit:         req.GetLimit(),
		LeaseDuration: req.GetLeaseDuration(),
	})
	if err != nil {
		return nil, err
	}
	return &gen.ModuleClaimJobsResponse{Jobs: resp.GetJobs()}, nil
}

func (s *ModuleCapabilitiesServer) HeartbeatJob(ctx context.Context, req *gen.ModuleHeartbeatJobRequest) (*gen.ModuleHeartbeatJobResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := service.ModuleHeartbeatJob(ctx, caller, &jobsv1.HeartbeatJobRequest{Lease: req.GetLease(), Extension: req.GetExtension()})
	if err != nil {
		return nil, err
	}
	return &gen.ModuleHeartbeatJobResponse{Lease: resp.GetLease()}, nil
}

func (s *ModuleCapabilitiesServer) AckJob(ctx context.Context, req *gen.ModuleAckJobRequest) (*emptypb.Empty, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	if err := service.ModuleAckJob(ctx, caller, &jobsv1.CompleteJobRequest{Lease: req.GetLease()}); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *ModuleCapabilitiesServer) NackJob(ctx context.Context, req *gen.ModuleNackJobRequest) (*emptypb.Empty, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	if err := service.ModuleNackJob(ctx, caller, req.GetLease(), req.GetFailure(), req.GetRetryable(), req.GetRetryAt()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *ModuleCapabilitiesServer) NotifyUser(ctx context.Context, req *gen.ModuleNotifyUserRequest) (*gen.ModuleNotifyUserResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	result, err := service.ModuleNotifyUser(ctx, caller, business.ModuleNotifyUserInput{
		Tenant:         req.GetTenant(),
		UserID:         req.GetUserId(),
		Title:          req.GetTitle(),
		Body:           req.GetBody(),
		Type:           req.GetType(),
		ActionURL:      req.GetActionUrl(),
		Category:       req.GetCategory(),
		IdempotencyKey: req.GetIdempotencyKey(),
	})
	if err != nil {
		return nil, err
	}
	return &gen.ModuleNotifyUserResponse{NotificationId: result.NotificationID, Delivered: result.Delivered}, nil
}

func (s *ModuleCapabilitiesServer) RequestApproval(ctx context.Context, req *gen.ModuleRequestApprovalRequest) (*gen.ModuleRequestApprovalResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	resume := req.GetResumeRef()
	id, err := service.ModuleRequestApproval(ctx, caller, business.ModuleRequestApprovalInput{
		Tenant:        req.GetTenant(),
		Resource:      req.GetResource(),
		Action:        req.GetAction(),
		Subject:       structToMap(req.GetSubject()),
		RequestedBy:   req.GetRequestedBy(),
		Quorum:        int(req.GetPolicy().GetQuorum()),
		ApproverSet:   req.GetPolicy().GetApproverSet(),
		AllowSelf:     req.GetPolicy().GetAllowSelf(),
		ResumeQueue:   resume.GetQueue(),
		ResumeTopic:   resume.GetTopic(),
		ResumePayload: structToMap(resume.GetPayload()),
		ExpiresAt:     timePtr(req.GetExpiresAt()),
		EscalateAt:    timePtr(req.GetEscalateAt()),
	})
	if err != nil {
		return nil, err
	}
	return &gen.ModuleRequestApprovalResponse{ApprovalId: id}, nil
}

func (s *ModuleCapabilitiesServer) GetApproval(ctx context.Context, req *gen.ModuleGetApprovalRequest) (*gen.ModuleApproval, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	approval, err := service.ModuleGetApproval(ctx, caller, req.GetTenant(), req.GetApprovalId())
	if err != nil {
		return nil, err
	}
	return moduleApprovalProto(approval), nil
}

func (s *ModuleCapabilitiesServer) CancelApproval(ctx context.Context, req *gen.ModuleCancelApprovalRequest) (*emptypb.Empty, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	if err := service.ModuleCancelApproval(ctx, caller, req.GetTenant(), req.GetApprovalId(), req.GetReason()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *ModuleCapabilitiesServer) EmitAuditEvent(ctx context.Context, req *gen.ModuleEmitAuditEventRequest) (*emptypb.Empty, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	if err := service.ModuleEmitAuditEvent(ctx, caller,
		req.GetTenant(), req.GetEventType(), req.GetActor(), req.GetSolution(), req.GetEntryId(), req.GetIdempotencyKey(), req.GetFields()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// FetchDatasourceBlob streams one datasource blob to the module. The blob is
// buffered whole in the business layer (it is already capped there), so this
// handler's only job is to slice it into bounded wire frames.
func (s *ModuleCapabilitiesServer) FetchDatasourceBlob(req *gen.FetchDatasourceBlobRequest, stream grpc.ServerStreamingServer[gen.FetchDatasourceBlobChunk]) error {
	return streamDatasourceBlob(stream.Context(), req, stream)
}

// datasourceBlobChunkBytes bounds each streamed frame. It sits well under the
// gRPC 4 MiB default message limit so a max-size blob streams in bounded frames
// rather than one oversized message the receiver would reject.
const datasourceBlobChunkBytes = 256 * 1024

// datasourceBlobSender is the send half both the gRPC and Connect server streams
// satisfy, so one implementation frames the blob for both transports.
type datasourceBlobSender interface {
	Send(*gen.FetchDatasourceBlobChunk) error
}

// streamDatasourceBlob resolves one datasource blob and writes it to stream in
// bounded frames. Every frame repeats the total size and content type so the
// receiver can size its buffer and label the content from the first frame; an
// empty blob still yields exactly one frame so that metadata always arrives.
func streamDatasourceBlob(ctx context.Context, req *gen.FetchDatasourceBlobRequest, stream datasourceBlobSender) error {
	if err := Validate(req); err != nil {
		return err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return err
	}
	content, contentType, err := service.ModuleFetchDatasourceBlob(ctx, caller, req.GetSourceId(), req.GetBlobSha())
	if err != nil {
		return err
	}
	return writeDatasourceBlobFrames(content, contentType, stream)
}

// writeDatasourceBlobFrames slices content into bounded wire frames, each
// repeating the total size and content type so the receiver can size its buffer
// and label the content from the first frame. An empty blob still yields exactly
// one frame so that metadata always arrives, and content whose length is an
// exact multiple of the frame size yields no trailing empty frame.
func writeDatasourceBlobFrames(content []byte, contentType string, stream datasourceBlobSender) error {
	total := int64(len(content))
	for {
		frame := content
		if len(frame) > datasourceBlobChunkBytes {
			frame = frame[:datasourceBlobChunkBytes]
		}
		if err := stream.Send(&gen.FetchDatasourceBlobChunk{
			Data:        frame,
			TotalSize:   total,
			ContentType: contentType,
		}); err != nil {
			return err
		}
		content = content[len(frame):]
		if len(content) == 0 {
			return nil
		}
	}
}

func (s *ModuleCapabilitiesServer) PlaceRecord(ctx context.Context, req *gen.ModulePlaceRecordRequest) (*gen.ModulePlaceRecordResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	nodeID, err := service.ModulePlaceRecord(ctx, caller, req.GetTenant(), req.GetScopePath(), req.GetKind(), req.GetLabel(), req.GetResourceType(), req.GetResourceId())
	if err != nil {
		return nil, err
	}
	return &gen.ModulePlaceRecordResponse{NodeId: nodeID}, nil
}

func (s *ModuleCapabilitiesServer) PublishEvent(ctx context.Context, req *gen.ModulePublishEventRequest) (*gen.ModulePublishEventResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	eventID, err := service.ModulePublishEvent(ctx, caller, req.GetTenant(), req.GetEnvelope())
	if err != nil {
		return nil, err
	}
	return &gen.ModulePublishEventResponse{EventId: eventID}, nil
}

func (s *ModuleCapabilitiesServer) Subscribe(ctx context.Context, req *gen.ModuleSubscribeRequest) (*gen.ModuleSubscribeResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	sub, err := service.ModuleSubscribe(ctx, caller, req.GetTypePattern(), req.GetQueue(), deliveryToString(req.GetDelivery()))
	if err != nil {
		return nil, err
	}
	return &gen.ModuleSubscribeResponse{Subscription: moduleSubscriptionProto(sub)}, nil
}

func (s *ModuleCapabilitiesServer) Unsubscribe(ctx context.Context, req *gen.ModuleUnsubscribeRequest) (*emptypb.Empty, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	if err := service.ModuleUnsubscribe(ctx, caller, req.GetSubscriptionId()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *ModuleCapabilitiesServer) ListSubscriptions(ctx context.Context, req *gen.ModuleListSubscriptionsRequest) (*gen.ModuleListSubscriptionsResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	subs, err := service.ModuleListSubscriptions(ctx, caller)
	if err != nil {
		return nil, err
	}
	out := make([]*gen.ModuleSubscription, 0, len(subs))
	for _, sub := range subs {
		out = append(out, moduleSubscriptionProto(sub))
	}
	return &gen.ModuleListSubscriptionsResponse{Subscriptions: out}, nil
}

func (s *ModuleCapabilitiesServer) ReplayEvents(ctx context.Context, req *gen.ModuleReplayEventsRequest) (*gen.ModuleReplayEventsResponse, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	caller, err := moduleCaller(ctx)
	if err != nil {
		return nil, err
	}
	var since time.Time
	if req.GetSince() != nil {
		since = req.GetSince().AsTime()
	}
	redelivered, err := service.ModuleReplayEvents(ctx, caller, req.GetTenant(), req.GetType(), since)
	if err != nil {
		return nil, err
	}
	return &gen.ModuleReplayEventsResponse{Redelivered: int32(redelivered)}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// deliveryToString narrows the wire enum to the business/DB spelling; an
// unspecified delivery is left empty so the Store applies its 'unordered'
// default.
func deliveryToString(d gen.EventDelivery) string {
	switch d {
	case gen.EventDelivery_EVENT_DELIVERY_ORDERED:
		return "ordered"
	case gen.EventDelivery_EVENT_DELIVERY_UNORDERED:
		return "unordered"
	default:
		return ""
	}
}

// deliveryToProto is the inverse of deliveryToString for outbound subscriptions.
func deliveryToProto(s string) gen.EventDelivery {
	switch s {
	case "ordered":
		return gen.EventDelivery_EVENT_DELIVERY_ORDERED
	case "unordered":
		return gen.EventDelivery_EVENT_DELIVERY_UNORDERED
	default:
		return gen.EventDelivery_EVENT_DELIVERY_UNSPECIFIED
	}
}

func moduleSubscriptionProto(sub *business.EventSubscription) *gen.ModuleSubscription {
	if sub == nil {
		return nil
	}
	return &gen.ModuleSubscription{
		Id:                    sub.ID,
		SubscriberPrincipalId: sub.SubscriberPrincipalID,
		TypePattern:           sub.TypePattern,
		Queue:                 sub.Queue,
		Delivery:              deliveryToProto(sub.Delivery),
		CreatedAt:             timestamppb.New(sub.CreatedAt),
	}
}

func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

func mapToStruct(m map[string]any) *structpb.Struct {
	if m == nil {
		return nil
	}
	s, err := structpb.NewStruct(m)
	if err != nil {
		return nil
	}
	return s
}

func timePtr(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	v := t.AsTime()
	return &v
}

func timeProto(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func moduleApprovalProto(a *business.ApprovalRequest) *gen.ModuleApproval {
	if a == nil {
		return nil
	}
	return &gen.ModuleApproval{
		Id:          a.ID,
		Tenant:      a.OrgID,
		Resource:    a.Resource,
		Action:      a.Action,
		Subject:     mapToStruct(a.Subject),
		RequestedBy: a.RequestedBy,
		Quorum:      uint32(a.Quorum),
		State:       string(a.State),
		ResumeRef: &gen.ModuleResumeRef{
			Queue:   a.ResumeRef.Queue,
			Topic:   a.ResumeRef.Topic,
			Payload: mapToStruct(a.ResumeRef.Payload),
		},
		ExpiresAt:  timeProto(a.ExpiresAt),
		EscalateAt: timeProto(a.EscalateAt),
		CreatedAt:  timestamppb.New(a.CreatedAt),
	}
}
