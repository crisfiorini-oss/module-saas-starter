package adapters

import (
	"context"

	gen "accounts/pkg/gen/saas/accounts/v1"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"
)

// moduleCapabilitiesConnectHandler serves the module-facing surface over the
// Connect protocol by delegating to the shared gRPC server, so both protocols
// enforce the same authority and see the same identity.
type moduleCapabilitiesConnectHandler struct {
	inner *ModuleCapabilitiesServer
}

func (h *moduleCapabilitiesConnectHandler) MintModuleRegistration(ctx context.Context, req *connect.Request[gen.ModuleMintRegistrationRequest]) (*connect.Response[gen.ModuleMintRegistrationResponse], error) {
	return unary(ctx, req, h.inner.MintModuleRegistration)
}

func (h *moduleCapabilitiesConnectHandler) MintModuleWorkContext(ctx context.Context, req *connect.Request[gen.ModuleMintWorkContextRequest]) (*connect.Response[gen.ModuleMintWorkContextResponse], error) {
	return unary(ctx, req, h.inner.MintModuleWorkContext)
}

func (h *moduleCapabilitiesConnectHandler) MintSolutionRegistration(ctx context.Context, req *connect.Request[gen.SolutionMintRegistrationRequest]) (*connect.Response[gen.SolutionMintRegistrationResponse], error) {
	return unary(ctx, req, h.inner.MintSolutionRegistration)
}

func (h *moduleCapabilitiesConnectHandler) EnqueueJob(ctx context.Context, req *connect.Request[gen.ModuleEnqueueJobRequest]) (*connect.Response[gen.ModuleEnqueueJobResponse], error) {
	return unary(ctx, req, h.inner.EnqueueJob)
}

func (h *moduleCapabilitiesConnectHandler) ClaimJobs(ctx context.Context, req *connect.Request[gen.ModuleClaimJobsRequest]) (*connect.Response[gen.ModuleClaimJobsResponse], error) {
	return unary(ctx, req, h.inner.ClaimJobs)
}

func (h *moduleCapabilitiesConnectHandler) HeartbeatJob(ctx context.Context, req *connect.Request[gen.ModuleHeartbeatJobRequest]) (*connect.Response[gen.ModuleHeartbeatJobResponse], error) {
	return unary(ctx, req, h.inner.HeartbeatJob)
}

func (h *moduleCapabilitiesConnectHandler) AckJob(ctx context.Context, req *connect.Request[gen.ModuleAckJobRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.AckJob)
}

func (h *moduleCapabilitiesConnectHandler) NackJob(ctx context.Context, req *connect.Request[gen.ModuleNackJobRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.NackJob)
}

func (h *moduleCapabilitiesConnectHandler) NotifyUser(ctx context.Context, req *connect.Request[gen.ModuleNotifyUserRequest]) (*connect.Response[gen.ModuleNotifyUserResponse], error) {
	return unary(ctx, req, h.inner.NotifyUser)
}

func (h *moduleCapabilitiesConnectHandler) RequestApproval(ctx context.Context, req *connect.Request[gen.ModuleRequestApprovalRequest]) (*connect.Response[gen.ModuleRequestApprovalResponse], error) {
	return unary(ctx, req, h.inner.RequestApproval)
}

func (h *moduleCapabilitiesConnectHandler) GetApproval(ctx context.Context, req *connect.Request[gen.ModuleGetApprovalRequest]) (*connect.Response[gen.ModuleApproval], error) {
	return unary(ctx, req, h.inner.GetApproval)
}

func (h *moduleCapabilitiesConnectHandler) CancelApproval(ctx context.Context, req *connect.Request[gen.ModuleCancelApprovalRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.CancelApproval)
}

func (h *moduleCapabilitiesConnectHandler) EmitAuditEvent(ctx context.Context, req *connect.Request[gen.ModuleEmitAuditEventRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.EmitAuditEvent)
}

func (h *moduleCapabilitiesConnectHandler) FetchDatasourceBlob(ctx context.Context, req *connect.Request[gen.FetchDatasourceBlobRequest], stream *connect.ServerStream[gen.FetchDatasourceBlobChunk]) error {
	return streamDatasourceBlob(ctx, req.Msg, stream)
}

func (h *moduleCapabilitiesConnectHandler) PlaceRecord(ctx context.Context, req *connect.Request[gen.ModulePlaceRecordRequest]) (*connect.Response[gen.ModulePlaceRecordResponse], error) {
	return unary(ctx, req, h.inner.PlaceRecord)
}

func (h *moduleCapabilitiesConnectHandler) PublishEvent(ctx context.Context, req *connect.Request[gen.ModulePublishEventRequest]) (*connect.Response[gen.ModulePublishEventResponse], error) {
	return unary(ctx, req, h.inner.PublishEvent)
}

func (h *moduleCapabilitiesConnectHandler) Subscribe(ctx context.Context, req *connect.Request[gen.ModuleSubscribeRequest]) (*connect.Response[gen.ModuleSubscribeResponse], error) {
	return unary(ctx, req, h.inner.Subscribe)
}

func (h *moduleCapabilitiesConnectHandler) Unsubscribe(ctx context.Context, req *connect.Request[gen.ModuleUnsubscribeRequest]) (*connect.Response[emptypb.Empty], error) {
	return unary(ctx, req, h.inner.Unsubscribe)
}

func (h *moduleCapabilitiesConnectHandler) ListSubscriptions(ctx context.Context, req *connect.Request[gen.ModuleListSubscriptionsRequest]) (*connect.Response[gen.ModuleListSubscriptionsResponse], error) {
	return unary(ctx, req, h.inner.ListSubscriptions)
}

func (h *moduleCapabilitiesConnectHandler) ReplayEvents(ctx context.Context, req *connect.Request[gen.ModuleReplayEventsRequest]) (*connect.Response[gen.ModuleReplayEventsResponse], error) {
	return unary(ctx, req, h.inner.ReplayEvents)
}
