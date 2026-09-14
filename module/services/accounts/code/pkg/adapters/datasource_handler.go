package adapters

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"accounts/pkg/business"
	gen "accounts/pkg/gen/saas/accounts/v1"
	"accounts/pkg/jobs"
)

// datasourceConnectHandler exposes the tenant-facing datasource management
// surface. Every RPC is org-gated at the handler layer (the business methods do
// not authz themselves): the mutating RPCs require org admin, the reads require
// org membership.
type datasourceConnectHandler struct{ svc *business.Service }

func (h *datasourceConnectHandler) AddGitHubSource(
	ctx context.Context,
	req *connect.Request[gen.AddGitHubSourceRequest],
) (*connect.Response[gen.AddGitHubSourceResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	actorID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgAdmin(ctx, actorID, req.Msg.OrgId); err != nil {
		return nil, translateGRPCError(err)
	}
	source, err := h.svc.AddGitHubSource(ctx, actorID, business.AddGitHubSourceInput{
		OrgID:           req.Msg.OrgId,
		Repo:            req.Msg.Repo,
		Paths:           req.Msg.Paths,
		Branch:          req.Msg.Branch,
		BoundaryNodeID:  req.Msg.GetBoundaryNodeId(),
		CollectionLabel: req.Msg.GetCollectionLabel(),
		AccessToken:     req.Msg.AccessToken,
		WebhookSecret:   req.Msg.WebhookSecret,
	})
	if err != nil {
		return nil, translateGRPCError(err)
	}
	return connect.NewResponse(&gen.AddGitHubSourceResponse{Datasource: datasourceSourceToProto(source)}), nil
}

func (h *datasourceConnectHandler) AddSource(
	ctx context.Context,
	req *connect.Request[gen.AddSourceRequest],
) (*connect.Response[gen.AddSourceResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	actorID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgAdmin(ctx, actorID, req.Msg.OrgId); err != nil {
		return nil, translateGRPCError(err)
	}
	input := business.AddSourceInput{
		OrgID:              req.Msg.OrgId,
		Provider:           datasourceProviderFromProto(req.Msg.Provider),
		BoundaryNodeID:     req.Msg.GetBoundaryNodeId(),
		CollectionLabel:    req.Msg.GetCollectionLabel(),
		Credential:         req.Msg.Credential,
		WebhookSecret:      req.Msg.WebhookSecret,
		OAuth2ClientSecret: req.Msg.Oauth2ClientSecret,
	}
	if gh := req.Msg.GetGithub(); gh != nil {
		input.Repo = gh.Repo
		input.Paths = gh.Paths
		input.Branch = gh.Branch
	}
	if api := req.Msg.GetApi(); api != nil {
		input.API = &business.APIDatasourceConfig{
			BaseURL:              api.BaseUrl,
			ResourcePath:         api.ResourcePath,
			CredentialKind:       apiCredentialKindFromProto(api.CredentialKind),
			CredentialHeader:     api.CredentialHeader,
			CredentialQueryParam: api.CredentialQueryParam,
		}
		if oauth := api.GetOauth2(); oauth != nil {
			input.API.OAuth2 = &business.APIOAuth2Config{
				TokenURL: oauth.TokenUrl,
				ClientID: oauth.ClientId,
				Scopes:   oauth.Scopes,
			}
		}
	}
	if c := req.Msg.GetCrawler(); c != nil {
		input.Crawler = &business.CrawlerDatasourceConfig{
			SitemapURL: c.SitemapUrl,
			MaxPages:   int(c.MaxPages),
		}
	}
	if up := req.Msg.GetUpload(); up != nil {
		input.Upload = &business.UploadDatasourceConfig{
			Endpoint:    up.Endpoint,
			Region:      up.Region,
			Bucket:      up.Bucket,
			Prefix:      up.Prefix,
			AccessKeyID: up.AccessKeyId,
			MaxObjects:  int(up.MaxObjects),
		}
	}
	source, err := h.svc.AddSource(ctx, actorID, input)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	return connect.NewResponse(&gen.AddSourceResponse{Datasource: datasourceSourceToProto(source)}), nil
}

func (h *datasourceConnectHandler) GetDatasourceCatalog(
	ctx context.Context,
	req *connect.Request[gen.GetDatasourceCatalogRequest],
) (*connect.Response[gen.GetDatasourceCatalogResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	if _, err := callerID(ctx); err != nil {
		return nil, err
	}
	return connect.NewResponse(datasourceCatalog()), nil
}

func (h *datasourceConnectHandler) ListSources(
	ctx context.Context,
	req *connect.Request[gen.ListSourcesRequest],
) (*connect.Response[gen.ListSourcesResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	actorID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgMember(ctx, actorID, req.Msg.OrgId); err != nil {
		return nil, translateGRPCError(err)
	}
	sources, err := h.svc.ListDatasourceSources(ctx, req.Msg.OrgId)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	out := make([]*gen.Datasource, 0, len(sources))
	for _, source := range sources {
		out = append(out, datasourceSourceToProto(source))
	}
	return connect.NewResponse(&gen.ListSourcesResponse{Datasources: out}), nil
}

func (h *datasourceConnectHandler) GetSource(
	ctx context.Context,
	req *connect.Request[gen.GetSourceRequest],
) (*connect.Response[gen.GetSourceResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	actorID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgMember(ctx, actorID, req.Msg.OrgId); err != nil {
		return nil, translateGRPCError(err)
	}
	source, err := h.svc.GetDatasourceSource(ctx, req.Msg.OrgId, req.Msg.Id)
	if err != nil {
		if errors.Is(err, business.ErrDatasourceSourceNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, translateGRPCError(err)
	}
	return connect.NewResponse(&gen.GetSourceResponse{Datasource: datasourceSourceToProto(source)}), nil
}

func (h *datasourceConnectHandler) SyncSource(
	ctx context.Context,
	req *connect.Request[gen.SyncSourceRequest],
) (*connect.Response[gen.SyncSourceResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	actorID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgAdmin(ctx, actorID, req.Msg.OrgId); err != nil {
		return nil, translateGRPCError(err)
	}
	jobID, err := h.svc.SyncDatasourceSource(ctx, actorID, req.Msg.OrgId, req.Msg.Id, req.Msg.AccessToken)
	if err != nil {
		var failure *jobs.ProcessingError
		if errors.As(err, &failure) {
			code := connect.CodeFailedPrecondition
			if failure.Retryable {
				code = connect.CodeUnavailable
			}
			return nil, connect.NewError(code, errors.New(failure.Failure.Message))
		}
		if errors.Is(err, business.ErrDatasourceSourceNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, translateGRPCError(err)
	}
	return connect.NewResponse(&gen.SyncSourceResponse{JobId: jobID}), nil
}

func (h *datasourceConnectHandler) DeleteSource(
	ctx context.Context,
	req *connect.Request[gen.DeleteSourceRequest],
) (*connect.Response[gen.DeleteSourceResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	actorID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgAdmin(ctx, actorID, req.Msg.OrgId); err != nil {
		return nil, translateGRPCError(err)
	}
	if err := h.svc.DeleteDatasourceSource(ctx, actorID, req.Msg.OrgId, req.Msg.Id); err != nil {
		return nil, translateGRPCError(err)
	}
	return connect.NewResponse(&gen.DeleteSourceResponse{}), nil
}

// datasourceSourceToProto projects the domain Source onto its non-secret proto
// representation. Credential and webhook-secret envelopes are deliberately not
// mapped — the wire type has no field for them.
func (h *datasourceConnectHandler) BeginGitHubAppSetup(
	ctx context.Context,
	req *connect.Request[gen.BeginGitHubAppSetupRequest],
) (*connect.Response[gen.BeginGitHubAppSetupResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	actorID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgAdmin(ctx, actorID, req.Msg.OrgId); err != nil {
		return nil, translateGRPCError(err)
	}
	handle, err := h.svc.BeginGitHubAppSetup(ctx, actorID, req.Msg.OrgId)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	return connect.NewResponse(&gen.BeginGitHubAppSetupResponse{
		InstallUrl: handle.InstallURL,
		State:      handle.State,
		ExpiresAt:  timestamppb.New(handle.ExpiresAt),
	}), nil
}

func (h *datasourceConnectHandler) CompleteGitHubAppSetup(
	ctx context.Context,
	req *connect.Request[gen.CompleteGitHubAppSetupRequest],
) (*connect.Response[gen.CompleteGitHubAppSetupResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	actorID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgAdmin(ctx, actorID, req.Msg.OrgId); err != nil {
		return nil, translateGRPCError(err)
	}
	installation, err := h.svc.CompleteGitHubAppSetup(ctx, actorID, req.Msg.OrgId, req.Msg.State, req.Msg.InstallationId)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	repositories := make([]*gen.GitHubAppRepository, 0, len(installation.Repositories))
	for _, repository := range installation.Repositories {
		repositories = append(repositories, &gen.GitHubAppRepository{
			Repo:             repository.Repo,
			DefaultBranch:    repository.DefaultBranch,
			AlreadyConnected: repository.AlreadyConnected,
		})
	}
	return connect.NewResponse(&gen.CompleteGitHubAppSetupResponse{
		InstallationId: installation.InstallationID,
		Repositories:   repositories,
	}), nil
}

func (h *datasourceConnectHandler) MigrateGitHubSourceToApp(
	ctx context.Context,
	req *connect.Request[gen.MigrateGitHubSourceToAppRequest],
) (*connect.Response[gen.MigrateGitHubSourceToAppResponse], error) {
	ctx = connectCtx(ctx, req.Header())
	actorID, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireOrgAdmin(ctx, actorID, req.Msg.OrgId); err != nil {
		return nil, translateGRPCError(err)
	}
	source, err := h.svc.MigrateGitHubSourceToApp(ctx, actorID, req.Msg.OrgId, req.Msg.Id)
	if err != nil {
		return nil, translateGRPCError(err)
	}
	return connect.NewResponse(&gen.MigrateGitHubSourceToAppResponse{
		Datasource: datasourceSourceToProto(source),
	}), nil
}

func datasourceSourceToProto(source *business.DatasourceSource) *gen.Datasource {
	out := &gen.Datasource{
		Id:                 source.ID,
		OrgId:              source.OrgID,
		Provider:           datasourceProviderToProto(source.Provider),
		BoundaryNodeId:     source.BoundaryNodeID,
		Status:             datasourceStatusToProto(source.Status),
		StatusReason:       source.StatusReason,
		WebhookConfigured:  source.WebhookConfigured(),
		CreatedAt:          timestamppb.New(source.CreatedAt),
		UpdatedAt:          timestamppb.New(source.UpdatedAt),
		LastIngestedCommit: source.LastIngestedCommit,
	}
	if source.Provider == business.DatasourceProviderGitHub {
		out.Github = &gen.GitHubDatasourceConfig{
			Repo:   source.Repo,
			Paths:  source.Paths,
			Branch: source.Branch,
		}
	}
	if source.API != nil {
		out.Api = &gen.ApiDatasourceConfig{
			BaseUrl:              source.API.BaseURL,
			ResourcePath:         source.API.ResourcePath,
			CredentialKind:       apiCredentialKindToProto(source.API.CredentialKind),
			CredentialHeader:     source.API.CredentialHeader,
			CredentialQueryParam: source.API.CredentialQueryParam,
		}
		if source.API.OAuth2 != nil {
			out.Api.Oauth2 = &gen.ApiOAuth2Config{
				TokenUrl: source.API.OAuth2.TokenURL,
				ClientId: source.API.OAuth2.ClientID,
				Scopes:   source.API.OAuth2.Scopes,
			}
		}
	}
	if source.Crawler != nil {
		out.Crawler = &gen.CrawlerDatasourceConfig{
			SitemapUrl: source.Crawler.SitemapURL,
			MaxPages:   uint32(source.Crawler.MaxPages),
		}
	}
	if source.Upload != nil {
		out.Upload = &gen.UploadDatasourceConfig{
			Endpoint:    source.Upload.Endpoint,
			Region:      source.Upload.Region,
			Bucket:      source.Upload.Bucket,
			Prefix:      source.Upload.Prefix,
			AccessKeyId: source.Upload.AccessKeyID,
			MaxObjects:  uint32(source.Upload.MaxObjects),
		}
	}
	if source.LastSyncedAt != nil {
		out.LastSyncedAt = timestamppb.New(*source.LastSyncedAt)
	}
	if source.LastIngestedAt != nil {
		out.LastIngestedAt = timestamppb.New(*source.LastIngestedAt)
	}
	return out
}

func datasourceProviderToProto(provider string) gen.DatasourceProvider {
	switch provider {
	case business.DatasourceProviderGitHub:
		return gen.DatasourceProvider_DATASOURCE_PROVIDER_GITHUB
	case business.DatasourceProviderAPI:
		return gen.DatasourceProvider_DATASOURCE_PROVIDER_API
	case business.DatasourceProviderCrawler:
		return gen.DatasourceProvider_DATASOURCE_PROVIDER_CRAWLER
	case business.DatasourceProviderUpload:
		return gen.DatasourceProvider_DATASOURCE_PROVIDER_UPLOAD
	default:
		return gen.DatasourceProvider_DATASOURCE_PROVIDER_UNSPECIFIED
	}
}

func datasourceProviderFromProto(provider gen.DatasourceProvider) string {
	switch provider {
	case gen.DatasourceProvider_DATASOURCE_PROVIDER_GITHUB:
		return business.DatasourceProviderGitHub
	case gen.DatasourceProvider_DATASOURCE_PROVIDER_API:
		return business.DatasourceProviderAPI
	case gen.DatasourceProvider_DATASOURCE_PROVIDER_CRAWLER:
		return business.DatasourceProviderCrawler
	case gen.DatasourceProvider_DATASOURCE_PROVIDER_UPLOAD:
		return business.DatasourceProviderUpload
	default:
		return ""
	}
}

func apiCredentialKindFromProto(kind gen.ApiCredentialKind) string {
	switch kind {
	case gen.ApiCredentialKind_API_CREDENTIAL_KIND_BEARER:
		return business.APICredentialKindBearer
	case gen.ApiCredentialKind_API_CREDENTIAL_KIND_BASIC:
		return business.APICredentialKindBasic
	case gen.ApiCredentialKind_API_CREDENTIAL_KIND_HEADER:
		return business.APICredentialKindHeader
	case gen.ApiCredentialKind_API_CREDENTIAL_KIND_QUERY:
		return business.APICredentialKindQuery
	case gen.ApiCredentialKind_API_CREDENTIAL_KIND_OAUTH2:
		return business.APICredentialKindOAuth2
	default:
		return ""
	}
}

func apiCredentialKindToProto(kind string) gen.ApiCredentialKind {
	switch kind {
	case business.APICredentialKindBearer:
		return gen.ApiCredentialKind_API_CREDENTIAL_KIND_BEARER
	case business.APICredentialKindBasic:
		return gen.ApiCredentialKind_API_CREDENTIAL_KIND_BASIC
	case business.APICredentialKindHeader:
		return gen.ApiCredentialKind_API_CREDENTIAL_KIND_HEADER
	case business.APICredentialKindQuery:
		return gen.ApiCredentialKind_API_CREDENTIAL_KIND_QUERY
	case business.APICredentialKindOAuth2:
		return gen.ApiCredentialKind_API_CREDENTIAL_KIND_OAUTH2
	default:
		return gen.ApiCredentialKind_API_CREDENTIAL_KIND_UNSPECIFIED
	}
}

// datasourceCatalog is the static provider registry the UI enumerates to render
// the "connect a source" surface. Config field keys match the provider config
// message field names.
func datasourceCatalog() *gen.GetDatasourceCatalogResponse {
	return &gen.GetDatasourceCatalogResponse{
		Providers: []*gen.DatasourceProviderDescriptor{
			{
				Provider:    gen.DatasourceProvider_DATASOURCE_PROVIDER_GITHUB,
				DisplayName: "GitHub",
				Description: "A GitHub repository, pulled on sync and kept fresh through push webhooks.",
				ConfigFields: []*gen.DatasourceConfigField{
					{Key: "repo", DisplayName: "Repository", Help: "owner/name, e.g. codefly-dev/module-saas-starter", Required: true},
					{Key: "paths", DisplayName: "Paths", Help: "Path prefixes to ingest; empty means the whole repository.", Required: false},
					{Key: "branch", DisplayName: "Branch", Help: "Git ref to pull; empty resolves to the default branch.", Required: false},
				},
				SupportsWebhook: true,
			},
			{
				Provider:    gen.DatasourceProvider_DATASOURCE_PROVIDER_API,
				DisplayName: "HTTP API",
				Description: "An HTTP API with a stored credential; a configured resource is fetched on sync.",
				ConfigFields: []*gen.DatasourceConfigField{
					{Key: "base_url", DisplayName: "Base URL", Help: "Absolute http(s) URL, e.g. https://api.example.com", Required: true},
					{Key: "resource_path", DisplayName: "Resource path", Help: "Path fetched on sync, relative to the base URL.", Required: false},
					{Key: "credential_kind", DisplayName: "Credential kind", Help: "How the credential is sent: bearer, basic, header, query, or oauth2.", Required: true},
					{Key: "credential_header", DisplayName: "Credential header", Help: "Header name, when the credential kind is header.", Required: false},
					{Key: "credential_query_param", DisplayName: "Credential query parameter", Help: "Query parameter name, when the credential kind is query.", Required: false},
					{Key: "oauth2", DisplayName: "OAuth 2.0 config", Help: "Token URL and client id, when the credential kind is oauth2; the refresh token is the credential.", Required: false},
				},
				SupportsWebhook: false,
				SupportedCredentialKinds: []gen.ApiCredentialKind{
					gen.ApiCredentialKind_API_CREDENTIAL_KIND_BEARER,
					gen.ApiCredentialKind_API_CREDENTIAL_KIND_BASIC,
					gen.ApiCredentialKind_API_CREDENTIAL_KIND_HEADER,
					gen.ApiCredentialKind_API_CREDENTIAL_KIND_QUERY,
					gen.ApiCredentialKind_API_CREDENTIAL_KIND_OAUTH2,
				},
			},
			{
				Provider:    gen.DatasourceProvider_DATASOURCE_PROVIDER_CRAWLER,
				DisplayName: "Web crawler",
				Description: "A documentation website, ingested from its sitemap.xml on sync. Needs no credential.",
				ConfigFields: []*gen.DatasourceConfigField{
					{Key: "sitemap_url", DisplayName: "Sitemap URL", Help: "Absolute http(s) URL of the site's sitemap.xml.", Required: true},
					{Key: "max_pages", DisplayName: "Max pages", Help: "Upper bound on pages fetched per sync; empty applies the default.", Required: false},
				},
				SupportsWebhook: false,
			},
			{
				Provider:    gen.DatasourceProvider_DATASOURCE_PROVIDER_UPLOAD,
				DisplayName: "Object storage",
				Description: "An S3-compatible bucket; objects under a prefix are pulled on sync. The credential is the secret access key.",
				ConfigFields: []*gen.DatasourceConfigField{
					{Key: "endpoint", DisplayName: "Endpoint", Help: "Absolute http(s) endpoint, e.g. https://s3.us-east-1.amazonaws.com", Required: true},
					{Key: "region", DisplayName: "Region", Help: "Signing region, e.g. us-east-1.", Required: true},
					{Key: "bucket", DisplayName: "Bucket", Help: "Bucket to pull from.", Required: true},
					{Key: "prefix", DisplayName: "Prefix", Help: "Key prefix to pull under; empty pulls the whole bucket.", Required: false},
					{Key: "access_key_id", DisplayName: "Access key id", Help: "AWS-style access key id; the secret access key is the credential.", Required: true},
					{Key: "max_objects", DisplayName: "Max objects", Help: "Upper bound on objects fetched per sync; empty applies the default.", Required: false},
				},
				SupportsWebhook: false,
			},
		},
	}
}

func datasourceStatusToProto(status string) gen.DatasourceStatus {
	switch status {
	case business.DatasourceStatusActive:
		return gen.DatasourceStatus_DATASOURCE_STATUS_ACTIVE
	case business.DatasourceStatusPaused:
		return gen.DatasourceStatus_DATASOURCE_STATUS_PAUSED
	case business.DatasourceStatusDegraded:
		return gen.DatasourceStatus_DATASOURCE_STATUS_DEGRADED
	default:
		return gen.DatasourceStatus_DATASOURCE_STATUS_UNSPECIFIED
	}
}
