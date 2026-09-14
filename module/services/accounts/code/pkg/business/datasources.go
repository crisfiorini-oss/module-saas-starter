package business

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"accounts/pkg/datasource/apisource"
	"accounts/pkg/datasource/crawler"
	"accounts/pkg/datasource/github"
	"accounts/pkg/datasource/objectstore"
	gen "accounts/pkg/gen/saas/accounts/v1"
	jobsv1 "accounts/pkg/gen/saas/jobs/v1"
	"accounts/pkg/jobs"

	"github.com/codefly-dev/core/wool"
)

// Datasource providers and lifecycle statuses. The provider string is recorded
// on every Source row and selects the connector.
const (
	DatasourceProviderGitHub  = "github"
	DatasourceProviderAPI     = "api"
	DatasourceProviderCrawler = "crawler"
	DatasourceProviderUpload  = "upload"

	DatasourceStatusActive = "active"
	DatasourceStatusPaused = "paused"
	// DatasourceStatusDegraded parks a source the change-set compiler cannot make
	// progress on for a structural reason an operator must resolve (an oversized
	// snapshot manifest). A degraded source is skipped by the reconcile sweep
	// until an operator resets it to active; StatusReason records why.
	DatasourceStatusDegraded = "degraded"
)

// DatasourceDegradeReason is the closed set of explanations that may be stored
// in a source's status_reason, which every organization member can read through
// ListSources and GetSource. The wire contract promises that field carries no
// credential material, and nothing about a plain string parameter would keep
// that promise: the idiomatic way to explain a failed provider call is
// fmt.Sprintf("%v", err), and a provider error wraps request URLs, response
// bodies and installation identifiers verbatim. So the reason is a distinct type
// whose body is unexported and which has no constructor from a string or an
// error. Outside this package a caller cannot build one at all; inside it, the
// named constructors below are the only way, which makes adding an unsafe reason
// a visible edit here rather than an ordinary-looking call site elsewhere.
type DatasourceDegradeReason struct{ text string }

// String renders the reason for storage and for the wire projection.
func (r DatasourceDegradeReason) String() string { return r.text }

// SnapshotTooLargeDegradeReason explains a source parked because its full-tree
// manifest overran the ingest payload cap. Both operands are sizes this process
// measured, never provider-supplied text.
func SnapshotTooLargeDegradeReason(size, limit int) DatasourceDegradeReason {
	return DatasourceDegradeReason{
		text: fmt.Sprintf("snapshot manifest is %d bytes, over the %d-byte ingest limit", size, limit),
	}
}

// API credential kinds mirror saas.accounts.v1.ApiCredentialKind; they select
// how the stored credential is presented on the generic connector's requests.
// OAuth2 is resolved in this layer (refresh + rotation) and handed to the
// connector as a bearer credential, so it has no apisource presentation kind.
const (
	APICredentialKindBearer = apisource.CredentialKindBearer
	APICredentialKindBasic  = apisource.CredentialKindBasic
	APICredentialKindHeader = apisource.CredentialKindHeader
	APICredentialKindQuery  = apisource.CredentialKindQuery
	APICredentialKindOAuth2 = "oauth2"
)

// defaultDatasourceReconcileInterval is the period at which a GitHub source is
// snapshot-reconciled as a safety net for lost webhooks and for local
// development without a public tunnel (issue #487 §6).
const defaultDatasourceReconcileInterval = 30 * time.Minute

// oauth2ExpiryLeeway refreshes a stored access token slightly before it expires
// so a token that lapses mid-fetch does not fail the sync.
const oauth2ExpiryLeeway = 60 * time.Second

// oauth2DefaultTTL bounds how long an access token is trusted when the token
// endpoint omits expires_in. Without it a missing expiry would force a refresh
// on every sync (and every retry), needlessly rotating single-use refresh tokens
// and hammering the endpoint during a retry storm.
const oauth2DefaultTTL = 5 * time.Minute

const (
	datasourceConnectorSecretPurposePrefix = "github-connector:"
	datasourceWebhookSecretPurposePrefix   = "github-webhook:"
)

// The ingest seam documents consumes. Sync and the inbound webhook receiver
// (pkg/datasource, issue #275) both land on queue "datasource"; the topic and
// attributes distinguish a full-sync file delivery from a raw push delivery so a
// single leased consumer can route them. The payload is raw bytes with routing
// in attributes — never an accounts-owned proto — because the consumer is a
// different service (documents) and the seam stays decoupled from any accounts
// type.
const (
	datasourceIngestQueue         = "datasource"
	datasourceSyncTopic           = "datasource.github.sync"
	datasourceSyncSource          = "github.sync"
	datasourceIngestSchemaVersion = 1
	datasourceIngestMaxAttempts   = 24
	datasourceIngestContentType   = "application/octet-stream"

	// datasourceRequestContentType types the body every datasource *request* job
	// carries (see datasourceRequestBody).
	datasourceRequestContentType = "application/json"

	// The internal sync-request queue. SyncSource enqueues one request here and
	// returns; a leased worker performs the actual repo pull off-request, so a
	// large repo cannot block or time out the RPC and gets the jobs framework's
	// retry/backoff (long enough to outlast a GitHub rate-limit window).
	DatasourceSyncRequestQueue         = "datasource.sync"
	datasourceSyncRequestTopic         = "datasource.github.sync.request"
	datasourceSyncRequestSource        = "github.sync.request"
	datasourceSyncRequestSchemaVersion = 1
	datasourceSyncRequestMaxAttempts   = 12

	// A file larger than the generic inbox's ~1 MiB payload cap is skipped by a
	// full sync; the documents ingest step re-fetches such refs by SHA through
	// the connector's API client rather than inlining an oversized payload.
	maxIngestPayload = 960 * 1024

	attrSourceID   = "datasource.source_id"
	attrOrgID      = "datasource.org_id"
	attrBoundaryID = "datasource.boundary_id"
	attrRepo       = "github.repo"
	attrPath       = "github.path"
	attrRef        = "github.ref"
	attrSHA        = "github.sha"
	attrCommit     = "github.commit"
	attrChangeType = "github.change_type"

	// The generic API connector lands on the same shared "datasource" queue; a
	// distinct topic/source lets the documents consumer route an API pull apart
	// from a GitHub one. The fetched body travels as the payload; the resource
	// URL and a content hash travel in attributes.
	datasourceAPISyncTopic  = "datasource.api.sync"
	datasourceAPISyncSource = "api.sync"

	attrAPIURL        = "api.url"
	attrAPIContentSHA = "api.content_sha"

	// The crawler and object-storage connectors land on the same shared
	// "datasource" queue with their own topic/source so the documents consumer
	// routes each apart from a GitHub or API pull. The fetched bytes travel as the
	// payload; the resource identity and a content hash travel in attributes.
	datasourceCrawlerSyncTopic  = "datasource.crawler.sync"
	datasourceCrawlerSyncSource = "crawler.sync"
	datasourceUploadSyncTopic   = "datasource.upload.sync"
	datasourceUploadSyncSource  = "upload.sync"

	attrCrawlerURL        = "crawler.url"
	attrCrawlerContentSHA = "crawler.content_sha"
	attrUploadBucket      = "upload.bucket"
	attrUploadKey         = "upload.key"
	attrUploadETag        = "upload.etag"

	changeTypeAdded = "added"
)

// ErrDatasourceSourceNotFound reports that no Source (or no webhook-configured
// Source) matches an id. It mirrors the receiver's not-found sentinel so an
// unknown source and an unconfigured one are indistinguishable to a caller.
var ErrDatasourceSourceNotFound = errors.New("datasource: source not found")

// ErrOAuth2ReauthRequired reports that an OAuth 2.0 source's refresh token was
// permanently rejected by the token endpoint: the stored grant can never
// succeed again and the source must be reconnected. It is terminal, so the sync
// worker stops retrying rather than replaying the dead token indefinitely.
var ErrOAuth2ReauthRequired = errors.New("datasource: oauth2 source requires reconnection")

// DatasourceConnectorSecretPurpose binds an access-token envelope to one Source
// so ciphertext cannot be replayed across rows. The row id is the binding
// because a repo may be connected more than once.
func DatasourceConnectorSecretPurpose(sourceID string) string {
	return datasourceConnectorSecretPurposePrefix + sourceID
}

// DatasourceWebhookSecretPurpose binds a webhook-signing-secret envelope to one
// Source, same rationale as the access-token purpose.
func DatasourceWebhookSecretPurpose(sourceID string) string {
	return datasourceWebhookSecretPurposePrefix + sourceID
}

// APIDatasourceConfig is the non-secret configuration of a generic
// API-with-credentials Source. It is persisted as the Source row's config JSONB;
// the credential itself lives only as a SecretCipher envelope in
// CredentialSecretRef.
type APIDatasourceConfig struct {
	BaseURL              string           `json:"base_url"`
	ResourcePath         string           `json:"resource_path"`
	CredentialKind       string           `json:"credential_kind"`
	CredentialHeader     string           `json:"credential_header,omitempty"`
	CredentialQueryParam string           `json:"credential_query_param,omitempty"`
	OAuth2               *APIOAuth2Config `json:"oauth2,omitempty"`
}

// APIOAuth2Config is the non-secret OAuth 2.0 configuration of an API Source.
// The refresh token and client secret are never held here; they live only in
// the SecretCipher credential envelope (oauthStoredCredential).
type APIOAuth2Config struct {
	TokenURL string   `json:"token_url"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes,omitempty"`
}

// oauthStoredCredential is the JSON shape encrypted into the credential envelope
// for an OAuth 2.0 API Source. The refresh token (and client secret, for a
// confidential client) come from the connect call; the access token and its
// expiry are filled in and rotated in place on each refresh.
type oauthStoredCredential struct {
	RefreshToken string `json:"refresh_token"`
	ClientSecret string `json:"client_secret,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
}

// CrawlerDatasourceConfig is the non-secret configuration of a web/sitemap
// crawler Source. It is persisted as the Source row's config JSONB. The crawler
// needs no credential.
type CrawlerDatasourceConfig struct {
	SitemapURL string `json:"sitemap_url"`
	MaxPages   int    `json:"max_pages,omitempty"`
}

// UploadDatasourceConfig is the non-secret configuration of an S3-compatible
// object-storage Source. It is persisted as the Source row's config JSONB; the
// secret access key lives only as a SecretCipher envelope in CredentialSecretRef.
type UploadDatasourceConfig struct {
	Endpoint    string `json:"endpoint"`
	Region      string `json:"region"`
	Bucket      string `json:"bucket"`
	Prefix      string `json:"prefix,omitempty"`
	AccessKeyID string `json:"access_key_id"`
	MaxObjects  int    `json:"max_objects,omitempty"`
}

// DatasourceSource is one connected external datasource. CredentialSecretRef and
// WebhookSecretRef hold SecretCipher envelopes (references into the secret
// provider), never plaintext. Repo/Paths/Branch are set for the GitHub provider;
// API/Crawler/Upload is set for the matching generic provider.
type DatasourceSource struct {
	ID                  string
	OrgID               string
	Provider            string
	Repo                string
	Paths               []string
	Branch              string
	API                 *APIDatasourceConfig
	Crawler             *CrawlerDatasourceConfig
	Upload              *UploadDatasourceConfig
	BoundaryNodeID      string
	CredentialSecretRef string
	WebhookSecretRef    string
	// GitHubInstallationID is the App installation this source's credential
	// envelope binds it to, denormalized so an App-level delivery can resolve the
	// sources it affects (the envelope is encrypted and cannot be selected on).
	// It is a routing index only — the envelope stays the sole authority for
	// minting a token. Empty for a PAT-backed source.
	GitHubInstallationID string
	Status               string
	// StatusReason explains a non-active status (the degrade reason for a source
	// the compiler parked); empty for an active source.
	StatusReason string
	LastSyncedAt *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time

	// Ingest cursor (issue #487). LastIngestedCommit is the head commit fully
	// enqueued as a change set; the compiler diffs from it, not from a delivery's
	// own `before`, so a missed delivery is caught up by the next one.
	// ReconcileInterval 0 disables the periodic snapshot (NextReconcileAt stays
	// nil); otherwise NextReconcileAt is when the reconcile sweep next considers
	// the source.
	LastIngestedCommit string
	LastIngestedAt     *time.Time
	LastDeliveryID     string
	ReconcileInterval  time.Duration
	NextReconcileAt    *time.Time
}

// WebhookConfigured reports whether a signing secret is stored, i.e. whether
// live webhook ingestion can verify deliveries for this Source.
func (d *DatasourceSource) WebhookConfigured() bool {
	return strings.TrimSpace(d.WebhookSecretRef) != ""
}

// AddGitHubSourceInput is the caller-supplied configuration for a GitHub Source.
// AccessToken and WebhookSecret are plaintext; each is encrypted through the
// SecretCipher and only its envelope reference is persisted.
type AddGitHubSourceInput struct {
	OrgID  string
	Repo   string
	Paths  []string
	Branch string
	// The data boundary the source writes into: exactly one of an existing scope
	// node's id, or a label to mint a new `collection` node (issue #473).
	BoundaryNodeID  string
	CollectionLabel string
	AccessToken     string
	WebhookSecret   string
}

// GitHubContentClient is the subset of the api.github.com client the datasource
// connector needs. The Service builds one per Source from its decrypted token.
type GitHubContentClient interface {
	DefaultBranch(ctx context.Context, repo string) (string, error)
	ResolveCommit(ctx context.Context, repo, ref string) (string, error)
	ListFiles(ctx context.Context, repo, ref string, prefixes []string) ([]github.File, error)
	GetFileContent(ctx context.Context, repo, ref, path string) ([]byte, error)
	Compare(ctx context.Context, repo, base, head string) (*github.Comparison, error)
	GetBlob(ctx context.Context, repo, blobSHA string, max int64) ([]byte, error)
}

// APIContentClient is the subset of the generic API connector the Service needs.
// The Service builds one per Source from its config and decrypted credential.
type APIContentClient interface {
	Fetch(ctx context.Context) (*apisource.Result, error)
}

// CrawlerContentClient is the subset of the crawler connector the Service needs.
// The Service builds one per Source from its config and drives it item-at-a-time
// (List then Fetch) so an entire site is never held in memory at once.
type CrawlerContentClient interface {
	List(ctx context.Context) ([]string, error)
	Fetch(ctx context.Context, pageURL string) (crawler.Page, error)
}

// UploadContentClient is the subset of the object-storage connector the Service
// needs. The Service builds one per Source from its config and decrypted secret
// access key and drives it item-at-a-time (List then Fetch).
type UploadContentClient interface {
	List(ctx context.Context) ([]objectstore.Entry, error)
	Fetch(ctx context.Context, key string) (objectstore.Object, error)
}

// OAuth2RefreshFunc exchanges an OAuth 2.0 refresh token for a fresh access
// token. It matches apisource.RefreshOAuth2; tests substitute a deterministic
// implementation.
type OAuth2RefreshFunc func(ctx context.Context, cfg apisource.OAuth2Config, refreshToken, clientSecret string) (*apisource.OAuth2Token, error)

// SetDatasourceConnector wires the fail-closed credential cipher, the privileged
// inbox producer used for ingest deliveries, and the GitHub API base URL. It is
// the one setter #274 adds; production passes Vault transit and the durable job
// store, tests pass deterministic substitutes.
func (s *Service) SetDatasourceConnector(cipher SecretCipher, producer jobs.Producer, githubBaseURL string) {
	s.datasourceCipher = cipher
	s.datasourceJobs = producer
	s.githubBaseURL = strings.TrimSpace(githubBaseURL)
	if s.newGitHubClient == nil {
		s.newGitHubClient = func(token string) GitHubContentClient {
			return github.New(token, s.githubBaseURL)
		}
	}
	if s.newAPIClient == nil {
		s.newAPIClient = func(cfg APIDatasourceConfig, credential string) APIContentClient {
			return apisource.New(apisource.Config{
				BaseURL:              cfg.BaseURL,
				ResourcePath:         cfg.ResourcePath,
				CredentialKind:       cfg.CredentialKind,
				CredentialHeader:     cfg.CredentialHeader,
				CredentialQueryParam: cfg.CredentialQueryParam,
			}, credential)
		}
	}
	if s.newCrawlerClient == nil {
		s.newCrawlerClient = func(cfg CrawlerDatasourceConfig) CrawlerContentClient {
			return crawler.New(crawler.Config{SitemapURL: cfg.SitemapURL, MaxPages: cfg.MaxPages})
		}
	}
	if s.newUploadClient == nil {
		s.newUploadClient = func(cfg UploadDatasourceConfig, secretAccessKey string) UploadContentClient {
			return objectstore.New(objectstore.Config{
				Endpoint:    cfg.Endpoint,
				Region:      cfg.Region,
				Bucket:      cfg.Bucket,
				Prefix:      cfg.Prefix,
				AccessKeyID: cfg.AccessKeyID,
				MaxObjects:  cfg.MaxObjects,
			}, secretAccessKey)
		}
	}
	if s.newOAuth2Refresh == nil {
		s.newOAuth2Refresh = apisource.RefreshOAuth2
	}
}

// SetDatasourceGitHubClientFactory overrides how per-Source GitHub clients are
// built. Tests use it to inject a fake without a live api.github.com.
func (s *Service) SetDatasourceGitHubClientFactory(factory func(token string) GitHubContentClient) {
	s.newGitHubClient = factory
}

// SetDatasourceTicketKey seeds the signer that mints and verifies the opaque
// content tickets a change-set job carries in place of an oversized blob. The
// seed is the deployment's internal key; the same seed must be present wherever
// ResolveContentTicket runs so a ticket minted by the compiler verifies at
// redemption.
func (s *Service) SetDatasourceTicketKey(seed []byte) {
	s.datasourceTicketSigner = newDatasourceTicketSigner(seed)
}

// SetDatasourceAPIClientFactory overrides how per-Source API clients are built.
// Tests use it to inject a fake without a live HTTP endpoint.
func (s *Service) SetDatasourceAPIClientFactory(factory func(cfg APIDatasourceConfig, credential string) APIContentClient) {
	s.newAPIClient = factory
}

// SetDatasourceCrawlerClientFactory overrides how per-Source crawler clients are
// built. Tests use it to inject a fake without a live website.
func (s *Service) SetDatasourceCrawlerClientFactory(factory func(cfg CrawlerDatasourceConfig) CrawlerContentClient) {
	s.newCrawlerClient = factory
}

// SetDatasourceUploadClientFactory overrides how per-Source object-storage
// clients are built. Tests use it to inject a fake without a live object store.
func (s *Service) SetDatasourceUploadClientFactory(factory func(cfg UploadDatasourceConfig, secretAccessKey string) UploadContentClient) {
	s.newUploadClient = factory
}

// SetDatasourceOAuth2RefreshFunc overrides how an OAuth 2.0 access token is
// refreshed. Tests use it to inject a deterministic token without a live token
// endpoint.
func (s *Service) SetDatasourceOAuth2RefreshFunc(fn OAuth2RefreshFunc) {
	s.newOAuth2Refresh = fn
}

// AddGitHubSource registers a GitHub repository as a Source. The access token
// (and optional webhook signing secret) are encrypted and stored only as
// envelope references. The returned Source carries no credential material.
func (s *Service) AddGitHubSource(ctx context.Context, actorID string, input AddGitHubSourceInput) (*DatasourceSource, error) {
	w := wool.Get(ctx).In("AddGitHubSource")

	orgID := strings.TrimSpace(input.OrgID)
	if orgID == "" {
		return nil, w.NewError("org id is required")
	}
	repo := strings.TrimSpace(input.Repo)
	if !validRepo(repo) {
		return nil, w.NewError("repo must be in owner/name form")
	}
	if err := requireBoundarySpec(input.BoundaryNodeID, input.CollectionLabel); err != nil {
		return nil, w.Wrap(err)
	}
	if strings.TrimSpace(input.AccessToken) == "" {
		return nil, w.NewError("access token is required")
	}
	if s.datasourceCipher == nil {
		return nil, w.NewError("datasource secret cipher is not configured")
	}

	if err := s.validateGitHubSource(ctx, repo, input.Branch, input.AccessToken); err != nil {
		return nil, err
	}

	source := &DatasourceSource{
		ID:                NewIDString(),
		OrgID:             orgID,
		Provider:          DatasourceProviderGitHub,
		Repo:              repo,
		Paths:             normalizePaths(input.Paths),
		Branch:            strings.TrimSpace(input.Branch),
		Status:            DatasourceStatusActive,
		ReconcileInterval: defaultDatasourceReconcileInterval,
	}
	nextReconcile := time.Now().UTC().Add(defaultDatasourceReconcileInterval)
	source.NextReconcileAt = &nextReconcile

	credentialRef, err := s.datasourceCipher.EncryptSecret(ctx, DatasourceConnectorSecretPurpose(source.ID), strings.TrimSpace(input.AccessToken))
	if err != nil {
		return nil, w.Wrapf(err, "encrypt access token")
	}
	source.CredentialSecretRef = credentialRef

	if secret := strings.TrimSpace(input.WebhookSecret); secret != "" {
		webhookRef, err := s.datasourceCipher.EncryptSecret(ctx, DatasourceWebhookSecretPurpose(source.ID), secret)
		if err != nil {
			return nil, w.Wrapf(err, "encrypt webhook secret")
		}
		source.WebhookSecretRef = webhookRef
	}

	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		boundaryID, err := s.resolveBoundary(ctx, orgID, input.BoundaryNodeID, input.CollectionLabel)
		if err != nil {
			return err
		}
		source.BoundaryNodeID = boundaryID
		if err := s.store.InsertDatasourceSource(ctx, source); err != nil {
			return err
		}
		return s.emitTx(ctx, actorID, "user", EventDatasourceSourceAdded, "datasource", source.ID, orgID,
			map[string]any{"repo": source.Repo})
	}); err != nil {
		return nil, w.Wrapf(err, "persist datasource source")
	}
	return source, nil
}

// AddSourceInput is the provider-agnostic connect input. Provider selects the
// connector; the matching config fields are read (Repo/Paths/Branch for GitHub,
// API for the generic API provider). Credential and WebhookSecret are plaintext,
// each encrypted through the SecretCipher and persisted only as an envelope
// reference.
type AddSourceInput struct {
	OrgID    string
	Provider string
	// The data boundary the source writes into: exactly one of an existing scope
	// node's id, or a label to mint a new `collection` node (issue #473).
	BoundaryNodeID  string
	CollectionLabel string
	Credential      string
	WebhookSecret   string

	// GitHub provider config.
	Repo   string
	Paths  []string
	Branch string

	// API provider config.
	API *APIDatasourceConfig

	// Crawler provider config.
	Crawler *CrawlerDatasourceConfig

	// Upload (object-storage) provider config.
	Upload *UploadDatasourceConfig

	// OAuth2ClientSecret is the confidential-client secret for an API source
	// whose credential kind is OAuth2; it is stored with the refresh token
	// (Credential) in the credential envelope and never projected.
	OAuth2ClientSecret string
}

// AddSource registers a datasource for any provider. It validates the config for
// the selected provider, encrypts the credential (and, where the provider
// supports webhooks, the signing secret), persists the non-secret row, and
// returns it without credential material.
func (s *Service) AddSource(ctx context.Context, actorID string, input AddSourceInput) (*DatasourceSource, error) {
	w := wool.Get(ctx).In("AddSource")

	orgID := strings.TrimSpace(input.OrgID)
	if orgID == "" {
		return nil, w.NewError("org id is required")
	}
	if err := requireBoundarySpec(input.BoundaryNodeID, input.CollectionLabel); err != nil {
		return nil, w.Wrap(err)
	}
	if s.datasourceCipher == nil {
		return nil, w.NewError("datasource secret cipher is not configured")
	}

	source := &DatasourceSource{
		ID:       NewIDString(),
		OrgID:    orgID,
		Provider: input.Provider,
		Status:   DatasourceStatusActive,
	}

	credential := strings.TrimSpace(input.Credential)

	switch input.Provider {
	case DatasourceProviderGitHub:
		if credential == "" {
			return nil, w.NewError("credential is required")
		}
		repo := strings.TrimSpace(input.Repo)
		if !validRepo(repo) {
			return nil, w.NewError("repo must be in owner/name form")
		}
		if err := s.validateGitHubSource(ctx, repo, input.Branch, credential); err != nil {
			return nil, err
		}
		source.Repo = repo
		source.Paths = normalizePaths(input.Paths)
		source.Branch = strings.TrimSpace(input.Branch)
		source.ReconcileInterval = defaultDatasourceReconcileInterval
		nextReconcile := time.Now().UTC().Add(defaultDatasourceReconcileInterval)
		source.NextReconcileAt = &nextReconcile
	case DatasourceProviderAPI:
		if credential == "" {
			return nil, w.NewError("credential is required")
		}
		// The generic API provider has no webhook receiver yet; refuse a secret
		// nothing would ever verify rather than storing dead credential material.
		if strings.TrimSpace(input.WebhookSecret) != "" {
			return nil, w.NewError("api provider does not support webhooks")
		}
		cfg, err := normalizeAPIConfig(input.API)
		if err != nil {
			return nil, w.Wrap(err)
		}
		source.API = cfg
	case DatasourceProviderCrawler:
		// The crawler reads public pages: it takes no credential and has no webhook
		// receiver. Reject either rather than storing material nothing would use.
		if credential != "" {
			return nil, w.NewError("crawler provider does not take a credential")
		}
		if strings.TrimSpace(input.WebhookSecret) != "" {
			return nil, w.NewError("crawler provider does not support webhooks")
		}
		cfg, err := normalizeCrawlerConfig(input.Crawler)
		if err != nil {
			return nil, w.Wrap(err)
		}
		source.Crawler = cfg
	case DatasourceProviderUpload:
		if credential == "" {
			return nil, w.NewError("credential is required")
		}
		// Object storage is pulled, not pushed: refuse a webhook secret nothing
		// would verify.
		if strings.TrimSpace(input.WebhookSecret) != "" {
			return nil, w.NewError("upload provider does not support webhooks")
		}
		cfg, err := normalizeUploadConfig(input.Upload)
		if err != nil {
			return nil, w.Wrap(err)
		}
		source.Upload = cfg
	default:
		return nil, w.NewError("unknown datasource provider")
	}

	if credential != "" {
		credentialPlaintext, err := connectorCredentialPlaintext(source, credential, input.OAuth2ClientSecret)
		if err != nil {
			return nil, w.Wrap(err)
		}
		credentialRef, err := s.datasourceCipher.EncryptSecret(ctx, DatasourceConnectorSecretPurpose(source.ID), credentialPlaintext)
		if err != nil {
			return nil, w.Wrapf(err, "encrypt credential")
		}
		source.CredentialSecretRef = credentialRef
	}

	if secret := strings.TrimSpace(input.WebhookSecret); secret != "" {
		webhookRef, err := s.datasourceCipher.EncryptSecret(ctx, DatasourceWebhookSecretPurpose(source.ID), secret)
		if err != nil {
			return nil, w.Wrapf(err, "encrypt webhook secret")
		}
		source.WebhookSecretRef = webhookRef
	}

	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		boundaryID, err := s.resolveBoundary(ctx, orgID, input.BoundaryNodeID, input.CollectionLabel)
		if err != nil {
			return err
		}
		source.BoundaryNodeID = boundaryID
		if err := s.store.InsertDatasourceSource(ctx, source); err != nil {
			return err
		}
		return s.emitTx(ctx, actorID, "user", EventDatasourceSourceAdded, "datasource", source.ID, orgID,
			map[string]any{"provider": source.Provider})
	}); err != nil {
		return nil, w.Wrapf(err, "persist datasource source")
	}
	return source, nil
}

// requireBoundarySpec rejects a connect input that names neither or both of a
// boundary node id and a collection label; the caller must pick exactly one.
func requireBoundarySpec(boundaryNodeID, collectionLabel string) error {
	hasID := strings.TrimSpace(boundaryNodeID) != ""
	hasLabel := strings.TrimSpace(collectionLabel) != ""
	switch {
	case hasID && hasLabel:
		return errors.New("boundary node id and collection label are mutually exclusive")
	case !hasID && !hasLabel:
		return errors.New("a boundary node id or collection label is required")
	default:
		return nil
	}
}

// resolveBoundary maps a connect input's boundary spec to a scope-node id: an
// existing node is validated for tenant visibility; a collection label resolves
// to the tenant's collection node of that name, creating one (registered as a
// root — a child of the org's solution node once installation identity lands) on
// first use. Reusing by label keeps every source of one collection under a single
// grantable boundary. Runs inside the source-insert transaction so a minted node
// and the source that binds it commit together.
func (s *Service) resolveBoundary(ctx context.Context, orgID, boundaryNodeID, collectionLabel string) (string, error) {
	w := wool.Get(ctx).In("resolveBoundary")
	if boundaryNodeID = strings.TrimSpace(boundaryNodeID); boundaryNodeID != "" {
		exists, err := s.store.ScopeNodeExists(ctx, boundaryNodeID)
		if err != nil {
			return "", w.Wrap(err)
		}
		if !exists {
			return "", w.NewError("boundary node is not a scope node in this org")
		}
		return boundaryNodeID, nil
	}
	node := &gen.ScopeNode{
		Id:    NewIDString(),
		OrgId: orgID,
		Kind:  ScopeNodeKindCollection,
		Label: strings.TrimSpace(collectionLabel),
	}
	node.ScopePath = strings.ReplaceAll(node.Id, "-", "_")
	boundaryID, err := s.store.GetOrCreateCollectionNode(ctx, node)
	if err != nil {
		return "", w.Wrapf(err, "resolve collection node")
	}
	return boundaryID, nil
}

// normalizeAPIConfig validates and trims a generic API provider config.
func normalizeAPIConfig(cfg *APIDatasourceConfig) (*APIDatasourceConfig, error) {
	if cfg == nil {
		return nil, errors.New("api config is required")
	}
	baseURL := strings.TrimSpace(cfg.BaseURL)
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("api base url must be an absolute http(s) url")
	}
	out := &APIDatasourceConfig{
		BaseURL:        baseURL,
		ResourcePath:   strings.TrimSpace(cfg.ResourcePath),
		CredentialKind: strings.TrimSpace(cfg.CredentialKind),
	}
	switch out.CredentialKind {
	case APICredentialKindBearer, APICredentialKindBasic:
	case APICredentialKindHeader:
		out.CredentialHeader = strings.TrimSpace(cfg.CredentialHeader)
		if out.CredentialHeader == "" {
			return nil, errors.New("api header credential kind requires a header name")
		}
	case APICredentialKindQuery:
		out.CredentialQueryParam = strings.TrimSpace(cfg.CredentialQueryParam)
		if out.CredentialQueryParam == "" {
			return nil, errors.New("api query credential kind requires a query parameter name")
		}
	case APICredentialKindOAuth2:
		oauth, err := normalizeOAuth2Config(cfg.OAuth2)
		if err != nil {
			return nil, err
		}
		out.OAuth2 = oauth
	default:
		return nil, errors.New("api credential kind must be bearer, basic, header, query, or oauth2")
	}
	return out, nil
}

// normalizeCrawlerConfig validates and trims a crawler provider config.
func normalizeCrawlerConfig(cfg *CrawlerDatasourceConfig) (*CrawlerDatasourceConfig, error) {
	if cfg == nil {
		return nil, errors.New("crawler config is required")
	}
	sitemapURL := strings.TrimSpace(cfg.SitemapURL)
	parsed, err := url.Parse(sitemapURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("crawler sitemap url must be an absolute http(s) url")
	}
	maxPages := cfg.MaxPages
	if maxPages < 0 {
		return nil, errors.New("crawler max pages must not be negative")
	}
	return &CrawlerDatasourceConfig{SitemapURL: sitemapURL, MaxPages: maxPages}, nil
}

// normalizeUploadConfig validates and trims an object-storage provider config.
func normalizeUploadConfig(cfg *UploadDatasourceConfig) (*UploadDatasourceConfig, error) {
	if cfg == nil {
		return nil, errors.New("upload config is required")
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("upload endpoint must be an absolute http(s) url")
	}
	out := &UploadDatasourceConfig{
		Endpoint:    endpoint,
		Region:      strings.TrimSpace(cfg.Region),
		Bucket:      strings.TrimSpace(cfg.Bucket),
		Prefix:      strings.TrimSpace(cfg.Prefix),
		AccessKeyID: strings.TrimSpace(cfg.AccessKeyID),
		MaxObjects:  cfg.MaxObjects,
	}
	if out.Region == "" {
		return nil, errors.New("upload region is required")
	}
	if out.Bucket == "" {
		return nil, errors.New("upload bucket is required")
	}
	if out.AccessKeyID == "" {
		return nil, errors.New("upload access key id is required")
	}
	if out.MaxObjects < 0 {
		return nil, errors.New("upload max objects must not be negative")
	}
	return out, nil
}

// normalizeOAuth2Config validates and trims the non-secret OAuth 2.0 config.
func normalizeOAuth2Config(cfg *APIOAuth2Config) (*APIOAuth2Config, error) {
	if cfg == nil {
		return nil, errors.New("api oauth2 credential kind requires oauth2 config")
	}
	tokenURL := strings.TrimSpace(cfg.TokenURL)
	parsed, err := url.Parse(tokenURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("api oauth2 token url must be an absolute http(s) url")
	}
	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return nil, errors.New("api oauth2 config requires a client id")
	}
	var scopes []string
	for _, s := range cfg.Scopes {
		if s = strings.TrimSpace(s); s != "" {
			scopes = append(scopes, s)
		}
	}
	return &APIOAuth2Config{TokenURL: tokenURL, ClientID: clientID, Scopes: scopes}, nil
}

// connectorCredentialPlaintext returns the plaintext to encrypt into the
// credential envelope. For every kind but OAuth2 that is the raw credential; an
// OAuth2 source stores a JSON token set so the access token and its expiry can
// be rotated in place, keyed by the same envelope.
func connectorCredentialPlaintext(source *DatasourceSource, credential, oauth2ClientSecret string) (string, error) {
	if source.API == nil || source.API.CredentialKind != APICredentialKindOAuth2 {
		return credential, nil
	}
	blob, err := json.Marshal(oauthStoredCredential{
		RefreshToken: credential,
		ClientSecret: strings.TrimSpace(oauth2ClientSecret),
	})
	if err != nil {
		return "", err
	}
	return string(blob), nil
}

// ListDatasourceSources returns the org's connected Sources.
func (s *Service) ListDatasourceSources(ctx context.Context, orgID string) ([]*DatasourceSource, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, errors.New("org id is required")
	}
	var sources []*DatasourceSource
	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		list, err := s.store.ListDatasourceSources(ctx, orgID)
		sources = list
		return err
	}); err != nil {
		return nil, err
	}
	return sources, nil
}

// GetDatasourceSource returns one connected Source in the org, or
// ErrDatasourceSourceNotFound.
func (s *Service) GetDatasourceSource(ctx context.Context, orgID, id string) (*DatasourceSource, error) {
	orgID = strings.TrimSpace(orgID)
	id = strings.TrimSpace(id)
	if orgID == "" || id == "" {
		return nil, errors.New("org id and source id are required")
	}
	var source *DatasourceSource
	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		found, err := s.store.GetDatasourceSource(ctx, orgID, id)
		source = found
		return err
	}); err != nil {
		return nil, err
	}
	if source == nil {
		return nil, ErrDatasourceSourceNotFound
	}
	return source, nil
}

// DeleteDatasourceSource removes a Source and its stored credentials.
func (s *Service) DeleteDatasourceSource(ctx context.Context, actorID, orgID, id string) error {
	orgID = strings.TrimSpace(orgID)
	id = strings.TrimSpace(id)
	if orgID == "" || id == "" {
		return errors.New("org id and source id are required")
	}
	if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
		if err := s.store.DeleteDatasourceSource(ctx, orgID, id); err != nil {
			return err
		}
		return s.emitTx(ctx, actorID, "user", EventDatasourceSourceRemoved, "datasource", id, orgID)
	}); err != nil {
		return err
	}
	return nil
}

// SyncDatasourceSource enqueues a durable "reconcile now" request and returns
// the request's job id. The pull runs off-request in a leased worker, so a large
// repository cannot block or time out the RPC and gets the jobs framework's
// retry/backoff. For a GitHub source this is a forced snapshot at the branch head
// (regardless of cursor equality), serialized behind any in-flight delivery for
// the same source; other providers keep the full-refetch sync path. The Source
// must belong to orgID.
func (s *Service) SyncDatasourceSource(ctx context.Context, actorID, orgID, id string, replacementToken ...string) (jobID string, resultErr error) {
	w := wool.Get(ctx).In("SyncDatasourceSource")
	source, err := s.GetDatasourceSource(ctx, orgID, id)
	if err != nil {
		return "", err
	}
	defer func() {
		if resultErr != nil {
			s.emit(ctx, actorID, "user", EventDatasourceSyncFailed, "datasource", source.ID, source.OrgID, datasourceFailureFields(resultErr, source.Repo, "manual"))
		}
	}()
	if s.datasourceJobs == nil {
		return "", w.NewError("datasource connector is not configured")
	}

	if len(replacementToken) > 0 && replacementToken[0] != "" && (source.Provider != DatasourceProviderGitHub || len(replacementToken[0]) > 4096) {
		return "", w.NewError("a replacement PAT of at most 4096 bytes is supported only for GitHub sources")
	}
	var job *jobsv1.NewJob
	if source.Provider == DatasourceProviderGitHub {
		if s.datasourceCipher == nil {
			return "", w.NewError("datasource secret cipher is not configured")
		}
		var token string
		if len(replacementToken) > 0 {
			token = strings.TrimSpace(replacementToken[0])
		}
		replacing := token != ""
		if !replacing {
			if err := s.checkGitHubSyncPreflight(ctx, source); err != nil {
				return "", err
			}
		} else if err := s.validateGitHubSource(ctx, source.Repo, source.Branch, token); err != nil {
			return "", err
		}
		if replacing {
			encrypted, err := s.datasourceCipher.EncryptSecret(ctx, DatasourceConnectorSecretPurpose(source.ID), token)
			if err != nil {
				return "", jobs.NewProcessingError("datasource.credential_store_unavailable", "Could not securely save the replacement credential. Retry shortly.", true)
			}
			if err := s.store.WithOrgTx(ctx, orgID, func(ctx context.Context) error {
				if _, err := s.store.LockDatasourceSourceCredentialRef(ctx, orgID, id); err != nil {
					return err
				}
				if err := s.store.UpdateDatasourceSourceCredential(ctx, orgID, id, encrypted); err != nil {
					return err
				}
				return s.emitTx(ctx, actorID, "user", EventDatasourceCredentialUpdated, "datasource", source.ID, orgID,
					map[string]any{"repo": source.Repo, "credential_kind": githubCredentialKindPAT})
			}); err != nil {
				return "", err
			}
		}
		job = &jobsv1.NewJob{
			Direction:      jobsv1.JobDirection_JOB_DIRECTION_INBOX,
			Scope:          &jobsv1.JobScope{Value: &jobsv1.JobScope_Global{Global: true}},
			Queue:          DatasourceDeliveryQueue,
			Topic:          datasourceReconcileTopic,
			Source:         datasourceReconcileSource,
			Ordering:       DatasourceDeliveryOrderingKey(source.ID),
			IdempotencyKey: NewIDString(),
			SchemaVersion:  datasourceReconcileSchemaVersion,
			Payload:        datasourceRequestBody(),
			ContentType:    datasourceRequestContentType,
			MaxAttempts:    datasourceDeliveryMaxAttempts,
			Attributes: map[string]string{
				attrSourceID:      source.ID,
				attrOrgID:         source.OrgID,
				attrBoundaryID:    source.BoundaryNodeID,
				attrReconcileMode: reconcileModeForce,
			},
		}
	} else {
		job = &jobsv1.NewJob{
			Direction: jobsv1.JobDirection_JOB_DIRECTION_INBOX,
			Scope:     &jobsv1.JobScope{Value: &jobsv1.JobScope_OrganizationId{OrganizationId: source.OrgID}},
			Queue:     DatasourceSyncRequestQueue,
			Topic:     datasourceSyncRequestTopic,
			Source:    datasourceSyncRequestSource,
			// A fresh key per request: a sync is an explicit "reconcile now" action,
			// so it must never be dropped as an idempotent replay of an earlier,
			// already-terminal request.
			IdempotencyKey: NewIDString(),
			SchemaVersion:  datasourceSyncRequestSchemaVersion,
			Payload:        datasourceRequestBody(),
			ContentType:    datasourceRequestContentType,
			MaxAttempts:    datasourceSyncRequestMaxAttempts,
			Attributes:     map[string]string{attrSourceID: source.ID},
		}
	}

	response, err := s.datasourceJobs.EnqueueJob(ctx, &jobsv1.EnqueueJobRequest{Job: job})
	if err != nil {
		return "", w.Wrapf(err, "enqueue sync request")
	}
	s.emit(ctx, actorID, "user", EventDatasourceSourceSynced, "datasource", source.ID, orgID, map[string]any{"job_id": response.GetJobId(), "repo": source.Repo})
	return response.GetJobId(), nil
}

// datasourceRequestBody is the body every datasource *request* job carries —
// the forced and periodic reconcile requests and the generic sync request. A
// request has no data of its own (its attributes name the source and the mode),
// but a job is a message: saas.jobs.v1 validates content_type (min_len 1) and
// job_messages.payload is NOT NULL, so a request declares an empty JSON object
// rather than nothing. Returned fresh per call so no consumer can mutate a
// shared backing array into another job's payload.
func datasourceRequestBody() []byte { return []byte("{}") }

// RunDatasourceSync performs the actual pull for one Source, dispatched by
// provider. It is invoked by the leased sync worker, never by request traffic.
// Returns the number of ingest deliveries enqueued.
func (s *Service) RunDatasourceSync(ctx context.Context, sourceID string) (int, error) {
	w := wool.Get(ctx).In("RunDatasourceSync")
	if s.datasourceCipher == nil || s.datasourceJobs == nil {
		return 0, w.NewError("datasource connector is not configured")
	}
	source, err := s.store.GetDatasourceSourceByID(ctx, sourceID)
	if err != nil {
		return 0, w.Wrapf(err, "load source")
	}
	if source == nil {
		return 0, ErrDatasourceSourceNotFound
	}

	switch source.Provider {
	case DatasourceProviderAPI:
		return s.runAPISync(ctx, source)
	case DatasourceProviderCrawler:
		return s.runCrawlerSync(ctx, source)
	case DatasourceProviderUpload:
		return s.runUploadSync(ctx, source)
	default:
		// GitHub sources are reconciled through the change-set delivery worker
		// (DatasourceDeliveryQueue), not this full-refetch path.
		return 0, w.NewError("unsupported datasource provider for full sync")
	}
}

// runAPISync fetches the API source's configured resource and enqueues its body
// as a single ingest delivery. Re-sync with unchanged content dedupes on the
// content hash; changed content is re-delivered.
func (s *Service) runAPISync(ctx context.Context, source *DatasourceSource) (int, error) {
	w := wool.Get(ctx).In("runAPISync")
	if s.newAPIClient == nil {
		return 0, w.NewError("datasource connector is not configured")
	}
	if source.API == nil {
		return 0, w.NewError("api source has no config")
	}

	fetchConfig := *source.API
	var fetchCredential string
	if source.API.CredentialKind == APICredentialKindOAuth2 {
		accessToken, err := s.resolveOAuth2AccessToken(ctx, source)
		if err != nil {
			return 0, w.Wrapf(err, "resolve oauth2 access token")
		}
		fetchConfig.CredentialKind = APICredentialKindBearer
		fetchCredential = accessToken
	} else {
		stored, err := s.datasourceCipher.DecryptSecret(ctx, DatasourceConnectorSecretPurpose(source.ID), source.CredentialSecretRef)
		if err != nil {
			return 0, w.Wrapf(err, "decrypt credential")
		}
		fetchCredential = stored
	}

	result, err := s.newAPIClient(fetchConfig, fetchCredential).Fetch(ctx)
	if err != nil {
		return 0, w.Wrapf(err, "fetch api resource")
	}
	if len(result.Body) > maxIngestPayload {
		return 0, w.NewError("api response exceeds the ingest payload limit")
	}
	if err := s.enqueueAPIIngest(ctx, source, result); err != nil {
		return 0, w.Wrapf(err, "enqueue api delivery")
	}

	if err := s.store.WithOrgTx(ctx, source.OrgID, func(ctx context.Context) error {
		return s.store.SetDatasourceSourceSynced(ctx, source.OrgID, source.ID, time.Now().UTC())
	}); err != nil {
		return 1, w.Wrapf(err, "record sync time")
	}
	return 1, nil
}

// resolveOAuth2AccessToken returns a live access token for an OAuth 2.0 source,
// refreshing at the token endpoint when the stored token is absent or within its
// expiry leeway. The whole read-modify-write runs inside one org transaction
// that first takes a row lock on the source: a concurrent sync of the same
// source blocks until this commits, then re-reads the freshly rotated envelope
// and skips its own refresh — so a single-use refresh token is never spent twice
// and a rotated token is never clobbered. A permanent rejection surfaces as
// ErrOAuth2ReauthRequired (terminal). source.CredentialSecretRef is updated to
// the rotated envelope.
func (s *Service) resolveOAuth2AccessToken(ctx context.Context, source *DatasourceSource) (string, error) {
	w := wool.Get(ctx).In("resolveOAuth2AccessToken")
	if s.newOAuth2Refresh == nil {
		return "", w.NewError("datasource connector is not configured")
	}
	if source.API.OAuth2 == nil {
		return "", w.NewError("oauth2 source has no oauth2 config")
	}

	var accessToken string
	err := s.store.WithOrgTx(ctx, source.OrgID, func(ctx context.Context) error {
		ref, err := s.store.LockDatasourceSourceCredentialRef(ctx, source.OrgID, source.ID)
		if err != nil {
			return w.Wrapf(err, "lock credential")
		}
		stored, err := s.datasourceCipher.DecryptSecret(ctx, DatasourceConnectorSecretPurpose(source.ID), ref)
		if err != nil {
			return w.Wrapf(err, "decrypt credential")
		}
		var cred oauthStoredCredential
		if err := json.Unmarshal([]byte(stored), &cred); err != nil {
			return w.Wrapf(err, "decode stored oauth2 credential")
		}

		now := time.Now().UTC()
		if cred.AccessToken != "" && cred.ExpiresAt > now.Add(oauth2ExpiryLeeway).Unix() {
			accessToken = cred.AccessToken
			source.CredentialSecretRef = ref
			return nil
		}

		token, err := s.newOAuth2Refresh(ctx, apisource.OAuth2Config{
			TokenURL: source.API.OAuth2.TokenURL,
			ClientID: source.API.OAuth2.ClientID,
			Scopes:   source.API.OAuth2.Scopes,
		}, cred.RefreshToken, cred.ClientSecret)
		if err != nil {
			if errors.Is(err, apisource.ErrRefreshRejected) {
				return ErrOAuth2ReauthRequired
			}
			return w.Wrapf(err, "refresh oauth2 token")
		}

		cred.AccessToken = token.AccessToken
		ttl := token.ExpiresIn
		if ttl <= 0 {
			ttl = oauth2DefaultTTL
		}
		cred.ExpiresAt = now.Add(ttl).Unix()
		if token.RefreshToken != "" {
			cred.RefreshToken = token.RefreshToken
		}

		blob, err := json.Marshal(cred)
		if err != nil {
			return w.Wrapf(err, "encode rotated oauth2 credential")
		}
		newRef, err := s.datasourceCipher.EncryptSecret(ctx, DatasourceConnectorSecretPurpose(source.ID), string(blob))
		if err != nil {
			return w.Wrapf(err, "encrypt rotated oauth2 credential")
		}
		if err := s.store.UpdateDatasourceSourceCredential(ctx, source.OrgID, source.ID, newRef); err != nil {
			return w.Wrapf(err, "persist rotated oauth2 credential")
		}
		source.CredentialSecretRef = newRef
		accessToken = cred.AccessToken
		return nil
	})
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

func (s *Service) enqueueAPIIngest(ctx context.Context, source *DatasourceSource, result *apisource.Result) error {
	if source.BoundaryNodeID == "" {
		return wool.Get(ctx).NewError("datasource source has no resolvable boundary")
	}
	contentType := result.ContentType
	if contentType == "" {
		contentType = datasourceIngestContentType
	}
	digest := sha256.Sum256(result.Body)
	contentSHA := hex.EncodeToString(digest[:])
	_, err := s.datasourceJobs.EnqueueJob(ctx, &jobsv1.EnqueueJobRequest{
		Job: &jobsv1.NewJob{
			Direction:      jobsv1.JobDirection_JOB_DIRECTION_INBOX,
			Scope:          &jobsv1.JobScope{Value: &jobsv1.JobScope_Global{Global: true}},
			Queue:          datasourceIngestQueue,
			Topic:          datasourceAPISyncTopic,
			Source:         datasourceAPISyncSource,
			IdempotencyKey: "datasource-api-sync/" + source.ID + "/" + contentSHA,
			SchemaVersion:  datasourceIngestSchemaVersion,
			Payload:        result.Body,
			ContentType:    contentType,
			MaxAttempts:    datasourceIngestMaxAttempts,
			Attributes: map[string]string{
				attrSourceID:      source.ID,
				attrOrgID:         source.OrgID,
				attrBoundaryID:    source.BoundaryNodeID,
				attrAPIURL:        apiResourceURL(source.API),
				attrAPIContentSHA: contentSHA,
				attrChangeType:    changeTypeAdded,
			},
		},
	})
	return err
}

func apiResourceURL(cfg *APIDatasourceConfig) string {
	if cfg.ResourcePath == "" {
		return cfg.BaseURL
	}
	return strings.TrimRight(cfg.BaseURL, "/") + "/" + strings.TrimLeft(cfg.ResourcePath, "/")
}

// runCrawlerSync reads the source's sitemap and fetches each listed page one at a
// time, enqueuing an ingest delivery per page. Pages are streamed (never all held
// in memory), a page too large to deliver is recorded and surfaced rather than
// silently dropped, and a sitemap that yields no deliverable page fails the sync
// rather than recording an empty success.
func (s *Service) runCrawlerSync(ctx context.Context, source *DatasourceSource) (int, error) {
	w := wool.Get(ctx).In("runCrawlerSync")
	if s.newCrawlerClient == nil {
		return 0, w.NewError("datasource connector is not configured")
	}
	if source.Crawler == nil {
		return 0, w.NewError("crawler source has no config")
	}
	client := s.newCrawlerClient(*source.Crawler)

	urls, err := client.List(ctx)
	if err != nil {
		return 0, w.Wrapf(err, "list sitemap")
	}

	enqueued := 0
	oversized := 0
	for _, u := range urls {
		page, err := client.Fetch(ctx, u)
		if err != nil {
			if errors.Is(err, crawler.ErrPageTooLarge) {
				oversized++
				continue
			}
			// One unreachable page must not abort the whole crawl; skip it
			// best-effort. A crawl that reaches none of its pages is caught below.
			w.Warn("skipping unfetchable page", wool.Field("url", u), wool.ErrField(err))
			continue
		}
		if len(page.Body) > maxIngestPayload {
			oversized++
			continue
		}
		if err := s.enqueueCrawlerIngest(ctx, source, page); err != nil {
			return enqueued, w.Wrapf(err, "enqueue %s", u)
		}
		enqueued++
	}

	// A sitemap that listed pages but produced no delivery and no oversized page
	// means every fetch failed — a wholesale outage, not an empty site.
	if len(urls) > 0 && enqueued == 0 && oversized == 0 {
		return 0, w.NewError("crawl fetched none of the sitemap's pages")
	}
	// Pages too large for the ingest inbox cannot be delivered and the consumer
	// holds no credentials to re-fetch them; surface it instead of a clean sync.
	if oversized > 0 {
		return enqueued, w.NewError("%d crawled page(s) exceed the ingest payload limit", oversized)
	}

	if err := s.store.WithOrgTx(ctx, source.OrgID, func(ctx context.Context) error {
		return s.store.SetDatasourceSourceSynced(ctx, source.OrgID, source.ID, time.Now().UTC())
	}); err != nil {
		return enqueued, w.Wrapf(err, "record sync time")
	}
	return enqueued, nil
}

func (s *Service) enqueueCrawlerIngest(ctx context.Context, source *DatasourceSource, page crawler.Page) error {
	if source.BoundaryNodeID == "" {
		return wool.Get(ctx).NewError("datasource source has no resolvable boundary")
	}
	contentType := page.ContentType
	if contentType == "" {
		contentType = datasourceIngestContentType
	}
	digest := sha256.Sum256(page.Body)
	contentSHA := hex.EncodeToString(digest[:])
	_, err := s.datasourceJobs.EnqueueJob(ctx, &jobsv1.EnqueueJobRequest{
		Job: &jobsv1.NewJob{
			Direction:      jobsv1.JobDirection_JOB_DIRECTION_INBOX,
			Scope:          &jobsv1.JobScope{Value: &jobsv1.JobScope_Global{Global: true}},
			Queue:          datasourceIngestQueue,
			Topic:          datasourceCrawlerSyncTopic,
			Source:         datasourceCrawlerSyncSource,
			IdempotencyKey: crawlerIngestIdempotencyKey(source.ID, page.URL, contentSHA),
			SchemaVersion:  datasourceIngestSchemaVersion,
			Payload:        page.Body,
			ContentType:    contentType,
			MaxAttempts:    datasourceIngestMaxAttempts,
			Attributes: map[string]string{
				attrSourceID:          source.ID,
				attrOrgID:             source.OrgID,
				attrBoundaryID:        source.BoundaryNodeID,
				attrCrawlerURL:        page.URL,
				attrCrawlerContentSHA: contentSHA,
				attrChangeType:        changeTypeAdded,
			},
		},
	})
	return err
}

// crawlerIngestIdempotencyKey is deterministic in (source, url, content hash) and
// bounded: a re-crawl of an unchanged page dedupes to the stored delivery, while
// changed content at the same URL keys distinctly and is re-delivered.
func crawlerIngestIdempotencyKey(sourceID, pageURL, contentSHA string) string {
	digest := sha256.Sum256([]byte(sourceID + "\x00" + pageURL + "\x00" + contentSHA))
	return "datasource-crawler-sync/" + hex.EncodeToString(digest[:])
}

// runUploadSync lists the source's objects and fetches each one at a time,
// enqueuing an ingest delivery per object. Objects are streamed (never all held
// in memory); a listed object deleted before its fetch is skipped, an object too
// large to deliver is recorded and surfaced, and any real fetch failure (a
// permission or transport error) aborts the sync rather than reading as an empty
// bucket.
func (s *Service) runUploadSync(ctx context.Context, source *DatasourceSource) (int, error) {
	w := wool.Get(ctx).In("runUploadSync")
	if s.newUploadClient == nil {
		return 0, w.NewError("datasource connector is not configured")
	}
	if source.Upload == nil {
		return 0, w.NewError("upload source has no config")
	}

	secretKey, err := s.datasourceCipher.DecryptSecret(ctx, DatasourceConnectorSecretPurpose(source.ID), source.CredentialSecretRef)
	if err != nil {
		return 0, w.Wrapf(err, "decrypt secret access key")
	}
	client := s.newUploadClient(*source.Upload, secretKey)

	entries, err := client.List(ctx)
	if err != nil {
		return 0, w.Wrapf(err, "list objects")
	}

	enqueued := 0
	oversized := 0
	for _, entry := range entries {
		object, err := client.Fetch(ctx, entry.Key)
		if err != nil {
			if errors.Is(err, objectstore.ErrObjectNotFound) {
				// Deleted between listing and fetch; skip best-effort.
				w.Warn("skipping vanished object", wool.Field("key", entry.Key))
				continue
			}
			if errors.Is(err, objectstore.ErrObjectTooLarge) {
				oversized++
				continue
			}
			// A permission or transport failure must not read as an empty bucket:
			// surface it so the sync is retried and the misconfiguration is visible.
			return enqueued, w.Wrapf(err, "fetch %s", entry.Key)
		}
		if len(object.Body) > maxIngestPayload {
			oversized++
			continue
		}
		if err := s.enqueueUploadIngest(ctx, source, object, uploadFingerprint(object, entry)); err != nil {
			return enqueued, w.Wrapf(err, "enqueue %s", entry.Key)
		}
		enqueued++
	}

	// Objects too large for the ingest inbox cannot be delivered and the consumer
	// holds no credentials to re-fetch them; surface it instead of a clean sync.
	if oversized > 0 {
		return enqueued, w.NewError("%d object(s) exceed the ingest payload limit", oversized)
	}

	if err := s.store.WithOrgTx(ctx, source.OrgID, func(ctx context.Context) error {
		return s.store.SetDatasourceSourceSynced(ctx, source.OrgID, source.ID, time.Now().UTC())
	}); err != nil {
		return enqueued, w.Wrapf(err, "record sync time")
	}
	return enqueued, nil
}

// uploadFingerprint is the object's content fingerprint used to key delivery
// idempotency: the ETag from the GET response, else the ETag from the listing,
// else a hash of the body — so a re-pull of unchanged content always dedupes.
func uploadFingerprint(object objectstore.Object, entry objectstore.Entry) string {
	if object.ETag != "" {
		return object.ETag
	}
	if entry.ETag != "" {
		return entry.ETag
	}
	digest := sha256.Sum256(object.Body)
	return hex.EncodeToString(digest[:])
}

func (s *Service) enqueueUploadIngest(ctx context.Context, source *DatasourceSource, object objectstore.Object, fingerprint string) error {
	if source.BoundaryNodeID == "" {
		return wool.Get(ctx).NewError("datasource source has no resolvable boundary")
	}
	contentType := object.ContentType
	if contentType == "" {
		contentType = datasourceIngestContentType
	}
	_, err := s.datasourceJobs.EnqueueJob(ctx, &jobsv1.EnqueueJobRequest{
		Job: &jobsv1.NewJob{
			Direction:      jobsv1.JobDirection_JOB_DIRECTION_INBOX,
			Scope:          &jobsv1.JobScope{Value: &jobsv1.JobScope_Global{Global: true}},
			Queue:          datasourceIngestQueue,
			Topic:          datasourceUploadSyncTopic,
			Source:         datasourceUploadSyncSource,
			IdempotencyKey: uploadIngestIdempotencyKey(source.ID, object.Key, fingerprint),
			SchemaVersion:  datasourceIngestSchemaVersion,
			Payload:        object.Body,
			ContentType:    contentType,
			MaxAttempts:    datasourceIngestMaxAttempts,
			Attributes: map[string]string{
				attrSourceID:     source.ID,
				attrOrgID:        source.OrgID,
				attrBoundaryID:   source.BoundaryNodeID,
				attrUploadBucket: source.Upload.Bucket,
				attrUploadKey:    object.Key,
				attrUploadETag:   fingerprint,
				attrChangeType:   changeTypeAdded,
			},
		},
	})
	return err
}

// uploadIngestIdempotencyKey is deterministic in (source, key, fingerprint) and
// bounded: a re-pull of an unchanged object dedupes, while a changed object at
// the same key keys distinctly and is re-delivered.
func uploadIngestIdempotencyKey(sourceID, key, fingerprint string) string {
	digest := sha256.Sum256([]byte(sourceID + "\x00" + key + "\x00" + fingerprint))
	return "datasource-upload-sync/" + hex.EncodeToString(digest[:])
}

// NewDatasourceSyncJobHandler adapts RunDatasourceSync to the generic leased
// worker. Malformed routing is a permanent failure (safe to retain); a pull
// failure stays retryable so the framework retries past a transient GitHub
// outage or rate-limit window. A source deleted between request and lease is a
// no-op success.
func (s *Service) NewDatasourceSyncJobHandler() jobs.Handler {
	return func(ctx context.Context, envelope *jobsv1.JobEnvelope) error {
		if envelope.GetQueue() != DatasourceSyncRequestQueue || envelope.GetTopic() != datasourceSyncRequestTopic {
			return jobs.NewProcessingError("datasource.invalid_job", "unexpected datasource sync job routing", false)
		}
		sourceID := envelope.GetAttributes()[attrSourceID]
		if sourceID == "" {
			return jobs.NewProcessingError("datasource.invalid_job", "datasource sync job has no source id", false)
		}
		_, err := s.RunDatasourceSync(ctx, sourceID)
		switch {
		case err == nil, errors.Is(err, ErrDatasourceSourceNotFound):
			return nil
		case errors.Is(err, ErrOAuth2ReauthRequired):
			// The refresh token is permanently dead; replaying it can never
			// succeed, so fail the job terminally rather than burning retries.
			return jobs.NewProcessingError("datasource.oauth2_reauth_required", err.Error(), false)
		default:
			return err
		}
	}
}

// ingestIdempotencyKey is deterministic in (source, commit, path) and bounded,
// so an unbounded repo path cannot overflow the inbox idempotency column, a
// re-sync at an unchanged commit dedupes to the stored delivery, and a revert to
// earlier content under a new commit is delivered rather than dropped.
func ingestIdempotencyKey(sourceID, commit, path string) string {
	digest := sha256.Sum256([]byte(sourceID + "\x00" + commit + "\x00" + path))
	return "datasource-sync/" + hex.EncodeToString(digest[:])
}

// DatasourceSyncRetryDelay backs off a failed sync pull far enough that a
// retry outlasts GitHub's hourly rate-limit window before giving up.
func DatasourceSyncRetryDelay(attempt uint32) time.Duration {
	schedule := [...]time.Duration{
		5 * time.Second,
		30 * time.Second,
		2 * time.Minute,
		10 * time.Minute,
		30 * time.Minute,
		2 * time.Hour,
	}
	if attempt == 0 {
		return schedule[0]
	}
	index := int(attempt - 1)
	if index >= len(schedule) {
		index = len(schedule) - 1
	}
	return schedule[index]
}

func validRepo(repo string) bool {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok {
		return false
	}
	return owner != "" && name != "" && !strings.Contains(name, "/")
}

// normalizePaths trims, de-slashes, drops empties, and de-duplicates the path
// prefixes so the stored set and the GitHub tree filter agree.
func normalizePaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		p = strings.Trim(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
