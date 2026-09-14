package business_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"accounts/pkg/business"
	"accounts/pkg/datasource/apisource"
	"accounts/pkg/datasource/crawler"
	"accounts/pkg/datasource/github"
	"accounts/pkg/datasource/objectstore"
	gen "accounts/pkg/gen/saas/accounts/v1"
	jobsv1 "accounts/pkg/gen/saas/jobs/v1"
	"accounts/pkg/jobs"
)

// datasourceFakeStore is a partial fake: it embeds Store (panics on any
// unimplemented method) and keeps sources in memory keyed by id.
type datasourceFakeStore struct {
	business.Store
	mu          sync.Mutex
	sources     map[string]*business.DatasourceSource
	nodes       map[string]bool
	collections map[string]string // label -> node id
	ordinals    map[string]int64  // source id -> next ordinal to hand out

	// beforeInstallationMark, when set, runs just before a park is applied.
	beforeInstallationMark func(sourceID string)

	// GitHub App onboarding: setups keyed by state hash, and the one
	// organization each installation is claimed by.
	setups        map[string]*business.GitHubAppSetup
	setupConsumed map[string]bool
	installations map[string]string // installation id -> owning org id
}

func newDatasourceFakeStore() *datasourceFakeStore {
	return &datasourceFakeStore{
		sources:     map[string]*business.DatasourceSource{},
		nodes:       map[string]bool{},
		collections: map[string]string{},
		ordinals:    map[string]int64{},

		setups:        map[string]*business.GitHubAppSetup{},
		setupConsumed: map[string]bool{},
		installations: map[string]string{},
	}
}

func (f *datasourceFakeStore) InsertGitHubAppSetup(_ context.Context, setup *business.GitHubAppSetup) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *setup
	f.setups[setup.StateHash] = &cp
	return nil
}

// ConsumeGitHubAppSetup mirrors the store's compare-and-set: every rejection
// cause collapses to one error, and a state already consumed loses.
func (f *datasourceFakeStore) ConsumeGitHubAppSetup(_ context.Context, orgID, stateHash, initiatedBy string, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	setup, ok := f.setups[stateHash]
	if !ok || setup.OrgID != orgID || setup.InitiatedBy != initiatedBy ||
		f.setupConsumed[stateHash] || !now.Before(setup.ExpiresAt) {
		return business.ErrGitHubAppSetupRejected
	}
	f.setupConsumed[stateHash] = true
	return nil
}

func (f *datasourceFakeStore) ClaimGitHubAppInstallation(_ context.Context, installationID, orgID, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if owner, ok := f.installations[installationID]; ok {
		return owner == orgID, nil
	}
	f.installations[installationID] = orgID
	return true, nil
}

func (f *datasourceFakeStore) GitHubAppInstallationClaimedBy(_ context.Context, installationID, orgID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installations[installationID] == orgID, nil
}

func (f *datasourceFakeStore) RegisterScopeNode(_ context.Context, node *gen.ScopeNode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[node.Id] = true
	return nil
}

func (f *datasourceFakeStore) GetOrCreateCollectionNode(_ context.Context, node *gen.ScopeNode) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.collections[node.Label]; ok {
		return id, nil
	}
	f.nodes[node.Id] = true
	f.collections[node.Label] = node.Id
	return node.Id, nil
}

func (f *datasourceFakeStore) ScopeNodeExists(_ context.Context, id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nodes[id], nil
}

func (f *datasourceFakeStore) WithOrgTx(ctx context.Context, _ string, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func (f *datasourceFakeStore) InsertDatasourceSource(_ context.Context, source *business.DatasourceSource) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *source
	f.sources[source.ID] = &cp
	return nil
}

func (f *datasourceFakeStore) ListDatasourceSources(_ context.Context, orgID string) ([]*business.DatasourceSource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*business.DatasourceSource
	for _, s := range f.sources {
		if s.OrgID == orgID {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *datasourceFakeStore) GetDatasourceSource(_ context.Context, orgID, id string) (*business.DatasourceSource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sources[id]; ok && s.OrgID == orgID {
		cp := *s
		return &cp, nil
	}
	return nil, nil
}

func (f *datasourceFakeStore) GetDatasourceSourceByID(_ context.Context, id string) (*business.DatasourceSource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sources[id]; ok {
		cp := *s
		return &cp, nil
	}
	return nil, nil
}

func (f *datasourceFakeStore) DeleteDatasourceSource(_ context.Context, orgID, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sources[id]; ok && s.OrgID == orgID {
		delete(f.sources, id)
	}
	return nil
}

func (f *datasourceFakeStore) SetDatasourceSourceSynced(_ context.Context, orgID, id string, syncedAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sources[id]; ok && s.OrgID == orgID {
		at := syncedAt
		s.LastSyncedAt = &at
	}
	return nil
}

func (f *datasourceFakeStore) LockDatasourceSourceCredentialRef(_ context.Context, orgID, id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sources[id]; ok && s.OrgID == orgID {
		return s.CredentialSecretRef, nil
	}
	return "", errors.New("not found")
}

func (f *datasourceFakeStore) UpdateDatasourceSourceCredential(_ context.Context, orgID, id, credentialRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sources[id]; ok && s.OrgID == orgID {
		s.CredentialSecretRef = credentialRef
	}
	return nil
}

func (f *datasourceFakeStore) WithControlPlane(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func (f *datasourceFakeStore) AdvanceDatasourceCursor(_ context.Context, sourceID, commit, deliveryID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sources[sourceID]
	if !ok {
		return errors.New("not found")
	}
	s.LastIngestedCommit = commit
	s.LastDeliveryID = deliveryID
	now := time.Now().UTC()
	s.LastIngestedAt = &now
	if s.ReconcileInterval > 0 {
		next := now.Add(s.ReconcileInterval)
		s.NextReconcileAt = &next
	} else {
		s.NextReconcileAt = nil
	}
	return nil
}

func (f *datasourceFakeStore) AllocateDatasourceOrdinal(_ context.Context, sourceID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sources[sourceID]; !ok {
		return 0, errors.New("not found")
	}
	next := f.ordinals[sourceID]
	if next == 0 {
		next = 1 // matches the column DEFAULT 1
	}
	f.ordinals[sourceID] = next + 1
	return next, nil
}

func (f *datasourceFakeStore) BumpDatasourceReconcile(_ context.Context, sourceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sources[sourceID]
	if !ok {
		return errors.New("not found")
	}
	if s.ReconcileInterval > 0 {
		next := time.Now().UTC().Add(s.ReconcileInterval)
		s.NextReconcileAt = &next
	} else {
		s.NextReconcileAt = nil
	}
	return nil
}

func (f *datasourceFakeStore) MarkDatasourceSourceDegraded(_ context.Context, sourceID string, reason business.DatasourceDegradeReason) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sources[sourceID]
	if !ok {
		return errors.New("not found")
	}
	s.Status = business.DatasourceStatusDegraded
	s.StatusReason = reason.String()
	s.NextReconcileAt = nil
	return nil
}

func (f *datasourceFakeStore) ListDatasourceSourcesByGitHubInstallation(_ context.Context, installationID, afterID string, limit int) ([]*business.DatasourceSource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*business.DatasourceSource
	for _, s := range f.sources {
		// Mirror the query's provider filter: the column is only ever stamped by
		// a GitHub path, and another provider must never be parked for a GitHub
		// reason.
		if s.GitHubInstallationID != installationID || s.Provider != business.DatasourceProviderGitHub {
			continue
		}
		if afterID != "" && s.ID <= afterID {
			continue
		}
		cp := *s
		out = append(out, &cp)
	}
	// The real store orders and pages; map iteration does neither, and a caller
	// that reconciles sources in a different order each run is untestable.
	slices.SortFunc(out, func(a, b *business.DatasourceSource) int { return strings.Compare(a.ID, b.ID) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *datasourceFakeStore) pendingRecheck(reasons []string) []string {
	var out []string
	for _, s := range f.sources {
		if s.Status != business.DatasourceStatusDegraded || s.GitHubInstallationID == "" {
			continue
		}
		if !slices.Contains(reasons, s.StatusReason) || slices.Contains(out, s.GitHubInstallationID) {
			continue
		}
		out = append(out, s.GitHubInstallationID)
	}
	slices.Sort(out)
	return out
}

func (f *datasourceFakeStore) CountGitHubInstallationsPendingRecheck(_ context.Context, reasons []string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pendingRecheck(reasons)), nil
}

func (f *datasourceFakeStore) ListGitHubInstallationsPendingRecheck(_ context.Context, reasons []string, offset, limit int) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.pendingRecheck(reasons)
	if offset >= len(out) {
		return nil, nil
	}
	out = out[offset:]
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *datasourceFakeStore) SetDatasourceSourceGitHubInstallation(_ context.Context, orgID, id, installationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sources[id]; ok && s.OrgID == orgID {
		s.GitHubInstallationID = installationID
	}
	return nil
}

// Mirrors the store's predicate: writes over 'active' or over one of the App
// path's own reasons, never over an operator pause or another path's degrade,
// and only when the reason actually changes.
//
// beforeInstallationMark runs immediately before the write, holding no lock, so
// a test can stand in for the operator pause or compiler degrade that can land
// between the reconciler's page read and its write.
func (f *datasourceFakeStore) MarkDatasourceSourceInstallationDegraded(_ context.Context, sourceID, reason string, reasons []string) (bool, error) {
	if f.beforeInstallationMark != nil {
		f.beforeInstallationMark(sourceID)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sources[sourceID]
	if !ok {
		return false, errors.New("not found")
	}
	if s.StatusReason == reason {
		return false, nil
	}
	owned := s.Status == business.DatasourceStatusDegraded && slices.Contains(reasons, s.StatusReason)
	if s.Status != business.DatasourceStatusActive && !owned {
		return false, nil
	}
	s.Status = business.DatasourceStatusDegraded
	s.StatusReason = reason
	s.NextReconcileAt = nil
	return true, nil
}

func (f *datasourceFakeStore) ClearDatasourceSourceInstallationDegraded(_ context.Context, sourceID string, reasons []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sources[sourceID]
	if !ok {
		return "", errors.New("not found")
	}
	// Mirror the store's status+reason guard: a source degraded for a reason
	// this path did not write keeps both its status and its reason.
	if s.Status != business.DatasourceStatusDegraded || !slices.Contains(reasons, s.StatusReason) {
		return "", nil
	}
	cleared := s.StatusReason
	s.Status = business.DatasourceStatusActive
	s.StatusReason = ""
	if s.ReconcileInterval > 0 {
		next := time.Now().UTC().Add(s.ReconcileInterval)
		s.NextReconcileAt = &next
	} else {
		s.NextReconcileAt = nil
	}
	return cleared, nil
}

func (f *datasourceFakeStore) ClearDatasourceSourceDegraded(_ context.Context, sourceID string, excludeReasons []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sources[sourceID]
	if !ok {
		return errors.New("not found")
	}
	// Mirror the store's status='degraded' guard: only a degraded row is revived,
	// so a paused source is left untouched.
	if s.Status != business.DatasourceStatusDegraded {
		return nil
	}
	// Mirror the store's exclusion: a degrade another path owns is not this
	// path's to lift.
	if slices.Contains(excludeReasons, s.StatusReason) {
		return nil
	}
	s.Status = business.DatasourceStatusActive
	s.StatusReason = ""
	if s.ReconcileInterval > 0 {
		next := time.Now().UTC().Add(s.ReconcileInterval)
		s.NextReconcileAt = &next
	} else {
		s.NextReconcileAt = nil
	}
	return nil
}

func (f *datasourceFakeStore) ListDatasourceSourcesDueForReconcile(_ context.Context, now time.Time, limit int) ([]*business.DatasourceSource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*business.DatasourceSource
	for _, s := range f.sources {
		if s.Status != business.DatasourceStatusActive || s.Provider != business.DatasourceProviderGitHub {
			continue
		}
		if s.NextReconcileAt == nil || s.NextReconcileAt.After(now) {
			continue
		}
		cp := *s
		out = append(out, &cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// purposeCipher is a deterministic, purpose-binding fake: the envelope embeds
// the purpose, so DecryptSecret fails closed if replayed under a different one —
// mirroring the Vault-transit binding the real cipher enforces.
type purposeCipher struct{}

func (purposeCipher) EncryptSecret(_ context.Context, purpose, plaintext string) (string, error) {
	return "enc:" + purpose + ":" + plaintext, nil
}

func (purposeCipher) DecryptSecret(_ context.Context, purpose, envelope string) (string, error) {
	rest, ok := strings.CutPrefix(envelope, "enc:"+purpose+":")
	if !ok {
		return "", errors.New("purpose mismatch")
	}
	return rest, nil
}

// recordingProducer captures every enqueue for assertions.
type recordingProducer struct {
	mu   sync.Mutex
	jobs []*jobsv1.NewJob
}

func (p *recordingProducer) EnqueueJob(_ context.Context, req *jobsv1.EnqueueJobRequest) (*jobsv1.EnqueueJobResponse, error) {
	// Enforce the same command contract the real producer does — PostgresJobStore
	// validates through jobs.EnqueueFingerprint before a statement is ever sent —
	// so a job this package builds that violates saas.jobs.v1 fails the test
	// instead of silently "queuing". Without this, a producer missing a field the
	// platform requires passes every test here and is refused in production; that
	// is exactly how the sync and reconcile requests shipped with no content type.
	// Matches fakeJobProducer in pkg/datasource and pkg/billing.
	if err := jobs.ValidateCommand(req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jobs = append(p.jobs, req.GetJob())
	return &jobsv1.EnqueueJobResponse{
		JobId:       "job",
		Disposition: jobsv1.JobEnqueueDisposition_JOB_ENQUEUE_DISPOSITION_INSERTED,
	}, nil
}

// fakeGitHub returns fixed repository contents without a live api.github.com.
// A path mapped to a nil (absent) content entry surfaces the error errs[path].
type fakeGitHub struct {
	defaultBranch string
	commit        string
	files         []github.File
	content       map[string][]byte
	errs          map[string]error
	compareFn     func(base, head string) (*github.Comparison, error)
	blobs         map[string][]byte
	blobErrs      map[string]error
}

func (f *fakeGitHub) DefaultBranch(context.Context, string) (string, error) {
	return f.defaultBranch, nil
}
func (f *fakeGitHub) ResolveCommit(context.Context, string, string) (string, error) {
	return f.commit, nil
}
func (f *fakeGitHub) ListFiles(context.Context, string, string, []string) ([]github.File, error) {
	return f.files, nil
}
func (f *fakeGitHub) GetFileContent(_ context.Context, _, _, path string) ([]byte, error) {
	if err, ok := f.errs[path]; ok {
		return nil, err
	}
	if content, ok := f.content[path]; ok {
		return content, nil
	}
	return nil, github.ErrNotFound
}
func (f *fakeGitHub) Compare(_ context.Context, _, base, head string) (*github.Comparison, error) {
	if f.compareFn != nil {
		return f.compareFn(base, head)
	}
	return nil, errors.New("compare not configured")
}
func (f *fakeGitHub) GetBlob(_ context.Context, _, blobSHA string, _ int64) ([]byte, error) {
	if err, ok := f.blobErrs[blobSHA]; ok {
		return nil, err
	}
	if b, ok := f.blobs[blobSHA]; ok {
		return b, nil
	}
	return nil, github.ErrNotFound
}

// recordingAudit captures emitted audit entries so a test can assert an RPC
// actually produces the audit event its policy declares.
type recordingAudit struct {
	mu      sync.Mutex
	entries []business.AuditEntry
}

func (a *recordingAudit) Emit(_ context.Context, entry business.AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, entry)
}

// EmitTx satisfies business.TxAuditEmitter: a double that only implemented the
// fire-and-forget half would make every security write it is wired behind fail
// closed instead of exercising the path under test.
func (a *recordingAudit) EmitTx(ctx context.Context, entry business.AuditEntry) error {
	a.Emit(ctx, entry)
	return nil
}

// entriesOf returns every recorded entry of one type, so a test can assert the
// payload a producer wrote and not merely that it emitted something.
func (a *recordingAudit) entriesOf(event business.EventType) []business.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []business.AuditEntry
	for _, e := range a.entries {
		if e.EventType == event {
			out = append(out, e)
		}
	}
	return out
}

func (a *recordingAudit) types() []business.EventType {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]business.EventType, len(a.entries))
	for i, e := range a.entries {
		out[i] = e.EventType
	}
	return out
}

func newDatasourceService(store business.Store, producer *recordingProducer, gh business.GitHubContentClient) (*business.Service, *recordingAudit) {
	svc, _ := business.NewService(store)
	svc.SetDatasourceConnector(purposeCipher{}, producer, "")
	audit := &recordingAudit{}
	svc.SetAuditEmitter(audit)
	if gh == nil {
		gh = &fakeGitHub{defaultBranch: "main", commit: "abc"}
	}
	if gh != nil {
		svc.SetDatasourceGitHubClientFactory(func(string) business.GitHubContentClient { return gh })
	}
	return svc, audit
}

const testOrg = "11111111-1111-1111-1111-111111111111"

func addSource(t *testing.T, svc *business.Service, in business.AddGitHubSourceInput) *business.DatasourceSource {
	t.Helper()
	source, err := svc.AddGitHubSource(context.Background(), "actor-1", in)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestAddGitHubSource_EncryptsPerSourceAndOmitsSecrets(t *testing.T) {
	svc, audit := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)

	source := addSource(t, svc, business.AddGitHubSourceInput{
		OrgID:           testOrg,
		Repo:            "acme/docs",
		Paths:           []string{"docs", "docs"}, // duplicate is normalized away
		CollectionLabel: "wiki",
		AccessToken:     "ghp_secret",
		WebhookSecret:   "whsec",
	})
	if source.Provider != business.DatasourceProviderGitHub || source.Status != business.DatasourceStatusActive {
		t.Fatalf("provider/status = %q/%q", source.Provider, source.Status)
	}
	if len(source.Paths) != 1 || source.Paths[0] != "docs" {
		t.Fatalf("paths = %v, want [docs]", source.Paths)
	}
	// The stored envelopes are bound to this source id's purposes.
	wantCred := "enc:" + business.DatasourceConnectorSecretPurpose(source.ID) + ":ghp_secret"
	wantHook := "enc:" + business.DatasourceWebhookSecretPurpose(source.ID) + ":whsec"
	if source.CredentialSecretRef != wantCred {
		t.Fatalf("credential ref = %q, want %q", source.CredentialSecretRef, wantCred)
	}
	if source.WebhookSecretRef != wantHook || !source.WebhookConfigured() {
		t.Fatalf("webhook ref = %q, configured=%v", source.WebhookSecretRef, source.WebhookConfigured())
	}
	// The RPC's declared audit event must actually be emitted.
	if got := audit.types(); len(got) != 1 || got[0] != business.EventDatasourceSourceAdded {
		t.Fatalf("audit events = %v, want [%s]", got, business.EventDatasourceSourceAdded)
	}
}

func TestAddGitHubSource_Validation(t *testing.T) {
	svc, _ := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)
	base := business.AddGitHubSourceInput{OrgID: testOrg, Repo: "acme/docs", CollectionLabel: "wiki", AccessToken: "t"}
	cases := map[string]business.AddGitHubSourceInput{
		"missing repo":       {OrgID: testOrg, CollectionLabel: "wiki", AccessToken: "t"},
		"bad repo":           mut(base, func(i *business.AddGitHubSourceInput) { i.Repo = "not-a-repo" }),
		"missing collection": mut(base, func(i *business.AddGitHubSourceInput) { i.CollectionLabel = "" }),
		"missing token":      mut(base, func(i *business.AddGitHubSourceInput) { i.AccessToken = "" }),
	}
	for name, in := range cases {
		if _, err := svc.AddGitHubSource(context.Background(), "actor-1", in); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func TestResolveWebhookSource_ResolvesPerSource(t *testing.T) {
	svc, _ := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)

	withHook := addSource(t, svc, business.AddGitHubSourceInput{
		OrgID: testOrg, Repo: "acme/docs", CollectionLabel: "wiki", AccessToken: "t", WebhookSecret: "whsec",
	})
	resolved, err := svc.ResolveWebhookSource(context.Background(), withHook.ID)
	if err != nil || resolved.SigningSecret != "whsec" {
		t.Fatalf("ResolveWebhookSource secret = %q, %v; want whsec", resolved.SigningSecret, err)
	}
	// The receiver stamps the tenant/boundary from this attribution.
	if resolved.OrgID != testOrg || resolved.BoundaryID != withHook.BoundaryNodeID {
		t.Fatalf("attribution = %+v, want org %s boundary %s", resolved, testOrg, withHook.BoundaryNodeID)
	}

	noHook := addSource(t, svc, business.AddGitHubSourceInput{
		OrgID: testOrg, Repo: "acme/other", CollectionLabel: "wiki", AccessToken: "t",
	})
	if _, err := svc.ResolveWebhookSource(context.Background(), noHook.ID); !errors.Is(err, business.ErrDatasourceSourceNotFound) {
		t.Fatalf("unconfigured source: err = %v, want ErrDatasourceSourceNotFound", err)
	}
	if _, err := svc.ResolveWebhookSource(context.Background(), "unknown"); !errors.Is(err, business.ErrDatasourceSourceNotFound) {
		t.Fatalf("unknown source: err = %v, want ErrDatasourceSourceNotFound", err)
	}
}

// TestSyncDatasourceSource_GitHubSchedulesForcedSnapshot proves "Sync now" for a
// GitHub source does NOT pull inline: it enqueues exactly one forced reconcile
// job on the delivery queue (keyed for per-source ordering), emits the sync audit
// event, and returns the job id.
func TestSyncDatasourceSource_GitHubSchedulesForcedSnapshot(t *testing.T) {
	producer := &recordingProducer{}
	svc, audit := newDatasourceService(newDatasourceFakeStore(), producer, &fakeGitHub{})
	source := addSource(t, svc, business.AddGitHubSourceInput{
		OrgID: testOrg, Repo: "acme/docs", CollectionLabel: "wiki", AccessToken: "t",
	})

	jobID, err := svc.SyncDatasourceSource(context.Background(), "actor-1", testOrg, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if jobID != "job" {
		t.Fatalf("job id = %q, want the enqueued job id", jobID)
	}
	if len(producer.jobs) != 1 {
		t.Fatalf("enqueued %d jobs, want exactly 1 reconcile request (no inline pull)", len(producer.jobs))
	}
	job := producer.jobs[0]
	if job.GetQueue() != business.DatasourceDeliveryQueue {
		t.Fatalf("queue = %q, want %q", job.GetQueue(), business.DatasourceDeliveryQueue)
	}
	if job.GetAttributes()["datasource.reconcile_mode"] != "force" {
		t.Fatalf("reconcile mode = %q, want force", job.GetAttributes()["datasource.reconcile_mode"])
	}
	// The job platform validates content_type (min_len 1) on every enqueue; a
	// request job that carries only attributes still has to declare one, or
	// Sync now is refused by the platform before the reconcile is ever scheduled.
	if job.GetContentType() != "application/json" || string(job.GetPayload()) != "{}" {
		t.Fatalf("sync request body = %q/%q, want an empty JSON object; the platform refuses an undeclared content type and job_messages.payload is NOT NULL",
			job.GetContentType(), job.GetPayload())
	}
	// A reconcile request is a control message, not a change set. Advertising the
	// change-set version over an empty body would describe `{}` as a v2 per-file
	// payload to anything that decodes on (schema_version, content_type).
	if job.GetSchemaVersion() != 1 {
		t.Fatalf("schema version = %d, want the reconcile request's (1), not the change set's (2)", job.GetSchemaVersion())
	}
	if job.GetOrdering().GetNamespace() != "datasource.delivery" ||
		len(job.GetOrdering().GetComponents()) != 1 || job.GetOrdering().GetComponents()[0] != source.ID {
		t.Fatalf("ordering key = %v, want per-source", job.GetOrdering())
	}
	got := audit.types()
	if len(got) == 0 || got[len(got)-1] != business.EventDatasourceSourceSynced {
		t.Fatalf("audit events = %v, want last = %s", got, business.EventDatasourceSourceSynced)
	}
}

func mut(in business.AddGitHubSourceInput, f func(*business.AddGitHubSourceInput)) business.AddGitHubSourceInput {
	f(&in)
	return in
}

// fakeAPIClient returns a fixed API fetch result without a live endpoint.
type fakeAPIClient struct {
	result *apisource.Result
	err    error
	calls  int
}

func (f *fakeAPIClient) Fetch(context.Context) (*apisource.Result, error) {
	f.calls++
	return f.result, f.err
}

func apiConfig() *business.APIDatasourceConfig {
	return &business.APIDatasourceConfig{
		BaseURL:        "https://api.example.com",
		ResourcePath:   "/v1/docs",
		CredentialKind: business.APICredentialKindBearer,
	}
}

func TestAddSource_APIStoresConfigAndEncryptsCredential(t *testing.T) {
	svc, audit := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)

	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID:           testOrg,
		Provider:        business.DatasourceProviderAPI,
		CollectionLabel: "wiki",
		Credential:      "sekret",
		API:             apiConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if source.Provider != business.DatasourceProviderAPI || source.Status != business.DatasourceStatusActive {
		t.Fatalf("provider/status = %q/%q", source.Provider, source.Status)
	}
	if source.Repo != "" {
		t.Fatalf("api source must have no repo, got %q", source.Repo)
	}
	if source.API == nil || source.API.BaseURL != "https://api.example.com" ||
		source.API.CredentialKind != business.APICredentialKindBearer {
		t.Fatalf("api config = %+v", source.API)
	}
	wantCred := "enc:" + business.DatasourceConnectorSecretPurpose(source.ID) + ":sekret"
	if source.CredentialSecretRef != wantCred {
		t.Fatalf("credential ref = %q, want %q", source.CredentialSecretRef, wantCred)
	}
	if source.WebhookConfigured() {
		t.Fatal("api source must not be webhook-configured")
	}
	if got := audit.types(); len(got) != 1 || got[0] != business.EventDatasourceSourceAdded {
		t.Fatalf("audit events = %v", got)
	}
}

func TestAddSource_APIRejectsWebhookSecret(t *testing.T) {
	svc, _ := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)
	_, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID: testOrg, Provider: business.DatasourceProviderAPI, CollectionLabel: "wiki",
		Credential: "sekret", API: apiConfig(), WebhookSecret: "whsec",
	})
	if err == nil {
		t.Fatal("api provider must reject a webhook secret it cannot verify")
	}
}

func TestAddSource_Validation(t *testing.T) {
	svc, _ := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)
	base := business.AddSourceInput{OrgID: testOrg, Provider: business.DatasourceProviderAPI, CollectionLabel: "wiki", Credential: "c", API: apiConfig()}
	cases := map[string]business.AddSourceInput{
		"missing credential":  {OrgID: testOrg, Provider: business.DatasourceProviderAPI, CollectionLabel: "wiki", API: apiConfig()},
		"missing collection":  {OrgID: testOrg, Provider: business.DatasourceProviderAPI, Credential: "c", API: apiConfig()},
		"unknown provider":    {OrgID: testOrg, Provider: "gitlab", CollectionLabel: "wiki", Credential: "c"},
		"api without config":  {OrgID: testOrg, Provider: business.DatasourceProviderAPI, CollectionLabel: "wiki", Credential: "c"},
		"github without repo": {OrgID: testOrg, Provider: business.DatasourceProviderGitHub, CollectionLabel: "wiki", Credential: "c"},
	}
	cases["bad base url"] = withAPI(base, func(c *business.APIDatasourceConfig) { c.BaseURL = "ftp://x" })
	cases["bad credential kind"] = withAPI(base, func(c *business.APIDatasourceConfig) { c.CredentialKind = "oauth" })
	cases["header kind without header"] = withAPI(base, func(c *business.APIDatasourceConfig) {
		c.CredentialKind = business.APICredentialKindHeader
	})
	cases["query kind without param"] = withAPI(base, func(c *business.APIDatasourceConfig) {
		c.CredentialKind = business.APICredentialKindQuery
	})
	cases["oauth2 kind without config"] = withAPI(base, func(c *business.APIDatasourceConfig) {
		c.CredentialKind = business.APICredentialKindOAuth2
	})
	cases["oauth2 bad token url"] = withAPI(base, func(c *business.APIDatasourceConfig) {
		c.CredentialKind = business.APICredentialKindOAuth2
		c.OAuth2 = &business.APIOAuth2Config{TokenURL: "ftp://x", ClientID: "id"}
	})
	cases["oauth2 missing client id"] = withAPI(base, func(c *business.APIDatasourceConfig) {
		c.CredentialKind = business.APICredentialKindOAuth2
		c.OAuth2 = &business.APIOAuth2Config{TokenURL: "https://oauth.example.com/token"}
	})
	for name, in := range cases {
		if _, err := svc.AddSource(context.Background(), "actor-1", in); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func withAPI(in business.AddSourceInput, f func(*business.APIDatasourceConfig)) business.AddSourceInput {
	cfg := *in.API
	f(&cfg)
	in.API = &cfg
	return in
}

func TestAddSource_GitHubBranchThroughGenericCall(t *testing.T) {
	svc, _ := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)
	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID: testOrg, Provider: business.DatasourceProviderGitHub, CollectionLabel: "wiki",
		Credential: "ghp", Repo: "acme/docs", Branch: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	if source.Provider != business.DatasourceProviderGitHub || source.Repo != "acme/docs" || source.Branch != "main" {
		t.Fatalf("github source = %+v", source)
	}
}

// fakeCrawlerClient serves fixed pages without a live website, driven one URL at
// a time. fetchErr injects a per-URL error (e.g. crawler.ErrPageTooLarge or a
// generic failure); listErr fails the listing.
type fakeCrawlerClient struct {
	pages      []crawler.Page
	fetchErr   map[string]error
	listErr    error
	listCalls  int
	fetchCalls int
}

func (f *fakeCrawlerClient) List(context.Context) ([]string, error) {
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	urls := make([]string, len(f.pages))
	for i, p := range f.pages {
		urls[i] = p.URL
	}
	return urls, nil
}

func (f *fakeCrawlerClient) Fetch(_ context.Context, pageURL string) (crawler.Page, error) {
	f.fetchCalls++
	if err := f.fetchErr[pageURL]; err != nil {
		return crawler.Page{}, err
	}
	for _, p := range f.pages {
		if p.URL == pageURL {
			return p, nil
		}
	}
	return crawler.Page{}, errors.New("unknown page")
}

// fakeUploadClient serves fixed objects without a live object store, driven one
// key at a time. fetchErr injects a per-key error (e.g. objectstore.ErrObjectNotFound,
// objectstore.ErrObjectTooLarge, or a generic failure); listErr fails the listing.
type fakeUploadClient struct {
	entries    []objectstore.Entry
	objects    map[string]objectstore.Object
	fetchErr   map[string]error
	listErr    error
	listCalls  int
	fetchCalls int
}

func (f *fakeUploadClient) List(context.Context) ([]objectstore.Entry, error) {
	f.listCalls++
	return f.entries, f.listErr
}

func (f *fakeUploadClient) Fetch(_ context.Context, key string) (objectstore.Object, error) {
	f.fetchCalls++
	if err := f.fetchErr[key]; err != nil {
		return objectstore.Object{}, err
	}
	return f.objects[key], nil
}

func crawlerConfig() *business.CrawlerDatasourceConfig {
	return &business.CrawlerDatasourceConfig{SitemapURL: "https://docs.example.com/sitemap.xml"}
}

func uploadConfig() *business.UploadDatasourceConfig {
	return &business.UploadDatasourceConfig{
		Endpoint:    "https://s3.us-east-1.amazonaws.com",
		Region:      "us-east-1",
		Bucket:      "docs",
		Prefix:      "kb/",
		AccessKeyID: "AKIAEXAMPLE",
	}
}

func TestAddSource_CrawlerStoresConfigAndTakesNoCredential(t *testing.T) {
	svc, audit := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)

	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID:           testOrg,
		Provider:        business.DatasourceProviderCrawler,
		CollectionLabel: "wiki",
		Crawler:         crawlerConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if source.Provider != business.DatasourceProviderCrawler || source.Crawler == nil ||
		source.Crawler.SitemapURL != "https://docs.example.com/sitemap.xml" {
		t.Fatalf("crawler source = %+v", source)
	}
	if source.CredentialSecretRef != "" {
		t.Fatalf("crawler must store no credential, got %q", source.CredentialSecretRef)
	}
	if source.WebhookConfigured() {
		t.Fatal("crawler must not be webhook-configured")
	}
	if got := audit.types(); len(got) != 1 || got[0] != business.EventDatasourceSourceAdded {
		t.Fatalf("audit events = %v", got)
	}
}

func TestAddSource_UploadStoresConfigAndEncryptsSecretKey(t *testing.T) {
	svc, _ := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)

	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID:           testOrg,
		Provider:        business.DatasourceProviderUpload,
		CollectionLabel: "wiki",
		Credential:      "secretkey",
		Upload:          uploadConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if source.Upload == nil || source.Upload.Bucket != "docs" || source.Upload.AccessKeyID != "AKIAEXAMPLE" {
		t.Fatalf("upload config = %+v", source.Upload)
	}
	wantCred := "enc:" + business.DatasourceConnectorSecretPurpose(source.ID) + ":secretkey"
	if source.CredentialSecretRef != wantCred {
		t.Fatalf("credential ref = %q, want %q", source.CredentialSecretRef, wantCred)
	}
}

func TestAddSource_NewProviderValidation(t *testing.T) {
	svc, _ := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)
	cases := map[string]business.AddSourceInput{
		"crawler without config": {OrgID: testOrg, Provider: business.DatasourceProviderCrawler, CollectionLabel: "wiki"},
		"crawler bad sitemap": {OrgID: testOrg, Provider: business.DatasourceProviderCrawler, CollectionLabel: "wiki",
			Crawler: &business.CrawlerDatasourceConfig{SitemapURL: "ftp://x"}},
		"crawler with credential": {OrgID: testOrg, Provider: business.DatasourceProviderCrawler, CollectionLabel: "wiki",
			Credential: "nope", Crawler: crawlerConfig()},
		"crawler with webhook": {OrgID: testOrg, Provider: business.DatasourceProviderCrawler, CollectionLabel: "wiki",
			WebhookSecret: "whsec", Crawler: crawlerConfig()},
		"upload without config": {OrgID: testOrg, Provider: business.DatasourceProviderUpload, CollectionLabel: "wiki", Credential: "c"},
		"upload without credential": {OrgID: testOrg, Provider: business.DatasourceProviderUpload, CollectionLabel: "wiki",
			Upload: uploadConfig()},
		"upload bad endpoint": {OrgID: testOrg, Provider: business.DatasourceProviderUpload, CollectionLabel: "wiki", Credential: "c",
			Upload: &business.UploadDatasourceConfig{Endpoint: "ftp://x", Region: "us-east-1", Bucket: "b", AccessKeyID: "k"}},
		"upload missing region": {OrgID: testOrg, Provider: business.DatasourceProviderUpload, CollectionLabel: "wiki", Credential: "c",
			Upload: &business.UploadDatasourceConfig{Endpoint: "https://s3.example.com", Bucket: "b", AccessKeyID: "k"}},
		"upload with webhook": {OrgID: testOrg, Provider: business.DatasourceProviderUpload, CollectionLabel: "wiki", Credential: "c",
			WebhookSecret: "whsec", Upload: uploadConfig()},
	}
	for name, in := range cases {
		if _, err := svc.AddSource(context.Background(), "actor-1", in); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func newCrawlerSource(t *testing.T, svc *business.Service) *business.DatasourceSource {
	t.Helper()
	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID: testOrg, Provider: business.DatasourceProviderCrawler, CollectionLabel: "wiki", Crawler: crawlerConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func newUploadSource(t *testing.T, svc *business.Service) *business.DatasourceSource {
	t.Helper()
	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID: testOrg, Provider: business.DatasourceProviderUpload, CollectionLabel: "wiki",
		Credential: "secretkey", Upload: uploadConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestRunDatasourceSync_CrawlerStreamsPerPage(t *testing.T) {
	producer := &recordingProducer{}
	svc, _ := newDatasourceService(newDatasourceFakeStore(), producer, nil)
	fake := &fakeCrawlerClient{pages: []crawler.Page{
		{URL: "https://docs.example.com/a", Body: []byte("A"), ContentType: "text/html"},
		{URL: "https://docs.example.com/b", Body: []byte("B"), ContentType: "text/html"},
	}}
	svc.SetDatasourceCrawlerClientFactory(func(business.CrawlerDatasourceConfig) business.CrawlerContentClient { return fake })
	source := newCrawlerSource(t, svc)

	enqueued, err := svc.RunDatasourceSync(context.Background(), source.ID)
	if err != nil {
		t.Fatal(err)
	}
	// One List then one Fetch per page — the whole site is never materialized.
	if enqueued != 2 || len(producer.jobs) != 2 || fake.listCalls != 1 || fake.fetchCalls != 2 {
		t.Fatalf("enqueued=%d jobs=%d list=%d fetch=%d, want 2/2/1/2", enqueued, len(producer.jobs), fake.listCalls, fake.fetchCalls)
	}
	job := producer.jobs[0]
	if job.GetTopic() != "datasource.crawler.sync" || !job.GetScope().GetGlobal() {
		t.Fatalf("topic=%q scope=%v", job.GetTopic(), job.GetScope())
	}
	if string(job.GetPayload()) != "A" || job.GetContentType() != "text/html" {
		t.Fatalf("payload=%q type=%q", job.GetPayload(), job.GetContentType())
	}
	attrs := job.GetAttributes()
	if attrs["datasource.source_id"] != source.ID || attrs["datasource.org_id"] != testOrg ||
		attrs["crawler.url"] != "https://docs.example.com/a" || attrs["crawler.content_sha"] == "" ||
		attrs["datasource.boundary_id"] == "" || attrs["datasource.boundary_id"] != source.BoundaryNodeID {
		t.Fatalf("attributes = %v", attrs)
	}
	if producer.jobs[0].GetIdempotencyKey() == producer.jobs[1].GetIdempotencyKey() {
		t.Fatal("idempotency keys collided across pages")
	}
}

// A page too large to deliver must surface as a sync error (the good pages still
// enqueue), never a silent drop reported as success.
func TestRunDatasourceSync_CrawlerSurfacesOversizedPage(t *testing.T) {
	producer := &recordingProducer{}
	svc, _ := newDatasourceService(newDatasourceFakeStore(), producer, nil)
	fake := &fakeCrawlerClient{
		pages: []crawler.Page{
			{URL: "https://docs.example.com/small", Body: []byte("ok"), ContentType: "text/html"},
			{URL: "https://docs.example.com/huge"},
		},
		fetchErr: map[string]error{"https://docs.example.com/huge": crawler.ErrPageTooLarge},
	}
	svc.SetDatasourceCrawlerClientFactory(func(business.CrawlerDatasourceConfig) business.CrawlerContentClient { return fake })
	source := newCrawlerSource(t, svc)

	enqueued, err := svc.RunDatasourceSync(context.Background(), source.ID)
	if err == nil {
		t.Fatal("an oversized page must surface as an error, not a silent success")
	}
	if enqueued != 1 || len(producer.jobs) != 1 {
		t.Fatalf("the deliverable page must still enqueue: enqueued=%d jobs=%d", enqueued, len(producer.jobs))
	}
}

// A sitemap whose every page fails to fetch must fail the sync, not record an
// empty success that looks like a healthy but contentless site.
func TestRunDatasourceSync_CrawlerWholesaleFailureIsNotEmptySuccess(t *testing.T) {
	producer := &recordingProducer{}
	svc, _ := newDatasourceService(newDatasourceFakeStore(), producer, nil)
	fake := &fakeCrawlerClient{
		pages: []crawler.Page{{URL: "https://docs.example.com/a"}, {URL: "https://docs.example.com/b"}},
		fetchErr: map[string]error{
			"https://docs.example.com/a": errors.New("timeout"),
			"https://docs.example.com/b": errors.New("timeout"),
		},
	}
	svc.SetDatasourceCrawlerClientFactory(func(business.CrawlerDatasourceConfig) business.CrawlerContentClient { return fake })
	source := newCrawlerSource(t, svc)

	if _, err := svc.RunDatasourceSync(context.Background(), source.ID); err == nil {
		t.Fatal("a crawl that reached no page must fail, not report an empty success")
	}
	if len(producer.jobs) != 0 {
		t.Fatalf("no deliveries expected, got %d", len(producer.jobs))
	}
}

func TestRunDatasourceSync_UploadStreamsPerObject(t *testing.T) {
	producer := &recordingProducer{}
	svc, _ := newDatasourceService(newDatasourceFakeStore(), producer, nil)
	var gotSecret string
	fake := &fakeUploadClient{
		entries: []objectstore.Entry{{Key: "kb/a.pdf", ETag: "etag-a"}, {Key: "kb/b.pdf", ETag: "etag-b"}},
		objects: map[string]objectstore.Object{
			"kb/a.pdf": {Key: "kb/a.pdf", Body: []byte("PDFA"), ContentType: "application/pdf", ETag: "etag-a"},
			"kb/b.pdf": {Key: "kb/b.pdf", Body: []byte("PDFB"), ContentType: "application/pdf", ETag: "etag-b"},
		},
	}
	svc.SetDatasourceUploadClientFactory(func(_ business.UploadDatasourceConfig, secret string) business.UploadContentClient {
		gotSecret = secret
		return fake
	})
	source := newUploadSource(t, svc)

	enqueued, err := svc.RunDatasourceSync(context.Background(), source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if enqueued != 2 || len(producer.jobs) != 2 || fake.listCalls != 1 || fake.fetchCalls != 2 {
		t.Fatalf("enqueued=%d jobs=%d list=%d fetch=%d, want 2/2/1/2", enqueued, len(producer.jobs), fake.listCalls, fake.fetchCalls)
	}
	if gotSecret != "secretkey" {
		t.Fatalf("secret handed to connector = %q, want the decrypted secret key", gotSecret)
	}
	job := producer.jobs[0]
	if job.GetTopic() != "datasource.upload.sync" || !job.GetScope().GetGlobal() {
		t.Fatalf("topic=%q scope=%v", job.GetTopic(), job.GetScope())
	}
	if string(job.GetPayload()) != "PDFA" || job.GetContentType() != "application/pdf" {
		t.Fatalf("payload=%q type=%q", job.GetPayload(), job.GetContentType())
	}
	attrs := job.GetAttributes()
	if attrs["datasource.source_id"] != source.ID || attrs["upload.bucket"] != "docs" ||
		attrs["upload.key"] != "kb/a.pdf" || attrs["upload.etag"] != "etag-a" ||
		attrs["datasource.boundary_id"] == "" || attrs["datasource.boundary_id"] != source.BoundaryNodeID {
		t.Fatalf("attributes = %v", attrs)
	}
	if producer.jobs[0].GetIdempotencyKey() == producer.jobs[1].GetIdempotencyKey() {
		t.Fatal("idempotency keys collided across objects")
	}
}

// A permission/transport failure on an object must abort the sync, not be skipped
// so that a wrong secret key reads as an empty bucket (successful zero-doc sync).
func TestRunDatasourceSync_UploadPropagatesFetchFailure(t *testing.T) {
	producer := &recordingProducer{}
	svc, _ := newDatasourceService(newDatasourceFakeStore(), producer, nil)
	fake := &fakeUploadClient{
		entries:  []objectstore.Entry{{Key: "kb/a.pdf", ETag: "e"}},
		fetchErr: map[string]error{"kb/a.pdf": errors.New("AccessDenied")},
	}
	svc.SetDatasourceUploadClientFactory(func(business.UploadDatasourceConfig, string) business.UploadContentClient { return fake })
	source := newUploadSource(t, svc)

	if _, err := svc.RunDatasourceSync(context.Background(), source.ID); err == nil {
		t.Fatal("a 403 on every object must fail the sync, not read as an empty bucket")
	}
}

// A listed object deleted before its fetch (404) is skipped best-effort while the
// rest still deliver; an oversized object is surfaced as an error.
func TestRunDatasourceSync_UploadSkipsVanishedAndSurfacesOversized(t *testing.T) {
	producer := &recordingProducer{}
	svc, _ := newDatasourceService(newDatasourceFakeStore(), producer, nil)
	fake := &fakeUploadClient{
		entries: []objectstore.Entry{{Key: "ok.pdf", ETag: "e1"}, {Key: "gone.pdf", ETag: "e2"}, {Key: "huge.pdf", ETag: "e3"}},
		objects: map[string]objectstore.Object{"ok.pdf": {Key: "ok.pdf", Body: []byte("OK"), ETag: "e1"}},
		fetchErr: map[string]error{
			"gone.pdf": objectstore.ErrObjectNotFound,
			"huge.pdf": objectstore.ErrObjectTooLarge,
		},
	}
	svc.SetDatasourceUploadClientFactory(func(business.UploadDatasourceConfig, string) business.UploadContentClient { return fake })
	source := newUploadSource(t, svc)

	enqueued, err := svc.RunDatasourceSync(context.Background(), source.ID)
	if err == nil {
		t.Fatal("the oversized object must surface as an error")
	}
	// The vanished object is skipped and the deliverable one still enqueues.
	if enqueued != 1 || len(producer.jobs) != 1 || producer.jobs[0].GetAttributes()["upload.key"] != "ok.pdf" {
		t.Fatalf("enqueued=%d jobs=%d, want only ok.pdf delivered", enqueued, len(producer.jobs))
	}
}

func TestRunDatasourceSync_APIEnqueuesFetchedBody(t *testing.T) {
	producer := &recordingProducer{}
	svc, _ := newDatasourceService(newDatasourceFakeStore(), producer, nil)
	fake := &fakeAPIClient{result: &apisource.Result{Body: []byte(`{"x":1}`), ContentType: "application/json"}}
	svc.SetDatasourceAPIClientFactory(func(business.APIDatasourceConfig, string) business.APIContentClient { return fake })

	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID: testOrg, Provider: business.DatasourceProviderAPI, CollectionLabel: "wiki",
		Credential: "sekret", API: apiConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}

	enqueued, err := svc.RunDatasourceSync(context.Background(), source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if enqueued != 1 || len(producer.jobs) != 1 || fake.calls != 1 {
		t.Fatalf("enqueued=%d jobs=%d fetch calls=%d, want 1/1/1", enqueued, len(producer.jobs), fake.calls)
	}
	job := producer.jobs[0]
	if job.GetTopic() != "datasource.api.sync" || !job.GetScope().GetGlobal() {
		t.Fatalf("topic=%q scope=%v", job.GetTopic(), job.GetScope())
	}
	if string(job.GetPayload()) != `{"x":1}` || job.GetContentType() != "application/json" {
		t.Fatalf("payload=%q type=%q", job.GetPayload(), job.GetContentType())
	}
	attrs := job.GetAttributes()
	if attrs["datasource.source_id"] != source.ID || attrs["datasource.org_id"] != testOrg ||
		attrs["datasource.boundary_id"] == "" || attrs["datasource.boundary_id"] != source.BoundaryNodeID ||
		attrs["api.url"] != "https://api.example.com/v1/docs" || attrs["api.content_sha"] == "" {
		t.Fatalf("attributes = %v", attrs)
	}
}

func oauthConfig() *business.APIDatasourceConfig {
	return &business.APIDatasourceConfig{
		BaseURL:        "https://api.example.com",
		ResourcePath:   "/v1/docs",
		CredentialKind: business.APICredentialKindOAuth2,
		OAuth2: &business.APIOAuth2Config{
			TokenURL: "https://oauth.example.com/token",
			ClientID: "client-id",
			Scopes:   []string{"read"},
		},
	}
}

// TestAddSource_OAuth2StoresTokenSet proves an OAuth2 source stores its refresh
// token and client secret in the Vault envelope as a token set, projects only
// the non-secret oauth2 config, and carries no access token until first fetch.
func TestAddSource_OAuth2StoresTokenSet(t *testing.T) {
	svc, _ := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)

	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID:              testOrg,
		Provider:           business.DatasourceProviderAPI,
		CollectionLabel:    "wiki",
		Credential:         "refresh-tok",
		OAuth2ClientSecret: "client-sekret",
		API:                oauthConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if source.API == nil || source.API.OAuth2 == nil ||
		source.API.OAuth2.TokenURL != "https://oauth.example.com/token" || source.API.OAuth2.ClientID != "client-id" {
		t.Fatalf("oauth2 config projection = %+v", source.API)
	}
	// The stored envelope holds the token set, not a bare string.
	plain, err := (purposeCipher{}).DecryptSecret(context.Background(),
		business.DatasourceConnectorSecretPurpose(source.ID), source.CredentialSecretRef)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		RefreshToken string `json:"refresh_token"`
		ClientSecret string `json:"client_secret"`
		AccessToken  string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(plain), &stored); err != nil {
		t.Fatalf("stored credential is not a token set: %v (%q)", err, plain)
	}
	if stored.RefreshToken != "refresh-tok" || stored.ClientSecret != "client-sekret" {
		t.Fatalf("stored token set = %+v, want refresh+client secret", stored)
	}
	if stored.AccessToken != "" {
		t.Fatalf("no access token should be stored before first fetch, got %q", stored.AccessToken)
	}
}

// TestRunDatasourceSync_OAuth2RefreshesRotatesAndBearer proves the OAuth2 flow
// end to end: the first sync refreshes at the token endpoint, presents the
// access token to the connector as a bearer credential, and rotates the stored
// token set (a new refresh token is persisted); a second sync reuses the
// still-valid access token without refreshing again.
func TestRunDatasourceSync_OAuth2RefreshesRotatesAndBearer(t *testing.T) {
	store := newDatasourceFakeStore()
	producer := &recordingProducer{}
	svc, _ := newDatasourceService(store, producer, nil)

	var gotKind, gotCredential string
	fake := &fakeAPIClient{result: &apisource.Result{Body: []byte("{}"), ContentType: "application/json"}}
	svc.SetDatasourceAPIClientFactory(func(cfg business.APIDatasourceConfig, cred string) business.APIContentClient {
		gotKind, gotCredential = cfg.CredentialKind, cred
		return fake
	})

	refreshCalls := 0
	var gotRefreshToken, gotClientSecret, gotTokenURL string
	svc.SetDatasourceOAuth2RefreshFunc(func(_ context.Context, cfg apisource.OAuth2Config, refreshToken, clientSecret string) (*apisource.OAuth2Token, error) {
		refreshCalls++
		gotRefreshToken, gotClientSecret, gotTokenURL = refreshToken, clientSecret, cfg.TokenURL
		return &apisource.OAuth2Token{AccessToken: "access-1", RefreshToken: "refresh-2", ExpiresIn: time.Hour}, nil
	})

	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID: testOrg, Provider: business.DatasourceProviderAPI, CollectionLabel: "wiki",
		Credential: "refresh-tok", OAuth2ClientSecret: "client-sekret", API: oauthConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.RunDatasourceSync(context.Background(), source.ID); err != nil {
		t.Fatal(err)
	}
	if refreshCalls != 1 {
		t.Fatalf("first sync refresh calls = %d, want 1", refreshCalls)
	}
	if gotKind != business.APICredentialKindBearer || gotCredential != "access-1" {
		t.Fatalf("connector built with kind=%q credential=%q, want bearer/access-1", gotKind, gotCredential)
	}
	if gotRefreshToken != "refresh-tok" || gotClientSecret != "client-sekret" || gotTokenURL != "https://oauth.example.com/token" {
		t.Fatalf("refresh called with refresh=%q secret=%q url=%q", gotRefreshToken, gotClientSecret, gotTokenURL)
	}

	// Rotation persisted: the envelope now holds the fresh access + rotated refresh token.
	rotated, _ := store.GetDatasourceSourceByID(context.Background(), source.ID)
	plain, err := (purposeCipher{}).DecryptSecret(context.Background(),
		business.DatasourceConnectorSecretPurpose(source.ID), rotated.CredentialSecretRef)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		RefreshToken string `json:"refresh_token"`
		AccessToken  string `json:"access_token"`
		ExpiresAt    int64  `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(plain), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.AccessToken != "access-1" || stored.RefreshToken != "refresh-2" || stored.ExpiresAt == 0 {
		t.Fatalf("rotated token set = %+v, want access-1/refresh-2/expiry", stored)
	}

	// A second sync reuses the still-valid access token without refreshing.
	if _, err := svc.RunDatasourceSync(context.Background(), source.ID); err != nil {
		t.Fatal(err)
	}
	if refreshCalls != 1 {
		t.Fatalf("second sync refresh calls = %d, want still 1 (reuse the valid token)", refreshCalls)
	}
}

// TestRunDatasourceSync_OAuth2RereadsRotatedCredentialUnderLock proves the
// concurrency fix: the refresh reads the credential envelope under a row lock,
// so a sync that runs after another worker has already refreshed and rotated the
// token picks up the fresh envelope and skips its own refresh — a single-use
// refresh token is never spent twice.
func TestRunDatasourceSync_OAuth2RereadsRotatedCredentialUnderLock(t *testing.T) {
	store := newDatasourceFakeStore()
	svc, _ := newDatasourceService(store, &recordingProducer{}, nil)

	var gotCredential string
	fake := &fakeAPIClient{result: &apisource.Result{Body: []byte("{}"), ContentType: "application/json"}}
	svc.SetDatasourceAPIClientFactory(func(_ business.APIDatasourceConfig, cred string) business.APIContentClient {
		gotCredential = cred
		return fake
	})
	refreshCalls := 0
	svc.SetDatasourceOAuth2RefreshFunc(func(context.Context, apisource.OAuth2Config, string, string) (*apisource.OAuth2Token, error) {
		refreshCalls++
		return &apisource.OAuth2Token{AccessToken: "must-not-be-used", ExpiresIn: time.Hour}, nil
	})

	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID: testOrg, Provider: business.DatasourceProviderAPI, CollectionLabel: "wiki",
		Credential: "refresh-tok", API: oauthConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate another worker having already refreshed and rotated the token set.
	blob, _ := json.Marshal(map[string]any{
		"refresh_token": "rotated",
		"access_token":  "already-valid",
		"expires_at":    time.Now().Add(time.Hour).Unix(),
	})
	ref, _ := (purposeCipher{}).EncryptSecret(context.Background(),
		business.DatasourceConnectorSecretPurpose(source.ID), string(blob))
	if err := store.UpdateDatasourceSourceCredential(context.Background(), testOrg, source.ID, ref); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.RunDatasourceSync(context.Background(), source.ID); err != nil {
		t.Fatal(err)
	}
	if refreshCalls != 0 {
		t.Fatalf("locked re-read must skip refresh when a valid token is already stored, got %d refreshes", refreshCalls)
	}
	if gotCredential != "already-valid" {
		t.Fatalf("connector credential = %q, want the stored valid access token", gotCredential)
	}
}

// TestRunDatasourceSync_OAuth2DefaultTTLWhenNoExpiry proves that a token
// endpoint that omits expires_in does not force a refresh on every sync: the
// access token is trusted for the default TTL, so a second sync reuses it.
func TestRunDatasourceSync_OAuth2DefaultTTLWhenNoExpiry(t *testing.T) {
	store := newDatasourceFakeStore()
	svc, _ := newDatasourceService(store, &recordingProducer{}, nil)
	svc.SetDatasourceAPIClientFactory(func(business.APIDatasourceConfig, string) business.APIContentClient {
		return &fakeAPIClient{result: &apisource.Result{Body: []byte("{}")}}
	})
	refreshCalls := 0
	svc.SetDatasourceOAuth2RefreshFunc(func(context.Context, apisource.OAuth2Config, string, string) (*apisource.OAuth2Token, error) {
		refreshCalls++
		// No ExpiresIn: the provider omitted expires_in.
		return &apisource.OAuth2Token{AccessToken: "access-1"}, nil
	})

	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID: testOrg, Provider: business.DatasourceProviderAPI, CollectionLabel: "wiki",
		Credential: "refresh-tok", API: oauthConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if _, err := svc.RunDatasourceSync(context.Background(), source.ID); err != nil {
			t.Fatal(err)
		}
	}
	if refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1 — a missing expires_in must not refresh every sync", refreshCalls)
	}
}

// TestRunDatasourceSync_OAuth2RejectedRefreshIsTerminal proves a permanently
// rejected refresh token surfaces as ErrOAuth2ReauthRequired and makes the sync
// job fail terminally (non-retryable), so the worker stops replaying the dead
// token instead of burning its retry budget.
func TestRunDatasourceSync_OAuth2RejectedRefreshIsTerminal(t *testing.T) {
	store := newDatasourceFakeStore()
	producer := &recordingProducer{}
	svc, _ := newDatasourceService(store, producer, nil)
	svc.SetDatasourceOAuth2RefreshFunc(func(context.Context, apisource.OAuth2Config, string, string) (*apisource.OAuth2Token, error) {
		return nil, apisource.ErrRefreshRejected
	})

	source, err := svc.AddSource(context.Background(), "actor-1", business.AddSourceInput{
		OrgID: testOrg, Provider: business.DatasourceProviderAPI, CollectionLabel: "wiki",
		Credential: "refresh-tok", API: oauthConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.RunDatasourceSync(context.Background(), source.ID)
	if !errors.Is(err, business.ErrOAuth2ReauthRequired) {
		t.Fatalf("rejected refresh must surface as ErrOAuth2ReauthRequired, got %v", err)
	}

	// Drive the sync job handler with the real routing an enqueued request carries.
	if _, err := svc.SyncDatasourceSource(context.Background(), "actor-1", testOrg, source.ID); err != nil {
		t.Fatal(err)
	}
	reqJob := producer.jobs[len(producer.jobs)-1]
	// The non-GitHub branch builds its own request job; it is a message on the
	// same terms as the GitHub one and must declare a body the platform accepts.
	if reqJob.GetQueue() != business.DatasourceSyncRequestQueue ||
		reqJob.GetContentType() != "application/json" || string(reqJob.GetPayload()) != "{}" {
		t.Fatalf("generic sync request = %s %q/%q, want an empty JSON object on the sync queue",
			reqJob.GetQueue(), reqJob.GetContentType(), reqJob.GetPayload())
	}
	env := &jobsv1.JobEnvelope{
		Queue:      reqJob.GetQueue(),
		Topic:      reqJob.GetTopic(),
		Attributes: reqJob.GetAttributes(),
	}
	jobErr := svc.NewDatasourceSyncJobHandler()(context.Background(), env)
	var procErr *jobs.ProcessingError
	if !errors.As(jobErr, &procErr) {
		t.Fatalf("handler error = %v, want a *jobs.ProcessingError", jobErr)
	}
	if procErr.Retryable {
		t.Fatal("a permanently rejected refresh must be a non-retryable job failure")
	}
}

// TestAddSource_ReusesCollectionNodeByLabel proves the connect path does not
// fragment a boundary: connecting several sources to the same collection label
// converges on one grantable node, while a distinct label resolves elsewhere.
func TestAddSource_ReusesCollectionNodeByLabel(t *testing.T) {
	svc, _ := newDatasourceService(newDatasourceFakeStore(), &recordingProducer{}, nil)

	a := addSource(t, svc, business.AddGitHubSourceInput{
		OrgID: testOrg, Repo: "acme/a", CollectionLabel: "wiki", AccessToken: "t",
	})
	b := addSource(t, svc, business.AddGitHubSourceInput{
		OrgID: testOrg, Repo: "acme/b", CollectionLabel: "wiki", AccessToken: "t",
	})
	c := addSource(t, svc, business.AddGitHubSourceInput{
		OrgID: testOrg, Repo: "acme/c", CollectionLabel: "docs", AccessToken: "t",
	})

	if a.BoundaryNodeID == "" || a.BoundaryNodeID != b.BoundaryNodeID {
		t.Fatalf("same collection label must reuse one boundary node, got %q and %q", a.BoundaryNodeID, b.BoundaryNodeID)
	}
	if c.BoundaryNodeID == a.BoundaryNodeID {
		t.Fatal("a distinct collection label must resolve to a different boundary node")
	}
}

// TestAddSource_BoundaryNodeIDMustExist proves the reuse path validates tenant
// visibility: an unregistered node id is refused, a registered one is bound.
func TestAddSource_BoundaryNodeIDMustExist(t *testing.T) {
	fs := newDatasourceFakeStore()
	svc, _ := newDatasourceService(fs, &recordingProducer{}, nil)
	const nodeID = "22222222-2222-2222-2222-222222222222"

	if _, err := svc.AddGitHubSource(context.Background(), "actor-1", business.AddGitHubSourceInput{
		OrgID: testOrg, Repo: "acme/a", BoundaryNodeID: nodeID, AccessToken: "t",
	}); err == nil {
		t.Fatal("an unregistered boundary node id must be rejected")
	}

	fs.nodes[nodeID] = true
	src := addSource(t, svc, business.AddGitHubSourceInput{
		OrgID: testOrg, Repo: "acme/a", BoundaryNodeID: nodeID, AccessToken: "t",
	})
	if src.BoundaryNodeID != nodeID {
		t.Fatalf("boundary node id = %q, want %q", src.BoundaryNodeID, nodeID)
	}
}
