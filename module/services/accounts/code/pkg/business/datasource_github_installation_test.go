package business_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"accounts/pkg/business"
	jobsv1 "accounts/pkg/gen/saas/jobs/v1"
	"accounts/pkg/githubconnector"
	"accounts/pkg/jobs"
)

const (
	testAppInstallation      = "4242"
	testOtherAppInstallation = "9999"
)

// fakeInstallationAPI answers the two app-authenticated reads the reconciler
// makes: which installation covers a repository, and whether that installation
// is suspended. Whatever a delivery claimed, this is what the host acts on.
type fakeInstallationAPI struct {
	mu sync.Mutex
	// coverage maps "owner/name" to the installation that still covers it; a
	// repository absent here has been deselected or the App uninstalled.
	coverage map[string]string
	// installations maps an installation id to its suspension instant (nil when
	// active); an id absent here has been deleted.
	installations map[string]*time.Time
	// failStatus, when set, fails every request — GitHub being unavailable.
	failStatus int
	// failRepo fails only the named repositories' coverage lookup, so a test can
	// strand one source and prove the rest are still reconciled.
	failRepo map[string]int

	coverageReads     int
	installationReads int
}

func (f *fakeInstallationAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failStatus != 0 {
		http.Error(w, `{"message":"unavailable"}`, f.failStatus)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/repos/") && strings.HasSuffix(r.URL.Path, "/installation"):
		f.coverageReads++
		repo := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repos/"), "/installation")
		if status, ok := f.failRepo[repo]; ok {
			http.Error(w, `{"message":"You have exceeded a secondary rate limit"}`, status)
			return
		}
		installation, ok := f.coverage[repo]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		writeAppJSON(w, http.StatusOK, map[string]any{"id": installation})
	case strings.HasPrefix(r.URL.Path, "/app/installations/"):
		f.installationReads++
		id := strings.TrimPrefix(r.URL.Path, "/app/installations/")
		suspendedAt, ok := f.installations[id]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		body := map[string]any{"id": id, "suspended_at": nil}
		if suspendedAt != nil {
			body["suspended_at"] = suspendedAt.Format(time.RFC3339)
		}
		writeAppJSON(w, http.StatusOK, body)
	default:
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}
}

func (f *fakeInstallationAPI) reads() (coverage, installations int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.coverageReads, f.installationReads
}

type installationHarness struct {
	svc      *business.Service
	store    *datasourceFakeStore
	api      *fakeInstallationAPI
	producer *recordingProducer
	audit    *recordingAudit
}

func newInstallationHarness(t *testing.T, api *fakeInstallationAPI) *installationHarness {
	t.Helper()
	if api.coverage == nil {
		api.coverage = map[string]string{}
	}
	if api.installations == nil {
		api.installations = map[string]*time.Time{}
	}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)

	store := newDatasourceFakeStore()
	producer := &recordingProducer{}
	svc, audit := newDatasourceService(store, producer, nil)
	svc.SetGitHubConnector(githubconnector.NewConnector(githubconnector.WithBaseURL(server.URL)))
	svc.SetGitHubAppRegistration("123456", testAppKeyPEM(t), "", "whsec_app")
	return &installationHarness{svc: svc, store: store, api: api, producer: producer, audit: audit}
}

// enqueuedRecheckKeys returns the idempotency key of every re-check job the
// sweep produced. The platform resolves a repeated key to the job already
// queued, so the key is what actually throttles the sweep.
func (h *installationHarness) enqueuedRecheckKeys() []string {
	h.producer.mu.Lock()
	defer h.producer.mu.Unlock()
	var keys []string
	for _, job := range h.producer.jobs {
		if job.GetQueue() == business.DatasourceInstallationQueue {
			keys = append(keys, job.GetIdempotencyKey())
		}
	}
	return keys
}

// seedAppSource writes an App-backed source straight into the store, bound to
// an installation and carrying ingested history the reconciler must not touch.
func (h *installationHarness) seedAppSource(t *testing.T, id, repo, installationID string) *business.DatasourceSource {
	t.Helper()
	source := &business.DatasourceSource{
		ID:                   id,
		OrgID:                testOrg,
		Provider:             business.DatasourceProviderGitHub,
		Repo:                 repo,
		Branch:               "main",
		BoundaryNodeID:       "boundary-" + id,
		CredentialSecretRef:  "envelope-" + id,
		Status:               business.DatasourceStatusActive,
		GitHubInstallationID: installationID,
		ReconcileInterval:    30 * time.Minute,
		LastIngestedCommit:   "commit-" + id,
	}
	require.NoError(t, h.store.InsertDatasourceSource(context.Background(), source))
	return source
}

func (h *installationHarness) reload(t *testing.T, id string) *business.DatasourceSource {
	t.Helper()
	source, err := h.store.GetDatasourceSourceByID(context.Background(), id)
	require.NoError(t, err)
	require.NotNil(t, source)
	return source
}

// installationReasons is what this path may park over and revive, mirroring the
// unexported set the service passes to the store.
var installationReasons = []string{
	business.DatasourceReasonInstallationRepositoryUnavailable,
	business.DatasourceReasonInstallationSuspended,
}

func (h *installationHarness) degrade(t *testing.T, id, reason string) {
	t.Helper()
	_, err := h.store.MarkDatasourceSourceInstallationDegraded(context.Background(), id, reason, installationReasons)
	require.NoError(t, err)
}

// degradeCompiler parks a source the way the change-set compiler does, through
// the other owner of status_reason and its closed reason type.
func (h *installationHarness) degradeCompiler(t *testing.T, id string, reason business.DatasourceDegradeReason) {
	t.Helper()
	require.NoError(t, h.store.MarkDatasourceSourceDegraded(context.Background(), id, reason))
}

func (h *installationHarness) reconcile(t *testing.T, installationID string) error {
	t.Helper()
	return h.svc.ReconcileGitHubInstallation(context.Background(), installationID)
}

// Losing a repository parks the source and says why — and leaves everything
// else on the row alone. Revocation is not deletion: the ingest cursor,
// boundary and identity survive, so restoring access resumes rather than
// re-ingests, and retained content stays governed by the tenant's own policy.
func TestReconcileInstallationParksDeselectedRepository(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	parked := h.reload(t, source.ID)
	require.Equal(t, business.DatasourceStatusDegraded, parked.Status)
	require.Equal(t, business.DatasourceReasonInstallationRepositoryUnavailable, parked.StatusReason)
	require.Equal(t, "commit-source-a", parked.LastIngestedCommit, "parking must not discard ingested history")
	require.Equal(t, "boundary-source-a", parked.BoundaryNodeID)
	require.Nil(t, parked.NextReconcileAt, "a parked source leaves the reconcile sweep")
}

func TestReconcileInstallationParksSuspendedInstallation(t *testing.T) {
	suspended := time.Now().UTC()
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testAppInstallation},
		installations: map[string]*time.Time{testAppInstallation: &suspended},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	parked := h.reload(t, source.ID)
	require.Equal(t, business.DatasourceStatusDegraded, parked.Status)
	require.Equal(t, business.DatasourceReasonInstallationSuspended, parked.StatusReason)
}

// The delivery is a claim, not an instruction. A replayed or late "deleted"
// arrives here as nothing more than an installation id, and GitHub says access
// is intact — so the source keeps syncing.
func TestReconcileInstallationTrustsGitHubOverTheDelivery(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testAppInstallation},
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	require.Equal(t, business.DatasourceStatusActive, h.reload(t, source.ID).Status)
}

// Restored access lifts the park this path applied, and restores the reconcile
// schedule so the source starts syncing again on its own.
func TestReconcileInstallationRestoresRepairedSource(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testAppInstallation},
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	h.degrade(t, source.ID, business.DatasourceReasonInstallationSuspended)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	restored := h.reload(t, source.ID)
	require.Equal(t, business.DatasourceStatusActive, restored.Status)
	require.Empty(t, restored.StatusReason)
	require.NotNil(t, restored.NextReconcileAt, "a restored source rejoins the reconcile sweep")
}

// Two paths degrade a source. Restored App access must not clear a park the
// change-set compiler applied for a structural fault of its own.
func TestReconcileInstallationLeavesAnotherPathsDegradeAlone(t *testing.T) {
	compilerReason := business.SnapshotTooLargeDegradeReason(1048576, 983040)
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testAppInstallation},
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	h.degradeCompiler(t, source.ID, compilerReason)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	untouched := h.reload(t, source.ID)
	require.Equal(t, business.DatasourceStatusDegraded, untouched.Status)
	require.Equal(t, compilerReason.String(), untouched.StatusReason)
}

// An operator pause outranks a webhook: losing access must not rewrite a source
// somebody deliberately stopped.
func TestReconcileInstallationDoesNotOverwriteOperatorPause(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	source.Status = business.DatasourceStatusPaused
	require.NoError(t, h.store.InsertDatasourceSource(context.Background(), source))

	require.NoError(t, h.reconcile(t, testAppInstallation))

	require.Equal(t, business.DatasourceStatusPaused, h.reload(t, source.ID).Status)
}

// The routing column is an index, not an authority. A source re-bound to
// another installation since the column was stamped is answered for the
// installation that actually covers its repository, so a stale column costs a
// redundant check rather than a wrong revocation.
func TestReconcileInstallationFollowsRebindingRatherThanTheColumn(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testOtherAppInstallation},
		installations: map[string]*time.Time{testOtherAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	require.Equal(t, business.DatasourceStatusActive, h.reload(t, source.ID).Status,
		"a source the app still covers must keep syncing whatever the column said")
}

// GitHub being briefly unavailable must not look like revocation: the job fails
// and retries, and every source keeps its status meanwhile.
func TestReconcileInstallationOutageDoesNotParkSources(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{failStatus: http.StatusInternalServerError})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	require.Error(t, h.reconcile(t, testAppInstallation))

	require.Equal(t, business.DatasourceStatusActive, h.reload(t, source.ID).Status)
}

// One installation usually covers several sources; its state is read once, not
// once per source.
func TestReconcileInstallationReadsInstallationStateOncePerInstallation(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage: map[string]string{
			"acme/docs":    testAppInstallation,
			"acme/widgets": testAppInstallation,
			"acme/specs":   testAppInstallation,
		},
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	h.seedAppSource(t, "source-b", "acme/widgets", testAppInstallation)
	h.seedAppSource(t, "source-c", "acme/specs", testAppInstallation)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	coverageReads, installationReads := h.api.reads()
	require.Equal(t, 3, coverageReads, "each source's repository is checked on its own")
	require.Equal(t, 1, installationReads, "the shared installation is read once")
}

// Sources bound to other installations are not in scope for this delivery.
func TestReconcileInstallationTouchesOnlyItsOwnSources(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/widgets": testOtherAppInstallation},
		installations: map[string]*time.Time{testOtherAppInstallation: nil},
	})
	revoked := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	other := h.seedAppSource(t, "source-b", "acme/widgets", testOtherAppInstallation)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	require.Equal(t, business.DatasourceStatusDegraded, h.reload(t, revoked.ID).Status)
	require.Equal(t, business.DatasourceStatusActive, h.reload(t, other.ID).Status)
}

// The reconciler decides what to park from a page listed before it called
// GitHub, and it is ordered per installation, not per source — so nothing stops
// an operator pausing a source in between. The park must re-test the status
// where it writes, or the pause is erased and the next re-check, finding access
// intact, flips that source back to active against the operator's stop.
func TestReconcileInstallationDoesNotOverwriteAConcurrentPause(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	h.store.beforeInstallationMark = func(id string) {
		h.store.mu.Lock()
		defer h.store.mu.Unlock()
		h.store.sources[id].Status = business.DatasourceStatusPaused
	}

	require.NoError(t, h.reconcile(t, testAppInstallation))

	paused := h.reload(t, source.ID)
	require.Equal(t, business.DatasourceStatusPaused, paused.Status,
		"a pause that lands mid-reconcile outranks the park")
	require.Empty(t, paused.StatusReason)
}

// GitHub answers 403 when it declines to serve a request — overwhelmingly a
// rate limit, which this path invites by issuing a request per source. Treating
// that as terminal would dead-letter the job and silently drop the revocation
// the endpoint exists to deliver.
func TestReconcileInstallationRateLimitedLookupStaysRetryable(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{failStatus: http.StatusForbidden})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	err := h.reconcile(t, testAppInstallation)
	require.Error(t, err)
	var processing *jobs.ProcessingError
	require.ErrorAs(t, err, &processing)
	require.True(t, processing.Retryable, "a 403 is GitHub declining to answer, not the tenant losing access")
	require.Equal(t, business.DatasourceStatusActive, h.reload(t, source.ID).Status,
		"a source is never parked on an answer GitHub did not give")
}

// One installation spans tenants, so a single unreachable repository must not
// strand every source behind it — including another organization's. The refusal
// has to be one that concerns only this repository: a 403 is GitHub throttling
// the caller, which the walk stops on instead (see the test below).
func TestReconcileInstallationStepsOverAnUnreachableSource(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		installations: map[string]*time.Time{testAppInstallation: nil},
		failRepo:      map[string]int{"acme/docs": http.StatusUnprocessableEntity},
	})
	blocked := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	deselected := h.seedAppSource(t, "source-b", "acme/widgets", testAppInstallation)

	err := h.reconcile(t, testAppInstallation)
	require.Error(t, err, "the job still reports the failure so it comes back")
	var processing *jobs.ProcessingError
	require.ErrorAs(t, err, &processing)
	require.True(t, processing.Retryable)

	require.Equal(t, business.DatasourceStatusActive, h.reload(t, blocked.ID).Status,
		"the source GitHub would not answer for is left alone")
	require.Equal(t, business.DatasourceStatusDegraded, h.reload(t, deselected.ID).Status,
		"the source behind it is still reconciled")
}

// An installation can cover more sources than one read holds.
func TestReconcileInstallationWalksEveryPage(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	const sources = 205
	ids := make([]string, 0, sources)
	for i := range sources {
		ids = append(ids, h.seedAppSource(t, fmt.Sprintf("source-%03d", i), "acme/docs", testAppInstallation).ID)
	}

	require.NoError(t, h.reconcile(t, testAppInstallation))

	for _, id := range ids {
		require.Equal(t, business.DatasourceStatusDegraded, h.reload(t, id).Status,
			"every page must be reconciled, not just the first")
	}
}

// The routing column is only ever stamped by a GitHub path, and a source of
// another provider must never be parked with a GitHub reason.
func TestReconcileInstallationSkipsAnotherProvider(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	h.store.mu.Lock()
	h.store.sources[source.ID].Provider = business.DatasourceProviderAPI
	h.store.mu.Unlock()

	require.NoError(t, h.reconcile(t, testAppInstallation))

	require.Equal(t, business.DatasourceStatusActive, h.reload(t, source.ID).Status)
}

// Parking takes a source out of the reconcile sweep, so if the `unsuspend`
// delivery is never handed over the source stays parked for good. The re-check
// sweep is the pull-side route back, and it must select exactly the
// installations this path parked.
func TestInstallationRecheckSweepEnqueuesParkedInstallationsOnly(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{})
	parked := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	h.seedAppSource(t, "source-b", "acme/widgets", testOtherAppInstallation)
	h.degrade(t, parked.ID, business.DatasourceReasonInstallationSuspended)

	enqueued, err := h.svc.RunGitHubInstallationRecheck(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, enqueued)

	keys := h.enqueuedRecheckKeys()
	require.Len(t, keys, 1)
	require.Contains(t, keys[0], testAppInstallation)
	require.NotContains(t, keys[0], testOtherAppInstallation, "an installation with no parked source needs no re-check")
}

func TestInstallationRecheckSweepIgnoresAnotherPathsDegrade(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	h.degradeCompiler(t, source.ID, business.SnapshotTooLargeDegradeReason(1048576, 983040))

	enqueued, err := h.svc.RunGitHubInstallationRecheck(context.Background())
	require.NoError(t, err)
	require.Zero(t, enqueued, "the compiler's degrade is not this sweep's to lift")
	require.Empty(t, h.enqueuedRecheckKeys())
}

// The sweep runs on a one-minute tick; the re-check window, not the tick, sets
// how often an installation is re-verified. The platform resolves a repeated
// idempotency key to the job already queued, so a stable key is the throttle.
func TestInstallationRecheckSweepUsesOneKeyPerWindow(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	h.degrade(t, source.ID, business.DatasourceReasonInstallationSuspended)

	for range 3 {
		_, err := h.svc.RunGitHubInstallationRecheck(context.Background())
		require.NoError(t, err)
	}

	keys := h.enqueuedRecheckKeys()
	require.Len(t, keys, 3)
	require.Equal(t, keys[0], keys[1], "repeated sweeps inside one window must reuse the key")
	require.Equal(t, keys[1], keys[2])
}

// The sweep takes one page per window, not the whole parked set, and the page it
// takes is contiguous rather than a mixture.
//
// The parked set is deliberately a whole number of pages. Which page a window
// takes is derived from the clock, so a set that divides unevenly would return a
// short final page in half the windows and make this assertion depend on the
// half-hour it ran in. Rotation itself is covered exhaustively and without a
// clock in TestRecheckPageOffsetReachesEveryPage.
func TestInstallationRecheckSweepTakesOnePageOfALargerParkedSet(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{})
	const pageSize = 100
	const parked = 2 * pageSize
	for i := range parked {
		source := h.seedAppSource(t, fmt.Sprintf("source-%03d", i), fmt.Sprintf("acme/repo-%03d", i), fmt.Sprintf("inst-%03d", i))
		h.degrade(t, source.ID, business.DatasourceReasonInstallationSuspended)
	}

	enqueued, err := h.svc.RunGitHubInstallationRecheck(context.Background())
	require.NoError(t, err)
	require.Equal(t, pageSize, enqueued, "one window re-checks one page of the parked set")

	keys := h.enqueuedRecheckKeys()
	require.Len(t, keys, pageSize)
	onFirstPage := 0
	for _, key := range keys {
		for i := range pageSize {
			if strings.Contains(key, fmt.Sprintf(":inst-%03d:", i)) {
				onFirstPage++
				break
			}
		}
	}
	require.True(t, onFirstPage == 0 || onFirstPage == pageSize,
		"a window takes one contiguous page, not a mixture of pages (got %d of %d from the first page)", onFirstPage, pageSize)
}

// Both producers of the installation queue stamp the same schema version on it,
// so a consumer reading the payload rather than the attributes must not find a
// different envelope depending on which produced it.
func TestInstallationRecheckJobCarriesTheSamePayloadAsADelivery(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	h.degrade(t, source.ID, business.DatasourceReasonInstallationSuspended)

	_, err := h.svc.RunGitHubInstallationRecheck(context.Background())
	require.NoError(t, err)

	h.producer.mu.Lock()
	defer h.producer.mu.Unlock()
	require.Len(t, h.producer.jobs, 1)
	require.JSONEq(t, fmt.Sprintf(`{"installation_id":%q}`, testAppInstallation), string(h.producer.jobs[0].GetPayload()),
		"the sweep and the receiver must describe one envelope")
}

// GitHub throttling is not a fact about one repository: it answers the same way
// for every source left in the walk, and the job restarts that walk from its
// first page. Continuing therefore spends a doomed request per remaining source
// and then repeats every request that already succeeded — load applied to the
// very limit that produced the failure.
func TestReconcileInstallationStopsOnAThrottledLookup(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testAppInstallation, "acme/widgets": testAppInstallation},
		installations: map[string]*time.Time{testAppInstallation: nil},
		failRepo:      map[string]int{"acme/docs": http.StatusTooManyRequests},
	})
	throttled := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	behind := h.seedAppSource(t, "source-b", "acme/widgets", testAppInstallation)

	err := h.reconcile(t, testAppInstallation)
	require.Error(t, err)
	var processing *jobs.ProcessingError
	require.ErrorAs(t, err, &processing)
	require.True(t, processing.Retryable, "the retry is what covers the sources the walk stopped short of")

	coverageReads, _ := h.api.reads()
	require.Equal(t, 1, coverageReads,
		"the walk must stop at the throttle, not ask once per remaining source")
	require.Equal(t, business.DatasourceStatusActive, h.reload(t, throttled.ID).Status)
	require.Equal(t, business.DatasourceStatusActive, h.reload(t, behind.ID).Status)
}

// The routing column is stamped once, when a source is bound to the App. An
// uninstall-and-reinstall issues a NEW installation id, so the column then names
// one that no longer exists — and since the reconciler lists BY that column, no
// later delivery for the real installation would ever reach this source again.
// Nothing else revisits it: the re-check sweep selects only degraded rows, and a
// syncing source is not degraded. Correcting it from what GitHub just answered
// is what keeps the staleness from being permanent.
func TestReconcileInstallationCorrectsAStaleRoutingColumn(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testOtherAppInstallation},
		installations: map[string]*time.Time{testOtherAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	reloaded := h.reload(t, source.ID)
	require.Equal(t, business.DatasourceStatusActive, reloaded.Status)
	require.Equal(t, testOtherAppInstallation, reloaded.GitHubInstallationID,
		"a delivery for the installation that actually covers this repository must be able to find it")
}

func TestInstallationJobHandlerRejectsMisroutedWork(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{})
	handler := h.svc.NewDatasourceInstallationJobHandler()

	for name, envelope := range map[string]*jobsv1.JobEnvelope{
		"another queue": {Queue: "datasource.deliveries", Topic: "datasource.github.installation"},
		"another topic": {Queue: business.DatasourceInstallationQueue, Topic: "datasource.github.push"},
		"no installation": {
			Queue: business.DatasourceInstallationQueue,
			Topic: "datasource.github.installation",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := handler(context.Background(), envelope)
			require.Error(t, err)
			require.Contains(t, fmt.Sprint(err), "datasource.invalid_job")
		})
	}
}

// onlyAuditEntry asserts exactly one record of a type was written and returns
// it, so a test reads the payload rather than only the fact of an emission.
func onlyAuditEntry(t *testing.T, h *installationHarness, event business.EventType) business.AuditEntry {
	t.Helper()
	entries := h.audit.entriesOf(event)
	require.Len(t, entries, 1, "expected exactly one %s record", event)
	return entries[0]
}

// A third party revoking access is the one datasource state change that had no
// entry on the tenant's audit spine: the row said a source was degraded, never
// when it became degraded. The record carries the installation and the cause,
// and no credential material.
func TestReconcileInstallationAuditsLostAccess(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	entry := onlyAuditEntry(t, h, business.EventDatasourceSourceAccessLost)
	require.Equal(t, "system", entry.ActorType, "the change originates in a third party's account, not a tenant request")
	require.Equal(t, testOrg, entry.OrgID, "the record belongs on the tenant's spine")
	require.Equal(t, "datasource", entry.Resource)
	require.Equal(t, source.ID, entry.ResourceID)
	require.Equal(t, map[string]any{
		"repo":            "acme/docs",
		"installation_id": testAppInstallation,
		"reason":          business.DatasourceAccessLostRepositoryUnavailable,
	}, entry.Payload)
	require.NoError(t, business.ValidatePayload(entry.EventType, entry.Payload))
}

func TestReconcileInstallationAuditsSuspensionAsItsOwnCause(t *testing.T) {
	suspended := time.Now().UTC()
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testAppInstallation},
		installations: map[string]*time.Time{testAppInstallation: &suspended},
	})
	h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	entry := onlyAuditEntry(t, h, business.EventDatasourceSourceAccessLost)
	require.Equal(t, business.DatasourceAccessLostSuspended, entry.Payload["reason"])
	require.NoError(t, business.ValidatePayload(entry.EventType, entry.Payload))
}

// The record must name the installation the decision was actually made against.
// Access is resolved per source BY REPOSITORY, so when a repository has moved to
// a different installation the routing column is not what answered — auditing it
// would attribute a revocation to an installation that had nothing to do with it.
func TestReconcileInstallationAuditsTheInstallationThatAnswered(t *testing.T) {
	suspended := time.Now().UTC()
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testOtherAppInstallation},
		installations: map[string]*time.Time{testOtherAppInstallation: &suspended},
	})
	h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	entry := onlyAuditEntry(t, h, business.EventDatasourceSourceAccessLost)
	require.Equal(t, testOtherAppInstallation, entry.Payload["installation_id"],
		"the audit names the installation that was asked, not the stale column")
	require.Equal(t, business.DatasourceAccessLostSuspended, entry.Payload["reason"])
	require.NoError(t, business.ValidatePayload(entry.EventType, entry.Payload))
}

func TestReconcileInstallationAuditsRestoredAccess(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testAppInstallation},
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	h.degrade(t, source.ID, business.DatasourceReasonInstallationSuspended)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	entry := onlyAuditEntry(t, h, business.EventDatasourceSourceAccessRestored)
	require.Equal(t, "system", entry.ActorType)
	require.Equal(t, testOrg, entry.OrgID)
	require.Equal(t, "datasource", entry.Resource)
	require.Equal(t, source.ID, entry.ResourceID)
	require.Equal(t, map[string]any{
		"repo":            "acme/docs",
		"installation_id": testAppInstallation,
		"restored_from":   business.DatasourceAccessLostSuspended,
	}, entry.Payload)
	require.NoError(t, business.ValidatePayload(entry.EventType, entry.Payload))
}

// An App-level delivery is redelivered freely, and GitHub answers the same way
// each time. Only the transition is an event, so a second pass over a source
// already in its target state adds nothing to the tenant's log.
func TestReconcileInstallationAuditsTheTransitionNotTheDelivery(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	require.NoError(t, h.reconcile(t, testAppInstallation))
	require.NoError(t, h.reconcile(t, testAppInstallation))

	require.Equal(t, 1, auditCount(h.audit, business.EventDatasourceSourceAccessLost))

	h.api.coverage = map[string]string{"acme/docs": testAppInstallation}
	require.NoError(t, h.reconcile(t, testAppInstallation))
	require.NoError(t, h.reconcile(t, testAppInstallation))

	require.Equal(t, 1, auditCount(h.audit, business.EventDatasourceSourceAccessRestored))
}

// The restore record follows what the write actually matched, not the status
// read before it: a source the change-set compiler parked keeps its degrade, so
// restored App access must not claim on the audit trail that it came back.
func TestReconcileInstallationDoesNotAuditARestoreItDidNotMake(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testAppInstallation},
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	h.degradeCompiler(t, source.ID, business.SnapshotTooLargeDegradeReason(1048576, 983040))

	require.NoError(t, h.reconcile(t, testAppInstallation))

	require.Empty(t, h.audit.entriesOf(business.EventDatasourceSourceAccessRestored))
}

// An operator pause is left alone, so there is no transition to record either.
func TestReconcileInstallationDoesNotAuditAnOperatorPause(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	source.Status = business.DatasourceStatusPaused
	require.NoError(t, h.store.InsertDatasourceSource(context.Background(), source))

	require.NoError(t, h.reconcile(t, testAppInstallation))

	require.Empty(t, h.audit.entriesOf(business.EventDatasourceSourceAccessLost))
}

// The reconciler lists every source, then spends one or two GitHub round-trips
// per source before writing it, and the change-set compiler parks sources under
// a different job ordering namespace — so nothing stops a compiler degrade from
// landing inside that window. Deciding from the listed status would overwrite it:
// the compiler's reason is discarded, and the row is left carrying one of this
// path's, which this path would then revive with the oversized-snapshot fault
// still standing. The write must refuse it, and audit nothing.
func TestReconcileInstallationDoesNotOverwriteADegradeThatLandedMidReconcile(t *testing.T) {
	compilerReason := business.SnapshotTooLargeDegradeReason(1048576, 983040)
	h := newInstallationHarness(t, &fakeInstallationAPI{
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	var once sync.Once
	h.store.beforeInstallationMark = func(string) {
		once.Do(func() { h.degradeCompiler(t, source.ID, compilerReason) })
	}

	require.NoError(t, h.reconcile(t, testAppInstallation))

	untouched := h.reload(t, source.ID)
	require.Equal(t, business.DatasourceStatusDegraded, untouched.Status)
	require.Equal(t, compilerReason.String(), untouched.StatusReason,
		"a stale listing must not let this path take ownership of another path's degrade")
	require.Empty(t, h.audit.entriesOf(business.EventDatasourceSourceAccessLost))
}

// The same window, with an operator pausing the source inside it. A pause
// outranks a webhook however stale the listing is.
func TestReconcileInstallationDoesNotOverwriteAPauseThatLandedMidReconcile(t *testing.T) {
	h := newInstallationHarness(t, &fakeInstallationAPI{
		installations: map[string]*time.Time{testAppInstallation: nil},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)

	var once sync.Once
	h.store.beforeInstallationMark = func(string) {
		once.Do(func() {
			paused := *source
			paused.Status = business.DatasourceStatusPaused
			require.NoError(t, h.store.InsertDatasourceSource(context.Background(), &paused))
		})
	}

	require.NoError(t, h.reconcile(t, testAppInstallation))

	require.Equal(t, business.DatasourceStatusPaused, h.reload(t, source.ID).Status)
	require.Empty(t, h.audit.entriesOf(business.EventDatasourceSourceAccessLost))
}

// A source parked for a deselected repository whose installation is later
// suspended is still degraded, so nothing about its status changes — but the
// recorded cause is now wrong, and an audit trail that never corrects it leaves
// the tenant reading the wrong reason forever.
func TestReconcileInstallationRecordsAChangedCause(t *testing.T) {
	suspended := time.Now().UTC()
	h := newInstallationHarness(t, &fakeInstallationAPI{
		coverage:      map[string]string{"acme/docs": testAppInstallation},
		installations: map[string]*time.Time{testAppInstallation: &suspended},
	})
	source := h.seedAppSource(t, "source-a", "acme/docs", testAppInstallation)
	h.degrade(t, source.ID, business.DatasourceReasonInstallationRepositoryUnavailable)

	require.NoError(t, h.reconcile(t, testAppInstallation))

	relabelled := h.reload(t, source.ID)
	require.Equal(t, business.DatasourceStatusDegraded, relabelled.Status)
	require.Equal(t, business.DatasourceReasonInstallationSuspended, relabelled.StatusReason)

	entry := onlyAuditEntry(t, h, business.EventDatasourceSourceAccessLost)
	require.Equal(t, business.DatasourceAccessLostSuspended, entry.Payload["reason"])
	require.NoError(t, business.ValidatePayload(entry.EventType, entry.Payload))

	// The corrected cause is itself a transition, so reconciling again adds nothing.
	require.NoError(t, h.reconcile(t, testAppInstallation))
	require.Equal(t, 1, auditCount(h.audit, business.EventDatasourceSourceAccessLost))
}
