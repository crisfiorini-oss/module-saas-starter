package business

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"accounts/pkg/datasource/github"
	jobsv1 "accounts/pkg/gen/saas/jobs/v1"
	"accounts/pkg/jobs"

	"github.com/codefly-dev/core/wool"
)

// The change-set compiler turns a raw GitHub delivery into a set of per-file
// ingest ops (issue #487). The receiver stays dumb — verify, persist, 2xx — and
// this leased worker, holding the source's decrypted token, does all the change
// detection accounts is the only place that can: branch and path filtering,
// ancestor/staleness checks against the ingest cursor, and a full snapshot when
// a force push makes an incremental diff impossible.
const (
	// DatasourceDeliveryQueue is the accounts-owned queue the receiver and the
	// reconcile scheduler enqueue onto; the compiler leases it. The module never
	// sees a raw GitHub payload again.
	DatasourceDeliveryQueue = "datasource.deliveries"

	// datasourcePushTopic must equal the receiver's GitHubWebhookTopic; the
	// compiler dispatches on it.
	datasourcePushTopic       = "datasource.github.push"
	datasourceReconcileTopic  = "datasource.github.reconcile"
	datasourceReconcileSource = "github.reconcile"

	// datasourceSnapshotTopic carries a full-tree manifest (paths + blob shas +
	// sizes, no content) the module diffs against its own bindings.
	datasourceSnapshotTopic = "datasource.github.snapshot"

	// datasourceDeliveryOrderingNamespace scopes the per-source FIFO ordering key
	// so the job platform keeps exactly one in-flight delivery per source: the
	// compiler reads and advances a source's cursor without a second delivery for
	// the same source racing it.
	datasourceDeliveryOrderingNamespace = "datasource.delivery"

	// datasourceChangeSetSchemaVersion is the per-file ingest payload version. v2
	// is the JSON change-set envelope (change_type, blob sha, inline content or a
	// content ticket); v1 was raw bytes with routing only in attributes.
	datasourceChangeSetSchemaVersion = 2

	// datasourceReconcileSchemaVersion versions the reconcile *request* message,
	// which is a control message and not a change set: its attributes name the
	// source and the mode and its body is empty. It must not advertise
	// datasourceChangeSetSchemaVersion — that versions the per-file payload a
	// consumer decodes, so reusing it would describe an empty body as a v2
	// change-set file.
	datasourceReconcileSchemaVersion = 1

	attrDeliveryID    = "datasource.delivery_id"
	attrChangeSet     = "datasource.change_set"
	attrReconcileMode = "datasource.reconcile_mode"

	reconcileModeConditional = "conditional"
	reconcileModeForce       = "force"

	changeTypeModified = "modified"
	changeTypeRemoved  = "removed"
	changeTypeRenamed  = "renamed"

	// zeroSHA is GitHub's "no commit" sentinel: a branch-creation push has it as
	// `before`, so there is no incremental base and the delivery snapshots.
	zeroSHA = "0000000000000000000000000000000000000000"

	datasourceDeliveryMaxAttempts = 24
	datasourceReconcileBatchSize  = 100
)

// DeliveryDisposition is the outcome of compiling one delivery, for observability
// and testing. Only Compiled and Snapshot enqueue ingest work; the rest are
// acknowledged drops.
type DeliveryDisposition string

const (
	DispositionCompiled      DeliveryDisposition = "compiled"
	DispositionSnapshot      DeliveryDisposition = "snapshot"
	DispositionIgnoredBranch DeliveryDisposition = "ignored_branch"
	DispositionStale         DeliveryDisposition = "stale"
	DispositionBranchDeleted DeliveryDisposition = "branch_deleted"
	// DispositionDegraded is an acknowledged drop: the snapshot manifest was too
	// large to ingest, so the source was parked in the degraded state for an
	// operator instead of dead-lettering the reconcile every interval forever.
	DispositionDegraded DeliveryDisposition = "degraded"
)

// ErrMalformedDelivery reports a delivery payload the compiler cannot parse. It
// is terminal: replaying the same bytes can never parse, so the worker
// dead-letters rather than retrying.
var ErrMalformedDelivery = errors.New("datasource: malformed delivery payload")

// githubPushPayload is the subset of a GitHub push event the compiler reads.
type githubPushPayload struct {
	Ref     string `json:"ref"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Created bool   `json:"created"`
	Deleted bool   `json:"deleted"`
}

// changeOp is one file operation in a compiled change set.
type changeOp struct {
	path       string
	prevPath   string
	blobSHA    string
	changeType string
}

// changeSetFile is the v2 per-file ingest payload. Content is base64-encoded by
// encoding/json. It is a pointer so an empty file (0-length content) still
// serializes as a present "content":"" — distinct from a delete or an oversized
// blob, which omit content entirely (the latter setting content_ticket). The
// invariant is: inline content present ⇔ an upsert whose blob fit the inline cap.
type changeSetFile struct {
	Repo          string  `json:"repo"`
	Path          string  `json:"path"`
	PrevPath      string  `json:"prev_path,omitempty"`
	Ref           string  `json:"ref"`
	Commit        string  `json:"commit"`
	BlobSHA       string  `json:"blob_sha,omitempty"`
	ChangeType    string  `json:"change_type"`
	Content       *[]byte `json:"content,omitempty"`
	ContentTicket string  `json:"content_ticket,omitempty"`
	// Ordinal is the strictly-increasing per-source delivery ordinal (issue #511),
	// allocated in the compiler's delivery transaction and stamped on every emitted
	// payload so a consumer can order deliveries per source and reject a stale or
	// out-of-order replay, without trusting wall-clock timestamps or commit
	// topology. Ordinals are strictly increasing but not contiguous — a redelivery
	// or a crashed enqueue leaves a gap — so a gap is expected, not a dropped
	// payload; only a repeated or backward ordinal signals a fault.
	Ordinal int64 `json:"ordinal"`
}

// snapshotManifest is the full-tree manifest a snapshot job carries: enough for
// the module to diff against its own bindings and request only changed blobs.
type snapshotManifest struct {
	Repo   string         `json:"repo"`
	Commit string         `json:"commit"`
	Files  []snapshotFile `json:"files"`
	// Ordinal is the strictly-increasing per-source delivery ordinal (issue #511),
	// carried on the snapshot payload for the same per-source ordering the change-set
	// payload gets. See changeSetFile.Ordinal.
	Ordinal int64 `json:"ordinal"`
}

type snapshotFile struct {
	Path    string `json:"path"`
	BlobSHA string `json:"blob_sha"`
	Size    int64  `json:"size"`
}

// WebhookSource is the attribution the receiver stamps onto a delivery so the
// compiler and any downstream consumer know the owning tenant and boundary
// without a second lookup.
type WebhookSource struct {
	SigningSecret string
	OrgID         string
	BoundaryID    string
}

// ResolveWebhookSource returns the signing secret and tenant attribution for an
// inbound webhook, in one cross-tenant control-plane read (the receiver is
// unauthenticated). An unknown or webhook-unconfigured source returns
// ErrDatasourceSourceNotFound so the receiver answers it exactly like a
// signature failure.
func (s *Service) ResolveWebhookSource(ctx context.Context, sourceID string) (*WebhookSource, error) {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return nil, ErrDatasourceSourceNotFound
	}
	if s.datasourceCipher == nil {
		return nil, errors.New("datasource secret cipher is not configured")
	}
	source, err := s.store.GetDatasourceSourceByID(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	if source == nil || !source.WebhookConfigured() {
		return nil, ErrDatasourceSourceNotFound
	}
	secret, err := s.datasourceCipher.DecryptSecret(ctx, DatasourceWebhookSecretPurpose(sourceID), source.WebhookSecretRef)
	if err != nil {
		return nil, err
	}
	return &WebhookSource{SigningSecret: secret, OrgID: source.OrgID, BoundaryID: source.BoundaryNodeID}, nil
}

// DatasourceDeliveryOrderingKey is the FIFO ordering key the receiver and the
// reconcile scheduler stamp on every job for a source, so the platform leases
// one in-flight delivery per source.
func DatasourceDeliveryOrderingKey(sourceID string) *jobsv1.JobOrderingKey {
	return &jobsv1.JobOrderingKey{
		Namespace:  datasourceDeliveryOrderingNamespace,
		Components: []string{sourceID},
	}
}

// NewDatasourceDeliveryJobHandler adapts the change-set compiler and the
// reconcile job to the leased worker. A source deleted between enqueue and lease
// is a no-op success; a malformed payload is terminal; a GitHub or store failure
// stays retryable.
func (s *Service) NewDatasourceDeliveryJobHandler() jobs.Handler {
	return func(ctx context.Context, envelope *jobsv1.JobEnvelope) (resultErr error) {
		if envelope.GetQueue() != DatasourceDeliveryQueue {
			return jobs.NewProcessingError("datasource.invalid_job", "unexpected datasource delivery job routing", false)
		}
		sourceID := envelope.GetAttributes()[attrSourceID]
		if sourceID == "" {
			return jobs.NewProcessingError("datasource.invalid_job", "datasource delivery job has no source id", false)
		}
		source, err := s.store.GetDatasourceSourceByID(ctx, sourceID)
		if err != nil {
			return err
		}
		if source == nil {
			return nil
		}
		defer func() {
			if resultErr != nil {
				resultErr = datasourceProcessingError(resultErr)
				trigger := "reconcile"
				if envelope.GetTopic() == datasourcePushTopic {
					trigger = "webhook"
				} else if envelope.GetAttributes()[attrReconcileMode] == reconcileModeForce {
					trigger = "manual"
				}
				fields := datasourceFailureFields(resultErr, source.Repo, trigger)
				fields["job_id"] = envelope.GetId()
				fields["attempt"] = int(envelope.GetAttemptCount())
				s.emit(ctx, source.ID, "system", EventDatasourceSyncFailed, "datasource", source.ID, source.OrgID, fields)
			}
		}()

		// Only GitHub sources are enqueued here today, but the compiler and
		// reconcile paths assume a GitHub token + repo; a non-GitHub source would
		// never become processable, so drop it terminally rather than driving
		// GitHub calls against it.
		if source.Provider != DatasourceProviderGitHub {
			return jobs.NewProcessingError("datasource.not_github", "datasource delivery for a non-GitHub source", false)
		}

		switch envelope.GetTopic() {
		case datasourcePushTopic:
			_, err := s.CompileGitHubDelivery(ctx, source, envelope.GetPayload(), envelope.GetAttributes()[attrDeliveryID])
			if errors.Is(err, ErrMalformedDelivery) {
				return jobs.NewProcessingError("datasource.malformed_delivery", err.Error(), false)
			}
			return err
		case datasourceReconcileTopic:
			force := envelope.GetAttributes()[attrReconcileMode] == reconcileModeForce
			_, err := s.ReconcileGitHubSource(ctx, source, force)
			return err
		default:
			return jobs.NewProcessingError("datasource.invalid_job", "unexpected datasource delivery topic", false)
		}
	}
}

// CompileGitHubDelivery turns one raw push delivery into a change set. It applies
// the branch filter, drops stale/redelivered/out-of-order deliveries against the
// cursor, diffs from the cursor (not the delivery's own `before`) so a missed
// delivery is caught up, and snapshots when a force push or divergence makes an
// incremental diff impossible. The cursor advances only after every op is
// durably enqueued.
func (s *Service) CompileGitHubDelivery(ctx context.Context, source *DatasourceSource, delivery []byte, deliveryID string) (DeliveryDisposition, error) {
	w := wool.Get(ctx).In("CompileGitHubDelivery")
	if s.datasourceCipher == nil || s.datasourceJobs == nil || s.newGitHubClient == nil {
		return "", w.NewError("datasource connector is not configured")
	}

	var push githubPushPayload
	if err := json.Unmarshal(delivery, &push); err != nil {
		return "", ErrMalformedDelivery
	}
	if push.After == "" || push.Ref == "" {
		return "", ErrMalformedDelivery
	}

	client, err := s.githubClientForSource(ctx, source)
	if err != nil {
		return "", err
	}

	branch := source.Branch
	if branch == "" {
		branch, err = client.DefaultBranch(ctx, source.Repo)
		if err != nil {
			return "", w.Wrapf(err, "resolve default branch")
		}
	}
	if push.Ref != "refs/heads/"+branch {
		w.Info("dropping delivery for other branch", wool.Field("ref", push.Ref), wool.Field("disposition", string(DispositionIgnoredBranch)))
		return DispositionIgnoredBranch, nil
	}

	if push.Deleted {
		s.emit(ctx, source.ID, "system", EventDatasourceBranchDeleted, "datasource", source.ID, source.OrgID,
			map[string]any{"ref": push.Ref, "delivery_id": deliveryID})
		return DispositionBranchDeleted, nil
	}

	cursor := source.LastIngestedCommit
	if cursor != "" {
		if cursor == push.After {
			return DispositionStale, nil
		}
		// after...cursor ahead|identical ⇒ after is an ancestor of the cursor:
		// a redelivery, an out-of-order delivery, or an already-ingested commit.
		ancestry, err := client.Compare(ctx, source.Repo, push.After, cursor)
		if err == nil && (ancestry.Status == github.CompareStatusAhead || ancestry.Status == github.CompareStatusIdentical) {
			return DispositionStale, nil
		}
	}

	base := cursor
	if base == "" && !push.Created && push.Before != "" && push.Before != zeroSHA {
		base = push.Before
	}
	if base == "" {
		return s.snapshotAt(ctx, source, client, push.After, deliveryID, false)
	}

	comparison, err := client.Compare(ctx, source.Repo, base, push.After)
	if err != nil {
		if errors.Is(err, github.ErrNotFound) {
			// base commit no longer reachable (force push) — snapshot.
			return s.snapshotAt(ctx, source, client, push.After, deliveryID, true)
		}
		return "", w.Wrapf(err, "compare %s...%s", base, push.After)
	}
	if comparison.Status == github.CompareStatusDiverged || comparison.Truncated {
		return s.snapshotAt(ctx, source, client, push.After, deliveryID, true)
	}
	if comparison.Status == github.CompareStatusBehind {
		// head is an ancestor of the base: a redelivered or out-of-order older
		// push. The ancestry pre-check should have dropped it, but that check
		// tolerates a transient Compare error — so guard here too, at the point the
		// cursor would otherwise move backward. Compiling this diff would re-emit
		// reverted content as new versions and rewind the cursor, so drop it.
		return DispositionStale, nil
	}

	ops := s.changeOps(comparison.Files, source.Paths)
	changeSet := base + "..." + push.After
	for _, op := range ops {
		if err := s.enqueueChangeSetFile(ctx, source, client, op, branch, push.After, changeSet, deliveryID); err != nil {
			return "", w.Wrapf(err, "enqueue %s", op.path)
		}
	}
	if err := s.advanceCursor(ctx, source.ID, push.After, deliveryID); err != nil {
		return "", w.Wrapf(err, "advance cursor")
	}
	s.emit(ctx, source.ID, "system", EventDatasourceChangeSetCompiled, "datasource", source.ID, source.OrgID,
		map[string]any{"base": base, "head": push.After, "ops": len(ops), "mode": "compare", "delivery_id": deliveryID})
	return DispositionCompiled, nil
}

// ReconcileGitHubSource snapshots the source at its current branch head. When
// force is false (periodic reconcile) it snapshots only if the head differs from
// the cursor; when force is true ("Sync now") it always snapshots. It reports
// whether a snapshot was enqueued.
func (s *Service) ReconcileGitHubSource(ctx context.Context, source *DatasourceSource, force bool) (bool, error) {
	w := wool.Get(ctx).In("ReconcileGitHubSource")
	if s.datasourceCipher == nil || s.datasourceJobs == nil || s.newGitHubClient == nil {
		return false, w.NewError("datasource connector is not configured")
	}
	client, err := s.githubClientForSource(ctx, source)
	if err != nil {
		return false, err
	}

	branch := source.Branch
	if branch == "" {
		branch, err = client.DefaultBranch(ctx, source.Repo)
		if err != nil {
			return false, w.Wrapf(err, "resolve default branch")
		}
	}
	head, err := client.ResolveCommit(ctx, source.Repo, branch)
	if err != nil {
		return false, w.Wrapf(err, "resolve commit")
	}
	if !force && head == source.LastIngestedCommit {
		return false, nil
	}
	disp, err := s.snapshotAt(ctx, source, client, head, "", false)
	if err != nil {
		return false, err
	}
	// Report whether a snapshot was actually enqueued. When the manifest overran
	// the ingest cap, snapshotAt degrades the source and returns DispositionDegraded
	// with a nil error; reporting true there would tell "Sync now" a snapshot was
	// dispatched when the source was in fact parked, so key the bool off the
	// disposition rather than the absence of an error.
	return disp == DispositionSnapshot, nil
}

// snapshotAt enqueues a full-tree manifest at commit and advances the cursor. It
// is the reconcile path for a created branch, a force push, a truncated compare,
// the periodic reconcile, and an explicit "Sync now". forcePush records the
// force-push audit alongside the change-set audit.
func (s *Service) snapshotAt(ctx context.Context, source *DatasourceSource, client GitHubContentClient, commit, deliveryID string, forcePush bool) (DeliveryDisposition, error) {
	w := wool.Get(ctx).In("snapshotAt")
	files, err := client.ListFiles(ctx, source.Repo, commit, source.Paths)
	if err != nil {
		return "", w.Wrapf(err, "list tree at %s", commit)
	}
	manifest := snapshotManifest{Repo: source.Repo, Commit: commit, Files: make([]snapshotFile, 0, len(files))}
	for _, f := range files {
		manifest.Files = append(manifest.Files, snapshotFile{Path: f.Path, BlobSHA: f.SHA, Size: f.Size})
	}
	ordinal, err := s.allocateOrdinal(ctx, source.ID)
	if err != nil {
		return "", w.Wrapf(err, "allocate ordinal")
	}
	manifest.Ordinal = ordinal
	payload, err := json.Marshal(manifest)
	if err != nil {
		return "", w.Wrapf(err, "encode snapshot manifest")
	}
	if len(payload) > maxIngestPayload {
		// Paging a large manifest across inbox jobs is issue #487 open question 3;
		// until the object-storage manifest seam lands, a manifest past the inbox
		// cap cannot be delivered. Failing terminally here dead-letters the job, but
		// the reconcile schedule was already bumped, so the source would re-enqueue
		// and dead-letter every interval forever with no visible status. Instead
		// park the source in the degraded state (which clears its schedule and drops
		// it from the reconcile sweep) and record why, so an operator sees it and
		// resets it once the manifest fits. Acknowledged, not retried.
		reason := SnapshotTooLargeDegradeReason(len(payload), maxIngestPayload)
		// Degrading is a state transition, so only write and audit when the
		// source is not already degraded. A source stuck oversized is retried by
		// "Sync now" (SyncDatasourceSource ignores status), and each such attempt
		// re-enters this branch; without the guard every retry would rewrite the
		// row and emit another snapshot_too_large event, burying the one real
		// transition under audit spam. The status read is reliable because the
		// per-source FIFO ordering key makes this the only in-flight delivery for
		// the source. Acknowledged, not retried.
		if source.Status != DatasourceStatusDegraded {
			if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
				return s.store.MarkDatasourceSourceDegraded(ctx, source.ID, reason)
			}); err != nil {
				return "", w.Wrapf(err, "degrade oversized source")
			}
			s.emit(ctx, source.ID, "system", EventDatasourceSnapshotTooLarge, "datasource", source.ID, source.OrgID,
				map[string]any{"head": commit, "bytes": len(payload), "limit": maxIngestPayload, "delivery_id": deliveryID})
		}
		return DispositionDegraded, nil
	}
	if _, err := s.datasourceJobs.EnqueueJob(ctx, &jobsv1.EnqueueJobRequest{
		Job: &jobsv1.NewJob{
			Direction:      jobsv1.JobDirection_JOB_DIRECTION_INBOX,
			Scope:          &jobsv1.JobScope{Value: &jobsv1.JobScope_Global{Global: true}},
			Queue:          datasourceIngestQueue,
			Topic:          datasourceSnapshotTopic,
			Source:         datasourceSyncSource,
			IdempotencyKey: ingestIdempotencyKey(source.ID, commit, "\x00snapshot"),
			SchemaVersion:  datasourceChangeSetSchemaVersion,
			Payload:        payload,
			ContentType:    "application/json",
			MaxAttempts:    datasourceIngestMaxAttempts,
			Attributes: map[string]string{
				attrSourceID:   source.ID,
				attrOrgID:      source.OrgID,
				attrBoundaryID: source.BoundaryNodeID,
				attrRepo:       source.Repo,
				attrCommit:     commit,
				attrDeliveryID: deliveryID,
			},
		},
	}); err != nil {
		return "", w.Wrapf(err, "enqueue snapshot")
	}
	if err := s.advanceCursor(ctx, source.ID, commit, deliveryID); err != nil {
		return "", w.Wrapf(err, "advance cursor")
	}
	if source.Status == DatasourceStatusDegraded {
		// This source was parked degraded by an earlier oversized snapshot; a
		// snapshot has now fit within the ingest cap, so return it to active and
		// restore its reconcile schedule. Gated on the current status so the
		// common already-active path neither writes nor emits. Recovery is
		// snapshot-only on purpose: an incremental compare compiling proves
		// nothing about the full-tree manifest size, so only snapshotAt — the
		// full-tree path — clears the flag. The status read is reliable because
		// the per-source FIFO ordering key makes this the only in-flight delivery.
		if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
			return s.store.ClearDatasourceSourceDegraded(ctx, source.ID, datasourceInstallationReasons)
		}); err != nil {
			return "", w.Wrapf(err, "clear degraded source")
		}
		s.emit(ctx, source.ID, "system", EventDatasourceSourceRecovered, "datasource", source.ID, source.OrgID,
			map[string]any{"head": commit, "delivery_id": deliveryID})
	}
	if forcePush {
		s.emit(ctx, source.ID, "system", EventDatasourceForcePushReconciled, "datasource", source.ID, source.OrgID,
			map[string]any{"head": commit, "delivery_id": deliveryID})
	}
	s.emit(ctx, source.ID, "system", EventDatasourceChangeSetCompiled, "datasource", source.ID, source.OrgID,
		map[string]any{"base": "", "head": commit, "ops": len(manifest.Files), "mode": "snapshot", "delivery_id": deliveryID})
	return DispositionSnapshot, nil
}

// changeOps maps a compare's files to ingest ops under the source's path filter.
// A rename is a rename only when both endpoints are in scope; a rename into scope
// is an upsert of the new path, a rename out of scope is a delete of the old
// path. Ops are returned in path order so a crash mid-set replays deterministically.
func (s *Service) changeOps(files []github.ChangedFile, paths []string) []changeOp {
	var ops []changeOp
	for _, f := range files {
		switch f.Status {
		case "added", "modified", "changed", "copied":
			if pathInScope(f.Filename, paths) {
				ops = append(ops, changeOp{path: f.Filename, blobSHA: f.SHA, changeType: upsertChangeType(f.Status)})
			}
		case "removed":
			if pathInScope(f.Filename, paths) {
				ops = append(ops, changeOp{path: f.Filename, changeType: changeTypeRemoved})
			}
		case "renamed":
			fromIn := pathInScope(f.PreviousFilename, paths)
			toIn := pathInScope(f.Filename, paths)
			switch {
			case fromIn && toIn:
				ops = append(ops, changeOp{path: f.Filename, prevPath: f.PreviousFilename, blobSHA: f.SHA, changeType: changeTypeRenamed})
			case toIn:
				ops = append(ops, changeOp{path: f.Filename, blobSHA: f.SHA, changeType: changeTypeAdded})
			case fromIn:
				ops = append(ops, changeOp{path: f.PreviousFilename, changeType: changeTypeRemoved})
			}
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].path < ops[j].path })
	return ops
}

func upsertChangeType(status string) string {
	if status == "added" || status == "copied" {
		return changeTypeAdded
	}
	return changeTypeModified
}

// enqueueChangeSetFile emits one v2 per-file ingest job. An upsert/rename fetches
// the blob inline when it fits the payload cap, else omits it and carries a
// signed content ticket the document store redeems through ResolveContentTicket.
// A delete carries no content.
func (s *Service) enqueueChangeSetFile(ctx context.Context, source *DatasourceSource, client GitHubContentClient, op changeOp, ref, commit, changeSet, deliveryID string) error {
	w := wool.Get(ctx).In("enqueueChangeSetFile")
	file := changeSetFile{
		Repo:       source.Repo,
		Path:       op.path,
		PrevPath:   op.prevPath,
		Ref:        "refs/heads/" + ref,
		Commit:     commit,
		BlobSHA:    op.blobSHA,
		ChangeType: op.changeType,
	}
	if op.changeType != changeTypeRemoved {
		content, err := client.GetFileContent(ctx, source.Repo, commit, op.path)
		switch {
		case errors.Is(err, github.ErrFileTooLarge):
			ticket, err := s.mintContentTicket(source.ID, op.blobSHA)
			if err != nil {
				return err
			}
			file.ContentTicket = ticket
		case err != nil:
			return w.Wrapf(err, "fetch content")
		case len(content) > maxIngestPayload:
			ticket, err := s.mintContentTicket(source.ID, op.blobSHA)
			if err != nil {
				return err
			}
			file.ContentTicket = ticket
		default:
			file.Content = &content
		}
	}
	ordinal, err := s.allocateOrdinal(ctx, source.ID)
	if err != nil {
		return w.Wrapf(err, "allocate ordinal")
	}
	file.Ordinal = ordinal
	payload, err := json.Marshal(file)
	if err != nil {
		return w.Wrapf(err, "encode change-set file")
	}
	_, err = s.datasourceJobs.EnqueueJob(ctx, &jobsv1.EnqueueJobRequest{
		Job: &jobsv1.NewJob{
			Direction:      jobsv1.JobDirection_JOB_DIRECTION_INBOX,
			Scope:          &jobsv1.JobScope{Value: &jobsv1.JobScope_Global{Global: true}},
			Queue:          datasourceIngestQueue,
			Topic:          datasourceSyncTopic,
			Source:         datasourceSyncSource,
			IdempotencyKey: ingestIdempotencyKey(source.ID, commit, op.path),
			SchemaVersion:  datasourceChangeSetSchemaVersion,
			Payload:        payload,
			ContentType:    "application/json",
			MaxAttempts:    datasourceIngestMaxAttempts,
			Attributes: map[string]string{
				attrSourceID:   source.ID,
				attrOrgID:      source.OrgID,
				attrBoundaryID: source.BoundaryNodeID,
				attrRepo:       source.Repo,
				attrPath:       op.path,
				attrRef:        file.Ref,
				attrSHA:        op.blobSHA,
				attrCommit:     commit,
				attrChangeType: op.changeType,
				attrDeliveryID: deliveryID,
				attrChangeSet:  changeSet,
			},
		},
	})
	return err
}

func (s *Service) mintContentTicket(sourceID, blobSHA string) (string, error) {
	if s.datasourceTicketSigner == nil {
		return "", errors.New("datasource content ticket signer is not configured")
	}
	if blobSHA == "" {
		return "", errors.New("datasource: cannot mint a content ticket without a blob sha")
	}
	return s.datasourceTicketSigner.mint(sourceID, blobSHA, time.Now().UTC())
}

func (s *Service) advanceCursor(ctx context.Context, sourceID, commit, deliveryID string) error {
	return s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		return s.store.AdvanceDatasourceCursor(ctx, sourceID, commit, deliveryID)
	})
}

// allocateOrdinal hands out the next strictly-increasing per-source ordinal for
// one emitted payload, in its own control-plane transaction. Each payload draws a
// distinct ordinal so a consumer can order the payload stream per source and
// reject a stale or out-of-order replay. Strictly increasing is the guarantee,
// not density: a crash between allocation and enqueue, or an idempotent
// re-enqueue on redelivery (the enqueue is keyed by (source, commit,
// path/snapshot), so a retry keeps the already-delivered payload and its original
// ordinal), only leaves a gap in the sequence — never a repeated or backward
// ordinal. A gap is therefore expected and is not a dropped payload.
//
// The ordinal ordering matches enqueue ordering only because a single source's
// deliveries are compiled one at a time: the row-lock the allocating UPDATE takes
// keeps values unique and increasing under concurrency, but if two compilers ever
// raced on the same source, the one that allocated the lower ordinal could enqueue
// after the higher — decoupling ordinal order from enqueue order. The per-source
// ordering contract therefore rests on serial per-source delivery processing, not
// on the ordinal allocation alone.
func (s *Service) allocateOrdinal(ctx context.Context, sourceID string) (int64, error) {
	var ordinal int64
	err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		var err error
		ordinal, err = s.store.AllocateDatasourceOrdinal(ctx, sourceID)
		return err
	})
	return ordinal, err
}

// RunDatasourceReconcile is the periodic sweep: it enqueues a reconcile job for
// every active GitHub source whose schedule has elapsed and reschedules it. The
// job itself resolves the head and snapshots only if it moved, so the sweep does
// no GitHub work and cannot be slowed by one unreachable repo.
func (s *Service) RunDatasourceReconcile(ctx context.Context) (int, error) {
	w := wool.Get(ctx).In("RunDatasourceReconcile")
	if s.datasourceJobs == nil {
		return 0, w.NewError("datasource connector is not configured")
	}
	var due []*DatasourceSource
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		found, err := s.store.ListDatasourceSourcesDueForReconcile(ctx, time.Now().UTC(), datasourceReconcileBatchSize)
		due = found
		return err
	}); err != nil {
		return 0, w.Wrapf(err, "list due sources")
	}
	enqueued := 0
	for _, source := range due {
		if err := s.enqueueReconcile(ctx, source, reconcileModeConditional); err != nil {
			w.Warn("enqueue reconcile failed", wool.Field("source", source.ID), wool.ErrField(err))
			continue
		}
		if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
			return s.store.BumpDatasourceReconcile(ctx, source.ID)
		}); err != nil {
			return enqueued, w.Wrapf(err, "reschedule reconcile")
		}
		enqueued++
	}
	return enqueued, nil
}

func (s *Service) enqueueReconcile(ctx context.Context, source *DatasourceSource, mode string) error {
	_, err := s.datasourceJobs.EnqueueJob(ctx, &jobsv1.EnqueueJobRequest{
		Job: &jobsv1.NewJob{
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
				attrReconcileMode: mode,
			},
		},
	})
	return err
}

// pathInScope reports whether p is under one of the source's path prefixes at a
// segment boundary. An empty prefix set matches the whole repository.
func pathInScope(p string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, prefix := range prefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}
