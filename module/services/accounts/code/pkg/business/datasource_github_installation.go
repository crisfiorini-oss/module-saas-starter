package business

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/codefly-dev/core/wool"

	jobsv1 "accounts/pkg/gen/saas/jobs/v1"
	"accounts/pkg/githubconnector"
	"accounts/pkg/jobs"
)

// The App-level lifecycle seam. These mirror the constants the receiver stamps
// (pkg/datasource, issue #691); that package imports this one, so they cannot
// be shared without an import cycle.
const (
	DatasourceInstallationQueue             = "datasource.installations"
	datasourceInstallationTopic             = "datasource.github.installation"
	datasourceInstallationOrderingNamespace = "datasource.installation"
	attrInstallationID                      = "datasource.installation_id"

	// datasourceInstallationRecheckSource marks the jobs this host enqueues for
	// itself, as opposed to the ones a verified delivery produced. It must stay
	// in step with datasource.GitHubAppWebhookSchemaVersion so both producers
	// describe the same envelope to one consumer.
	datasourceInstallationRecheckSource = "datasource.installation.recheck"
	datasourceInstallationSchemaVersion = 1

	// datasourceInstallationPageSize bounds one read of an installation's
	// sources. An installation can cover any number of repositories across any
	// number of tenants, so the reconcile pages through them rather than holding
	// the whole set.
	datasourceInstallationPageSize = 100

	// datasourceInstallationRecheckBatch bounds one sweep.
	datasourceInstallationRecheckBatch = 100

	// datasourceInstallationRecheckInterval is how often one parked installation
	// is re-verified. The sweep ticks far more often than that; the window is
	// what throttles it, through the jobs platform's idempotency key.
	datasourceInstallationRecheckInterval = 30 * time.Minute
)

// Why an App-backed source was parked. These are the exact strings written to
// status_reason and the set the reconciler will lift again, so they are
// matched, not just displayed: editing one strands sources already degraded
// under the old text until an operator resets them.
const (
	DatasourceReasonInstallationRepositoryUnavailable = "The GitHub App installation no longer grants access to this repository. Reinstall the App or re-select this repository to resume syncing."
	DatasourceReasonInstallationSuspended             = "The GitHub App installation for this source is suspended. Unsuspend it in GitHub to resume syncing."
)

// The same causes as audit codes. The operator-facing sentence above is matched
// against stored rows, so it cannot double as the analytics discriminator:
// rewording it for operators would silently re-type historical audit records.
// The codes are load-bearing in the other direction — they are the values
// consumers filter and aggregate on — so neither string may be edited once
// published; a changed cause is a new pair.
const (
	DatasourceAccessLostRepositoryUnavailable = "repository_unavailable"
	DatasourceAccessLostSuspended             = "suspended"
)

// datasourceInstallationReasonCodes pairs every cause this path may write with
// the code that names it on the audit trail. It is the one place the two
// vocabularies meet, so a cause cannot exist with a sentence and no code.
//
// Every lookup through it is total by construction: a park's sentence comes from
// githubInstallationAccess, which returns only these keys, and a revive's comes
// back from an UPDATE that matched status_reason against the same set.
var datasourceInstallationReasonCodes = map[string]string{
	DatasourceReasonInstallationRepositoryUnavailable: DatasourceAccessLostRepositoryUnavailable,
	DatasourceReasonInstallationSuspended:             DatasourceAccessLostSuspended,
}

// datasourceInstallationReasons bounds what this path may park over, revive and
// re-label: a source the change-set compiler parked for a structural fault of
// its own must stay parked when App access returns. It is also what the recheck
// sweep selects on.
var datasourceInstallationReasons = []string{
	DatasourceReasonInstallationRepositoryUnavailable,
	DatasourceReasonInstallationSuspended,
}

// ErrGitHubAppWebhookUnconfigured reports that this deployment registered no
// App webhook secret, so no App-level delivery can be verified.
var ErrGitHubAppWebhookUnconfigured = errors.New("business: no github app webhook secret configured")

// AppWebhookSecret hands the App-level receiver the registration's webhook
// secret. An unconfigured deployment returns ErrGitHubAppWebhookUnconfigured,
// which the receiver answers exactly like a signature failure.
func (s *Service) AppWebhookSecret(_ context.Context) (string, error) {
	if s.githubAppWebhookSecret == "" {
		return "", ErrGitHubAppWebhookUnconfigured
	}
	return s.githubAppWebhookSecret, nil
}

// GitHubAppWebhookConfigured reports whether this deployment can verify the
// App's own lifecycle deliveries at all, i.e. whether the App-level receiver
// should be mounted.
func (s *Service) GitHubAppWebhookConfigured() bool {
	return s.GitHubAppConfigured() && s.githubAppWebhookSecret != ""
}

// NewDatasourceInstallationJobHandler adapts the installation reconciler to the
// leased worker. The delivery body is not read here: the job carries only which
// installation to re-examine, and the reconciler asks GitHub what is true now.
func (s *Service) NewDatasourceInstallationJobHandler() jobs.Handler {
	return func(ctx context.Context, envelope *jobsv1.JobEnvelope) error {
		if envelope.GetQueue() != DatasourceInstallationQueue || envelope.GetTopic() != datasourceInstallationTopic {
			return jobs.NewProcessingError("datasource.invalid_job", "unexpected datasource installation job routing", false)
		}
		installationID := envelope.GetAttributes()[attrInstallationID]
		if installationID == "" {
			return jobs.NewProcessingError("datasource.invalid_job", "datasource installation job has no installation id", false)
		}
		return s.ReconcileGitHubInstallation(ctx, installationID)
	}
}

// ReconcileGitHubInstallation brings every source bound to one App installation
// back in line with the access GitHub currently grants. It is driven by an
// App-level delivery but never acts on one: the delivery names an installation,
// and everything else is re-derived, so a replayed suspend cannot re-park a
// source whose installation has since been restored.
//
// Losing access parks a source; it never deletes one. The row keeps its
// boundary, path scope, ingest cursor, grants and audit history, so restoring
// access resumes where the source left off instead of re-ingesting it, and the
// content already ingested stays governed by the tenant's own retention policy
// rather than by a third party's webhook.
//
// One installation can cover sources in several organizations, so a source that
// cannot be resolved is recorded and stepped over rather than returned on:
// failing the whole job at the first bad repository would leave every source
// behind it — including other tenants' — unexamined.
func (s *Service) ReconcileGitHubInstallation(ctx context.Context, installationID string) error {
	w := wool.Get(ctx).In("ReconcileGitHubInstallation")
	if s.githubConnector == nil || !s.GitHubAppConfigured() {
		return jobs.NewProcessingError("datasource.github_app_unconfigured",
			"This deployment has no GitHub App registration to verify an installation against. Restore the App registration. This job will not retry.", false)
	}

	registration := githubconnector.AppCredential{AppID: s.githubAppID, PrivateKeyPEM: s.githubAppKeyPEM}
	// One installation usually covers several sources, so its suspension state
	// is read once per covering installation rather than once per source.
	suspended := map[string]bool{}
	var failure error
	after := ""
	for {
		var page []*DatasourceSource
		if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
			var err error
			page, err = s.store.ListDatasourceSourcesByGitHubInstallation(ctx, installationID, after, datasourceInstallationPageSize)
			return err
		}); err != nil {
			return w.Wrapf(err, "list installation sources")
		}
		for _, source := range page {
			after = source.ID
			reason, covering, err := s.githubInstallationAccess(ctx, registration, source, suspended)
			if err != nil {
				w.Warn("installation access check failed", wool.Field("source", source.ID), wool.ErrField(err))
				failure = keepRetryable(failure, err)
				if !isPerSourceFault(err) {
					// Throttled, or GitHub is not answering: stop rather than ask
					// the same question for every source left. Nothing is stranded
					// by stopping — the failure is retryable and the retry walks
					// the installation again from the start.
					return failure
				}
				continue
			}
			// Correct the routing index from what GitHub just answered. The
			// column is stamped once, when a source is bound to the App, so an
			// uninstall-and-reinstall leaves it naming an installation that no
			// longer exists — and since this listing is BY that column, no later
			// delivery for the real installation would ever reach this source
			// again. Nothing else revisits it either: the recheck sweep selects
			// only degraded rows, and an actively syncing source is never
			// degraded. Left unwritten, the staleness is permanent.
			if covering != "" && covering != source.GitHubInstallationID {
				if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
					return s.store.SetDatasourceSourceGitHubInstallation(ctx, source.OrgID, source.ID, covering)
				}); err != nil {
					failure = keepRetryable(failure, err)
				} else {
					source.GitHubInstallationID = covering
				}
			}
			if err := s.applyGitHubInstallationAccess(ctx, source, reason); err != nil {
				failure = keepRetryable(failure, err)
			}
		}
		if len(page) < datasourceInstallationPageSize {
			return failure
		}
	}
}

// RunGitHubInstallationRecheck re-verifies the installations that still hold a
// parked source, and reports how many it enqueued.
//
// Parking takes a source out of the reconcile sweep, which selects only active
// sources, so without this the single route back to active is another App-level
// delivery — and GitHub does not retry a delivery forever. An `unsuspend` that
// arrives while this host is restarting would otherwise park a tenant's source
// permanently, with no audit entry and nothing to explain it. Restoration
// therefore gets a pull-side path of its own, on the same footing as the
// reconcile safety net that exists for lost push deliveries.
func (s *Service) RunGitHubInstallationRecheck(ctx context.Context) (int, error) {
	w := wool.Get(ctx).In("RunGitHubInstallationRecheck")
	if s.datasourceJobs == nil {
		return 0, w.NewError("datasource connector is not configured")
	}
	if !s.GitHubAppConfigured() {
		return 0, nil
	}

	// One job per installation per window. The sweep runs on the retention
	// ticker, far more often than an installation's state changes, so the
	// window — not the tick — sets the re-check rate: the jobs platform resolves
	// a repeated idempotency key to the job already queued.
	window := time.Now().UTC().Truncate(datasourceInstallationRecheckInterval).Unix()
	// The same window, counted rather than stamped, also chooses which page of
	// the parked set this sweep takes. A raw unix timestamp is unusable as a
	// rotation index: it advances by the window length, so modulo a page count
	// sharing a factor with it, some pages would never come up at all.
	counter := window / int64(datasourceInstallationRecheckInterval/time.Second)

	var installations []string
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		total, err := s.store.CountGitHubInstallationsPendingRecheck(ctx, datasourceInstallationReasons)
		if err != nil {
			return err
		}
		if total == 0 {
			return nil
		}
		// Rotate, because a source parked for a DELETED installation never comes
		// back: its id stays in this set permanently. A fixed first page would
		// fill with those and silently stop re-checking everything behind them —
		// including the live installation whose `unsuspend` delivery was lost,
		// which is the one case this sweep exists to catch. Deriving the page
		// from the window counter rather than from a cursor held in memory keeps
		// the rotation going across restarts, which a process-local cursor would
		// reset to the same first page on every deploy.
		offset := recheckPageOffset(counter, total, datasourceInstallationRecheckBatch)
		installations, err = s.store.ListGitHubInstallationsPendingRecheck(ctx, datasourceInstallationReasons, offset, datasourceInstallationRecheckBatch)
		return err
	}); err != nil {
		return 0, w.Wrapf(err, "list installations pending recheck")
	}
	enqueued := 0
	for _, installation := range installations {
		response, err := s.datasourceJobs.EnqueueJob(ctx, &jobsv1.EnqueueJobRequest{
			Job: &jobsv1.NewJob{
				Direction: jobsv1.JobDirection_JOB_DIRECTION_INBOX,
				Scope:     &jobsv1.JobScope{Value: &jobsv1.JobScope_Global{Global: true}},
				Queue:     DatasourceInstallationQueue,
				Topic:     datasourceInstallationTopic,
				Source:    datasourceInstallationRecheckSource,
				Ordering: &jobsv1.JobOrderingKey{
					Namespace:  datasourceInstallationOrderingNamespace,
					Components: []string{installation},
				},
				IdempotencyKey: fmt.Sprintf("%s:%s:%d", datasourceInstallationRecheckSource, installation, window),
				SchemaVersion:  datasourceInstallationSchemaVersion,
				// The same body the receiver records, because both producers
				// stamp the same schema version on this one queue: a consumer
				// that reads the payload rather than the attributes must not
				// find a different envelope depending on which produced it.
				Payload:     installationJobPayload(installation),
				ContentType: datasourceRequestContentType,
				MaxAttempts: datasourceDeliveryMaxAttempts,
				Attributes:  map[string]string{attrInstallationID: installation},
			},
		})
		if err != nil {
			// A conflicting key means this window's job is already recorded with
			// different bytes; either way the installation is covered.
			if !errors.Is(err, jobs.ErrIdempotencyConflict) {
				w.Warn("enqueue installation recheck failed", wool.Field("installation", installation), wool.ErrField(err))
			}
			continue
		}
		if response.GetDisposition() == jobsv1.JobEnqueueDisposition_JOB_ENQUEUE_DISPOSITION_INSERTED {
			enqueued++
		}
	}
	return enqueued, nil
}

// installationJobPayload is the body both producers of the installation queue
// write. The reconciler routes on the job's attributes, but the receiver and
// this sweep stamp one schema version on one queue, so their envelopes must not
// differ by producer. Marshalling a one-entry map of strings has no failure
// mode, which is why the error is not plumbed.
func installationJobPayload(installationID string) []byte {
	encoded, _ := json.Marshal(map[string]string{"installation_id": installationID})
	return encoded
}

// recheckPageOffset picks which page of the parked set one sweep takes. counter
// advances by exactly one per re-check window, so consecutive sweeps take
// consecutive pages and every parked installation is reached within one full
// rotation. Without that rotation the sweep re-reads its first page forever, and
// since a deleted installation can never regain access its sources stay parked
// permanently — so the dead accumulate at a fixed position and starve every live
// installation behind them.
func recheckPageOffset(counter int64, total, batch int) int {
	pages := int64((total + batch - 1) / batch)
	if pages <= 1 {
		return 0
	}
	return int(counter%pages) * batch
}

// githubInstallationAccess reports why a source can no longer read its
// repository, or "" when access is intact, together with the installation that
// actually covers the repository now. The sentence it returns is always a key of
// datasourceInstallationReasons, which is what makes the audit code lookup at
// the write site total.
//
// The question is put to GitHub per source and by repository — never by the
// installation id the delivery carried. A source rebound to a different
// installation since its routing column was stamped is then answered for the
// installation that actually covers it, so a stale column costs a redundant
// check rather than a wrong revocation.
func (s *Service) githubInstallationAccess(ctx context.Context, registration githubconnector.AppCredential, source *DatasourceSource, suspended map[string]bool) (string, string, error) {
	owner, repo, _ := strings.Cut(source.Repo, "/")
	covering, err := s.githubConnector.FindRepositoryInstallation(ctx, registration, owner, repo)
	if err != nil {
		if githubconnector.IsNotFound(err) {
			return DatasourceReasonInstallationRepositoryUnavailable, "", nil
		}
		return "", "", githubInstallationStateError(err)
	}

	isSuspended, known := suspended[covering]
	if !known {
		installation, err := s.githubConnector.GetInstallation(ctx, registration, covering)
		if err != nil {
			if githubconnector.IsNotFound(err) {
				return DatasourceReasonInstallationRepositoryUnavailable, covering, nil
			}
			return "", covering, githubInstallationStateError(err)
		}
		isSuspended = installation.SuspendedAt != nil
		suspended[covering] = isSuspended
	}
	if isSuspended {
		return DatasourceReasonInstallationSuspended, covering, nil
	}
	return "", covering, nil
}

// githubInstallationStateError classifies a failure to READ installation state,
// which is a different question from failing to mint a token and must not reuse
// githubInstallationTokenError.
//
// Minting answers "may this source still read that repository", so a 403 there
// is a real denial and terminal. Here the host authenticates as the App itself
// to ask what GitHub currently reports, and an absent installation already
// answered 404 further up. A 403 on this path is GitHub declining to serve the
// request — overwhelmingly a primary or secondary rate limit, which this path
// invites because it issues a request per source. Treating that as terminal
// dead-letters the job and silently drops the revocation the endpoint exists to
// deliver promptly, so everything except a rejected credential stays retryable.
func githubInstallationStateError(err error) error {
	var apiErr *githubconnector.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.StatusCode == http.StatusUnauthorized:
			return jobs.NewProcessingError(githubAppCredentialRejectedCode,
				"GitHub rejected this deployment's GitHub App credential. Check the registered App id and signing key. This job will not retry.", false)
		case apiErr.StatusCode == http.StatusForbidden,
			apiErr.StatusCode == http.StatusTooManyRequests,
			apiErr.StatusCode >= http.StatusInternalServerError:
			return jobs.NewProcessingError(githubAppStateUnavailableCode,
				"Could not read the GitHub App installation's current state. GitHub may be unavailable or rate limiting; this job may retry.", true)
		}
		// Any other refusal is about this one repository — a malformed name, say
		// — and says nothing about the App or about GitHub's willingness to
		// answer for the next source.
		return jobs.NewProcessingError(githubRepositoryUnreadableCode,
			"Could not read this repository's GitHub App installation. This source was skipped; the job may retry.", true)
	}
	// A transport failure is not specific to one repository either.
	return jobs.NewProcessingError(githubAppStateUnavailableCode,
		"Could not read the GitHub App installation's current state. GitHub may be unavailable or rate limiting; this job may retry.", true)
}

// The failure codes this path records. They are load-bearing beyond reporting:
// the reconcile loop decides from them whether a failure concerns one source or
// every remaining one.
const (
	githubAppCredentialRejectedCode = "datasource.github_app_credential_rejected"
	githubAppStateUnavailableCode   = "datasource.github_app_state_unavailable"
	githubRepositoryUnreadableCode  = "datasource.github_repository_unreadable"
)

// isPerSourceFault reports whether a failed access check concerns only the
// source it happened on. Everything else — a rejected credential, throttling,
// GitHub being unavailable — will answer the same way for every source left in
// the walk, and the job restarts that walk from its first page, so continuing
// past one spends a doomed request per remaining source and then repeats every
// request that already succeeded. That is load, applied to the exact limit that
// produced the failure.
func isPerSourceFault(err error) bool {
	var processing *jobs.ProcessingError
	return errors.As(err, &processing) && processing.Failure.GetCode() == githubRepositoryUnreadableCode
}

// keepRetryable prefers a retryable failure over a terminal one, so a job that
// hit both still comes back and finishes the work the transient error stopped.
func keepRetryable(existing, next error) error {
	if existing == nil {
		return next
	}
	var held *jobs.ProcessingError
	if errors.As(existing, &held) && held.Retryable {
		return existing
	}
	var candidate *jobs.ProcessingError
	if errors.As(next, &candidate) && candidate.Retryable {
		return next
	}
	return existing
}

// applyGitHubInstallationAccess parks or revives one source, and leaves every
// other status alone. Both writes carry their own predicate — active for a
// park, degraded-for-one-of-our-reasons for a revival — because the status read
// here comes from a page listed before any GitHub call, and this path is
// ordered per installation, not per source, so nothing stops an operator pause
// or a compiler degrade landing in between. The status checks below are only a
// fast path that saves a statement per unchanged source; the predicates in the
// UPDATEs are what actually decide.
//
// The park predicate is deliberately not active-only. A source parked for a
// deselected repository whose installation is later suspended is still degraded,
// so an active-only write would match no row and leave the recorded cause wrong
// for good; it therefore also writes over this path's own reasons, and only when
// the reason actually changes.
//
// Each transition is recorded on the tenant's audit spine, and only a real
// transition is: both emits are gated on the row the write actually matched, so
// a stale read can neither invent a record nor mislabel one. The actor is the
// system — this runs from a verified App-level delivery, not from anything a
// tenant asked for, and the change itself happened in a third party's account.
func (s *Service) applyGitHubInstallationAccess(ctx context.Context, source *DatasourceSource, reason string) error {
	w := wool.Get(ctx).In("applyGitHubInstallationAccess")
	if reason == "" {
		// The only cheap pre-check that is safe: the clear matches
		// status='degraded', and nothing outside this path — which is FIFO per
		// installation — can move a source INTO one of our reasons, so a stale
		// 'active' can only skip a clear that would have matched no row anyway.
		// It keeps the common healthy source from costing a write.
		if source.Status != DatasourceStatusDegraded {
			return nil
		}
		var restoredFrom string
		if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
			var err error
			restoredFrom, err = s.store.ClearDatasourceSourceInstallationDegraded(ctx, source.ID, datasourceInstallationReasons)
			return err
		}); err != nil {
			return w.Wrapf(err, "restore source")
		}
		if restoredFrom != "" {
			s.emit(ctx, source.ID, "system", EventDatasourceSourceAccessRestored, "datasource", source.ID, source.OrgID,
				map[string]any{
					"repo":            source.Repo,
					"installation_id": source.GitHubInstallationID,
					"restored_from":   datasourceInstallationReasonCodes[restoredFrom],
				})
		}
		return nil
	}
	if source.Status == DatasourceStatusDegraded && source.StatusReason == reason {
		return nil
	}
	var parked bool
	if err := s.store.WithControlPlane(ctx, func(ctx context.Context) error {
		var err error
		parked, err = s.store.MarkDatasourceSourceInstallationDegraded(ctx, source.ID, reason, datasourceInstallationReasons)
		return err
	}); err != nil {
		return w.Wrapf(err, "park source")
	}
	if parked {
		s.emit(ctx, source.ID, "system", EventDatasourceSourceAccessLost, "datasource", source.ID, source.OrgID,
			map[string]any{
				"repo":            source.Repo,
				"installation_id": source.GitHubInstallationID,
				"reason":          datasourceInstallationReasonCodes[reason],
			})
	}
	return nil
}
