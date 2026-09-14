package infra

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"accounts/pkg/business"
)

// datasourceSourceColumns is the shared projection; COALESCE keeps the optional
// text columns non-null so they scan into plain strings (repo is null for
// providers that have no repository), while last_synced_at and config stay
// nullable.
const datasourceSourceColumns = `
	id::text, org_id::text, provider, COALESCE(repo, ''), paths, COALESCE(branch, ''),
	boundary_node_id::text, credential_secret_ref, COALESCE(webhook_secret_ref, ''),
	status, COALESCE(status_reason, ''), last_synced_at, created_at, updated_at, config,
	COALESCE(last_ingested_commit, ''), last_ingested_at, COALESCE(last_delivery_id, ''),
	(EXTRACT(EPOCH FROM reconcile_interval))::bigint, next_reconcile_at,
	COALESCE(github_installation_id, '')`

func scanDatasourceSource(row pgx.Row) (*business.DatasourceSource, error) {
	var d business.DatasourceSource
	var config []byte
	var reconcileIntervalSeconds int64
	if err := row.Scan(
		&d.ID, &d.OrgID, &d.Provider, &d.Repo, &d.Paths, &d.Branch,
		&d.BoundaryNodeID, &d.CredentialSecretRef, &d.WebhookSecretRef,
		&d.Status, &d.StatusReason, &d.LastSyncedAt, &d.CreatedAt, &d.UpdatedAt, &config,
		&d.LastIngestedCommit, &d.LastIngestedAt, &d.LastDeliveryID,
		&reconcileIntervalSeconds, &d.NextReconcileAt, &d.GitHubInstallationID,
	); err != nil {
		return nil, err
	}
	d.ReconcileInterval = time.Duration(reconcileIntervalSeconds) * time.Second
	if len(config) > 0 {
		switch d.Provider {
		case business.DatasourceProviderAPI:
			var api business.APIDatasourceConfig
			if err := json.Unmarshal(config, &api); err != nil {
				return nil, err
			}
			d.API = &api
		case business.DatasourceProviderCrawler:
			var c business.CrawlerDatasourceConfig
			if err := json.Unmarshal(config, &c); err != nil {
				return nil, err
			}
			d.Crawler = &c
		case business.DatasourceProviderUpload:
			var u business.UploadDatasourceConfig
			if err := json.Unmarshal(config, &u); err != nil {
				return nil, err
			}
			d.Upload = &u
		}
	}
	return &d, nil
}

// InsertDatasourceSource writes a new connected Source. Runs under the caller's
// WithOrgTx.
func (s *PostgresStore) InsertDatasourceSource(ctx context.Context, source *business.DatasourceSource) error {
	paths := source.Paths
	if paths == nil {
		paths = []string{}
	}
	var payload any
	switch {
	case source.API != nil:
		payload = source.API
	case source.Crawler != nil:
		payload = source.Crawler
	case source.Upload != nil:
		payload = source.Upload
	}
	var config []byte
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		config = encoded
	}
	_, err := s.getQueryExecutor(ctx).Exec(ctx, `
		INSERT INTO datasource_sources (
			id, org_id, provider, repo, paths, branch, boundary_node_id,
			credential_secret_ref, webhook_secret_ref, status, config,
			reconcile_interval, next_reconcile_at, github_installation_id)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, NULLIF($6, ''), $7, $8, NULLIF($9, ''), $10, $11,
			make_interval(secs => $12), $13, NULLIF($14, ''))`,
		source.ID, source.OrgID, source.Provider, source.Repo, paths, source.Branch,
		source.BoundaryNodeID, source.CredentialSecretRef, source.WebhookSecretRef, source.Status, config,
		source.ReconcileInterval.Seconds(), source.NextReconcileAt, source.GitHubInstallationID,
	)
	return err
}

// AdvanceDatasourceCursor records the head commit fully enqueued as a change set
// and reschedules the periodic reconcile. next_reconcile_at is pushed out by the
// reconcile interval, or cleared when reconcile is disabled (interval 0). Runs
// under the caller's WithControlPlane.
func (s *PostgresStore) AdvanceDatasourceCursor(ctx context.Context, sourceID, commit, deliveryID string) error {
	_, err := s.getQueryExecutor(ctx).Exec(ctx, `
		UPDATE datasource_sources
		   SET last_ingested_commit = $2,
		       last_ingested_at     = NOW(),
		       last_delivery_id      = NULLIF($3, ''),
		       next_reconcile_at     = CASE WHEN reconcile_interval > INTERVAL '0'
		                                    THEN NOW() + reconcile_interval END,
		       updated_at            = NOW()
		 WHERE id = $1`, sourceID, commit, deliveryID)
	return err
}

// AllocateDatasourceOrdinal atomically hands out the next per-source delivery
// ordinal and advances the counter in one UPDATE, so ordinals are strictly
// increasing per source even under concurrent compilers. Returns the allocated
// ordinal (the value before the bump); the first allocation for a source returns
// 1. Runs under the caller's WithControlPlane (the leased compiler has no tenant
// context). The allocation commits with that transaction, independently of the
// job enqueue that follows, so a delivery that fails after allocating leaves a
// harmless gap — the sequence stays strictly increasing, never repeated or
// backward.
func (s *PostgresStore) AllocateDatasourceOrdinal(ctx context.Context, sourceID string) (int64, error) {
	var ordinal int64
	err := s.getQueryExecutor(ctx).QueryRow(ctx, `
		UPDATE datasource_sources
		   SET next_ordinal = next_ordinal + 1,
		       updated_at    = NOW()
		 WHERE id = $1
		 RETURNING next_ordinal - 1`, sourceID).Scan(&ordinal)
	return ordinal, err
}

// BumpDatasourceReconcile reschedules the periodic reconcile without touching the
// cursor. Runs under the caller's WithControlPlane.
func (s *PostgresStore) BumpDatasourceReconcile(ctx context.Context, sourceID string) error {
	_, err := s.getQueryExecutor(ctx).Exec(ctx, `
		UPDATE datasource_sources
		   SET next_reconcile_at = CASE WHEN reconcile_interval > INTERVAL '0'
		                                THEN NOW() + reconcile_interval END,
		       updated_at        = NOW()
		 WHERE id = $1`, sourceID)
	return err
}

// MarkDatasourceSourceDegraded parks a source the compiler cannot make progress
// on for a structural reason an operator must resolve (an oversized snapshot
// manifest). Flipping status off 'active' removes it from the reconcile sweep and
// its partial index, so it stops being re-selected — no schedule bump. Clearing
// next_reconcile_at keeps the row out of the due set even after an operator
// widens the interval. Runs under the caller's WithControlPlane (the leased
// compiler has no tenant context).
func (s *PostgresStore) MarkDatasourceSourceDegraded(ctx context.Context, sourceID string, reason business.DatasourceDegradeReason) error {
	_, err := s.getQueryExecutor(ctx).Exec(ctx, `
		UPDATE datasource_sources
		   SET status            = 'degraded',
		       status_reason     = $2,
		       next_reconcile_at = NULL,
		       updated_at        = NOW()
		 WHERE id = $1`, sourceID, reason.String())
	return err
}

// ClearDatasourceSourceDegraded returns a degraded source to active after a
// snapshot succeeds again, undoing MarkDatasourceSourceDegraded: it clears
// status_reason and restores next_reconcile_at from the reconcile interval (or
// leaves it NULL when reconcile is disabled) so the sweep resumes selecting it.
// The status='degraded' guard makes it a no-op on a source an operator has since
// paused, so recovery cannot silently override an operator pause. Runs under the
// caller's WithControlPlane (the leased compiler has no tenant context).
//
// excludeReasons names the degrades this path does not own, which it must not
// lift. Recovery here proves one thing — a snapshot fit within the ingest cap —
// and that says nothing about whether a GitHub App installation has started
// granting access again. Without the exclusion a successful snapshot would
// revive a source parked for withdrawn App access and record it as an ingest
// recovery, leaving that path's access_lost with no matching access_restored.
// status_reason is nullable, so it is coalesced: a legacy degraded row with no
// reason recorded stays clearable, where `NULL <> ALL(...)` would silently
// match nothing and strand it degraded for good.
func (s *PostgresStore) ClearDatasourceSourceDegraded(ctx context.Context, sourceID string, excludeReasons []string) error {
	_, err := s.getQueryExecutor(ctx).Exec(ctx, `
		UPDATE datasource_sources
		   SET status            = 'active',
		       status_reason     = '',
		       next_reconcile_at = CASE WHEN reconcile_interval > INTERVAL '0'
		                                THEN NOW() + reconcile_interval END,
		       updated_at        = NOW()
		 WHERE id = $1 AND status = 'degraded'
		   AND COALESCE(status_reason, '') <> ALL($2)`, sourceID, excludeReasons)
	return err
}

// MarkDatasourceSourceInstallationDegraded parks a source the GitHub App no
// longer grants access to, and re-labels one this path already parked when the
// cause changes. It is MarkDatasourceSourceDegraded narrowed on both sides: the
// row must be 'active' or already carry one of reasons, and its reason must
// actually differ.
//
// Every one of those is a predicate rather than a caller-side check because the
// App-level reconciler decides from a listing taken one or two GitHub round-trips
// earlier, while the change-set compiler degrades sources under a different job
// ordering namespace. A Go-side status check would let a stale 'active' overwrite
// that compiler degrade — discarding its reason and leaving the row carrying one
// of ours, which this path would then happily revive with the fault still
// standing. Requiring a real change also makes a redelivery write no row, so the
// caller's audit record follows a transition rather than an attempt.
//
// Runs under the caller's WithControlPlane.
func (s *PostgresStore) MarkDatasourceSourceInstallationDegraded(ctx context.Context, sourceID, reason string, reasons []string) (bool, error) {
	tag, err := s.getQueryExecutor(ctx).Exec(ctx, `
		UPDATE datasource_sources
		   SET status            = 'degraded',
		       status_reason     = $2,
		       next_reconcile_at = NULL,
		       updated_at        = NOW()
		 WHERE id = $1
		   AND status_reason IS DISTINCT FROM $2
		   AND (status = 'active' OR (status = 'degraded' AND status_reason = ANY($3)))`,
		sourceID, reason, reasons)
	return tag.RowsAffected() > 0, err
}

// ClearDatasourceSourceInstallationDegraded is ClearDatasourceSourceDegraded
// narrowed to the reasons the App-level reconciler writes, so restored App
// access revives only a source that path parked — a source the compiler
// degraded for a structural fault of its own keeps both its status and its
// reason. Matching the reason inside the UPDATE rather than against an earlier
// read keeps that decision atomic against a concurrent degrade, and returning
// the reason it replaced is what lets the caller name the cause the source
// recovered from: the row read before the UPDATE may not be the row it matched.
// Empty when no row matched. Runs under the caller's WithControlPlane.
func (s *PostgresStore) ClearDatasourceSourceInstallationDegraded(ctx context.Context, sourceID string, reasons []string) (string, error) {
	var cleared string
	// RETURNING yields the post-UPDATE row, where status_reason is already '',
	// so the reason being replaced is read in a locking CTE that runs against
	// the pre-UPDATE snapshot. FOR UPDATE makes the match and the write one
	// atomic step rather than a read this statement could race.
	err := s.getQueryExecutor(ctx).QueryRow(ctx, `
		WITH parked AS (
			SELECT id, status_reason
			  FROM datasource_sources
			 WHERE id = $1 AND status = 'degraded' AND status_reason = ANY($2)
			   FOR UPDATE
		)
		UPDATE datasource_sources d
		   SET status            = 'active',
		       status_reason     = '',
		       next_reconcile_at = CASE WHEN d.reconcile_interval > INTERVAL '0'
		                                THEN NOW() + d.reconcile_interval END,
		       updated_at        = NOW()
		  FROM parked p
		 WHERE d.id = p.id
		 RETURNING p.status_reason`, sourceID, reasons).Scan(&cleared)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return cleared, err
}

// CountGitHubInstallationsPendingRecheck reports how many distinct installations
// still hold a parked source. The sweep needs the size of the set, not just a
// page of it, to rotate across the whole of it — see the offset argument below.
// Control-plane.
func (s *PostgresStore) CountGitHubInstallationsPendingRecheck(ctx context.Context, reasons []string) (int, error) {
	var total int
	err := s.getQueryExecutor(ctx).QueryRow(ctx, `
		SELECT COUNT(DISTINCT github_installation_id)
		  FROM datasource_sources
		 WHERE status = 'degraded'
		   AND provider = 'github'
		   AND status_reason = ANY($1)
		   AND github_installation_id IS NOT NULL`, reasons).Scan(&total)
	return total, err
}

// ListGitHubInstallationsPendingRecheck returns one page of the distinct
// installations that still have a source parked for one of reasons. A parked
// source leaves the reconcile sweep (that sweep selects status='active'), so
// without this the only way back to active is another App-level delivery — and
// a delivery GitHub fails to hand over is not retried forever. This is the
// pull-side safety net that makes restoration independent of one webhook
// arriving. Control-plane.
//
// offset is what keeps that safety net from covering only its own first page.
// An installation that was deleted parks its sources permanently — access can
// never return — so those rows stay in this set for good. Reading a fixed first
// page every window therefore starves every installation sorting behind them
// once the permanently-parked fill one batch, and the caller rotates offset so
// each page is reached in turn.
func (s *PostgresStore) ListGitHubInstallationsPendingRecheck(ctx context.Context, reasons []string, offset, limit int) ([]string, error) {
	rows, err := s.getQueryExecutor(ctx).Query(ctx, `
		SELECT DISTINCT github_installation_id
		  FROM datasource_sources
		 WHERE status = 'degraded'
		   AND provider = 'github'
		   AND status_reason = ANY($1)
		   AND github_installation_id IS NOT NULL
		 ORDER BY github_installation_id
		 LIMIT $2 OFFSET $3`, reasons, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var installations []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		installations = append(installations, id)
	}
	return installations, rows.Err()
}

// ListDatasourceSourcesByGitHubInstallation returns one page of the GitHub
// sources bound to an App installation, ordered by id and starting after
// afterID, so a reconcile walks an installation of any size in bounded memory.
// The read spans tenants because an App-level delivery names an installation
// and no tenant, so it runs under the caller's WithControlPlane. Non-GitHub
// providers are excluded: the column is only ever stamped by a GitHub path, and
// a source of another provider must never be parked with a GitHub reason.
func (s *PostgresStore) ListDatasourceSourcesByGitHubInstallation(ctx context.Context, installationID, afterID string, limit int) ([]*business.DatasourceSource, error) {
	rows, err := s.getQueryExecutor(ctx).Query(ctx,
		`SELECT `+datasourceSourceColumns+`
		   FROM datasource_sources
		  WHERE github_installation_id = $1
		    AND provider = 'github'
		    AND ($2 = '' OR id::text > $2)
		  ORDER BY id::text
		  LIMIT $3`, installationID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []*business.DatasourceSource
	for rows.Next() {
		source, err := scanDatasourceSource(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

// SetDatasourceSourceGitHubInstallation stamps the routing index an App-level
// delivery resolves sources through. Runs under the caller's WithOrgTx, beside
// the credential envelope it indexes.
func (s *PostgresStore) SetDatasourceSourceGitHubInstallation(ctx context.Context, orgID, id, installationID string) error {
	_, err := s.getQueryExecutor(ctx).Exec(ctx, `
		UPDATE datasource_sources
		   SET github_installation_id = NULLIF($3, ''),
		       updated_at             = NOW()
		 WHERE id = $1 AND org_id = $2`, id, orgID, installationID)
	return err
}

// ListDatasourceSourcesDueForReconcile returns active GitHub sources whose
// reconcile is due, oldest schedule first. Runs under the caller's WithControlPlane.
func (s *PostgresStore) ListDatasourceSourcesDueForReconcile(ctx context.Context, now time.Time, limit int) ([]*business.DatasourceSource, error) {
	rows, err := s.getQueryExecutor(ctx).Query(ctx,
		`SELECT `+datasourceSourceColumns+`
		   FROM datasource_sources
		  WHERE status = 'active'
		    AND provider = 'github'
		    AND next_reconcile_at IS NOT NULL
		    AND next_reconcile_at <= $1
		  ORDER BY next_reconcile_at
		  LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []*business.DatasourceSource
	for rows.Next() {
		source, err := scanDatasourceSource(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

// ListDatasourceSources returns the org's Sources, newest first. Runs under the
// caller's WithOrgTx.
func (s *PostgresStore) ListDatasourceSources(ctx context.Context, orgID string) ([]*business.DatasourceSource, error) {
	rows, err := s.getQueryExecutor(ctx).Query(ctx,
		`SELECT `+datasourceSourceColumns+`
		   FROM datasource_sources
		  WHERE org_id = $1
		  ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []*business.DatasourceSource
	for rows.Next() {
		source, err := scanDatasourceSource(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

// GetDatasourceSource returns one org-scoped Source, or (nil, nil) when none
// matches. Runs under the caller's WithOrgTx.
func (s *PostgresStore) GetDatasourceSource(ctx context.Context, orgID, id string) (*business.DatasourceSource, error) {
	row := s.getQueryExecutor(ctx).QueryRow(ctx,
		`SELECT `+datasourceSourceColumns+`
		   FROM datasource_sources WHERE org_id = $1 AND id = $2`, orgID, id)
	source, err := scanDatasourceSource(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return source, nil
}

// DeleteDatasourceSource removes an org-scoped Source. Runs under the caller's
// WithOrgTx.
func (s *PostgresStore) DeleteDatasourceSource(ctx context.Context, orgID, id string) error {
	_, err := s.getQueryExecutor(ctx).Exec(ctx,
		`DELETE FROM datasource_sources WHERE org_id = $1 AND id = $2`, orgID, id)
	return err
}

// SetDatasourceSourceSynced records the last successful sync time. Runs under
// the caller's WithOrgTx.
func (s *PostgresStore) SetDatasourceSourceSynced(ctx context.Context, orgID, id string, syncedAt time.Time) error {
	_, err := s.getQueryExecutor(ctx).Exec(ctx, `
		UPDATE datasource_sources
		   SET last_synced_at = $3, updated_at = NOW()
		 WHERE org_id = $1 AND id = $2`, orgID, id, syncedAt)
	return err
}

// LockDatasourceSourceCredentialRef reads the credential envelope under a row
// lock so a refresh-and-rotate cycle (OAuth 2.0) serializes against a concurrent
// sync of the same source: the second caller blocks here until the first commits,
// then reads the freshly rotated envelope and skips its own refresh. Runs under
// the caller's WithOrgTx; the FOR UPDATE lock is held until that transaction
// commits. Returns ErrNoRows when the source is gone.
func (s *PostgresStore) LockDatasourceSourceCredentialRef(ctx context.Context, orgID, id string) (string, error) {
	var ref string
	err := s.getQueryExecutor(ctx).QueryRow(ctx, `
		SELECT credential_secret_ref
		  FROM datasource_sources
		 WHERE org_id = $1 AND id = $2
		   FOR UPDATE`, orgID, id).Scan(&ref)
	if err != nil {
		return "", err
	}
	return ref, nil
}

// UpdateDatasourceSourceCredential rotates the stored credential envelope in
// place, for a connector (OAuth 2.0) that refreshes and re-persists its token
// set at fetch time. Runs under the caller's WithOrgTx.
func (s *PostgresStore) UpdateDatasourceSourceCredential(ctx context.Context, orgID, id, credentialRef string) error {
	_, err := s.getQueryExecutor(ctx).Exec(ctx, `
		UPDATE datasource_sources
		   SET credential_secret_ref = $3, updated_at = NOW()
		 WHERE org_id = $1 AND id = $2`, orgID, id, credentialRef)
	return err
}

// GetDatasourceSourceByID is the unauthenticated webhook-receipt lookup: no
// tenant context, so it opens its own control-plane transaction (BYPASSRLS is a
// database capability, not a client-settable GUC). Returns (nil, nil) on miss.
func (s *PostgresStore) GetDatasourceSourceByID(ctx context.Context, id string) (*business.DatasourceSource, error) {
	var source *business.DatasourceSource
	err := s.WithControlPlane(ctx, func(ctx context.Context) error {
		row := s.getQueryExecutor(ctx).QueryRow(ctx,
			`SELECT `+datasourceSourceColumns+` FROM datasource_sources WHERE id = $1`, id)
		found, err := scanDatasourceSource(row)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		source = found
		return nil
	})
	if err != nil {
		return nil, err
	}
	return source, nil
}
