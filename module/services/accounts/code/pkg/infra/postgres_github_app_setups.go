package infra

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"accounts/pkg/business"
)

func (s *PostgresStore) InsertGitHubAppSetup(ctx context.Context, setup *business.GitHubAppSetup) error {
	_, err := s.getQueryExecutor(ctx).Exec(ctx, `
		INSERT INTO github_app_setups (id, org_id, initiated_by, state_hash, expires_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)`,
		setup.ID, setup.OrgID, setup.InitiatedBy, setup.StateHash, setup.ExpiresAt)
	return err
}

// ConsumeGitHubAppSetup redeems a state exactly once. The row is locked before
// it is inspected, so two concurrent redemptions of the same state serialize
// and the second sees consumed_at already set; the UPDATE is additionally
// guarded on consumed_at IS NULL, so a replay can never win even if the lock is
// released between statements.
//
// Every rejection cause — unknown, expired, already consumed, or begun by a
// different user — returns the same error, so the endpoint is not an oracle for
// which states exist.
func (s *PostgresStore) ConsumeGitHubAppSetup(ctx context.Context, orgID, stateHash, initiatedBy string, now time.Time) error {
	q := s.getQueryExecutor(ctx)
	var id string
	var rowInitiatedBy string
	var expiresAt time.Time
	var consumedAt *time.Time
	err := q.QueryRow(ctx, `
		SELECT id::text, initiated_by::text, expires_at, consumed_at
		FROM github_app_setups
		WHERE state_hash = $1 AND org_id = $2::uuid
		FOR UPDATE`, stateHash, orgID).Scan(&id, &rowInitiatedBy, &expiresAt, &consumedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return business.ErrGitHubAppSetupRejected
		}
		return err
	}
	if consumedAt != nil || !now.Before(expiresAt) || rowInitiatedBy != initiatedBy {
		return business.ErrGitHubAppSetupRejected
	}

	tag, err := q.Exec(ctx, `
		UPDATE github_app_setups SET consumed_at = $2
		WHERE id = $1::uuid AND consumed_at IS NULL`, id, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return business.ErrGitHubAppSetupRejected
	}
	return nil
}

// ClaimGitHubAppInstallation binds an installation to one organization. The
// installation id is the primary key, so a second organization presenting the
// same id conflicts rather than overwriting the binding; DO NOTHING plus the
// follow-up read distinguishes "this org already holds it" (idempotent
// re-setup) from "another org holds it" (refused) without the row of the other
// tenant ever being readable through RLS.
func (s *PostgresStore) ClaimGitHubAppInstallation(ctx context.Context, installationID, orgID, verifiedBy string) (bool, error) {
	q := s.getQueryExecutor(ctx)
	tag, err := q.Exec(ctx, `
		INSERT INTO github_app_installations (installation_id, org_id, verified_by)
		VALUES ($1, $2::uuid, $3::uuid)
		ON CONFLICT (installation_id) DO NOTHING`, installationID, orgID, verifiedBy)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	return s.GitHubAppInstallationClaimedBy(ctx, installationID, orgID)
}

func (s *PostgresStore) GitHubAppInstallationClaimedBy(ctx context.Context, installationID, orgID string) (bool, error) {
	var exists bool
	err := s.getQueryExecutor(ctx).QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM github_app_installations
			WHERE installation_id = $1 AND org_id = $2::uuid
		)`, installationID, orgID).Scan(&exists)
	return exists, err
}
