//go:build !pure

package infra_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"accounts/pkg/business"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Installation ids are minted per run rather than fixed: installation_id is the
// primary key of a table that spans tenants, and the suite's database is a
// long-lived bind mount, so a shared constant would collide with the rows an
// earlier run left behind.
var (
	setupRun      = time.Now().UnixNano()
	setupSequence atomic.Int64
)

func uniqueAppInstallationID() string {
	return strconv.FormatInt(setupRun+setupSequence.Add(1), 10)
}

// setupStateHash mirrors what the service persists: hex(sha256(state)), which is
// also the only shape the column's length-64 CHECK accepts.
func setupStateHash(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

// beginSetupRow inserts one in-flight setup exactly as the service does — inside
// the organization's own tenant transaction, so RLS is in force for the write.
func beginSetupRow(t *testing.T, orgID, initiatedBy string, expiresAt time.Time) string {
	t.Helper()
	stateHash := setupStateHash(business.NewIDString())
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		return testStore.InsertGitHubAppSetup(ctx, &business.GitHubAppSetup{
			ID:          business.NewIDString(),
			OrgID:       orgID,
			InitiatedBy: initiatedBy,
			StateHash:   stateHash,
			ExpiresAt:   expiresAt,
		})
	}))
	return stateHash
}

// redeemSetup runs the redemption under the tenant transaction the service uses,
// so every rejection below is one RLS and the row predicates actually produce.
func redeemSetup(orgID, stateHash, initiatedBy string, now time.Time) error {
	var consumeErr error
	txErr := testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		consumeErr = testStore.ConsumeGitHubAppSetup(ctx, orgID, stateHash, initiatedBy, now)
		return nil
	})
	if txErr != nil {
		return txErr
	}
	return consumeErr
}

func claimInstallation(t *testing.T, orgID, installationID, verifiedBy string) bool {
	t.Helper()
	var claimed bool
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		var err error
		claimed, err = testStore.ClaimGitHubAppInstallation(ctx, installationID, orgID, verifiedBy)
		return err
	}))
	return claimed
}

func installationHeldBy(t *testing.T, orgID, installationID string) bool {
	t.Helper()
	var held bool
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		var err error
		held, err = testStore.GitHubAppInstallationClaimedBy(ctx, installationID, orgID)
		return err
	}))
	return held
}

// setupRowExists reads through the tenant transaction rather than the pool: a
// fresh pooled connection carries no app.current_org_id, so RLS would hide every
// row and the answer would be false for the wrong reason.
func setupRowExists(t *testing.T, orgID, stateHash string) bool {
	t.Helper()
	var exists bool
	require.NoError(t, testStore.WithOrgTx(testCtx, orgID, func(ctx context.Context) error {
		tx := ctx.Value("tx").(pgx.Tx) //nolint:staticcheck // shared "tx" key with WithOrgTx
		return tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM github_app_setups WHERE state_hash = $1)`,
			stateHash).Scan(&exists)
	}))
	return exists
}

// A setup state is the browser's ticket back from GitHub, so a replayed redirect
// must not install a second time. The guarantee is two SQL statements — a locking
// read and an UPDATE guarded on consumed_at IS NULL — so only a real database
// proves it.
func TestPostgresConsumeGitHubAppSetupRedeemsOnlyOnce(t *testing.T) {
	user := seedUser(t)
	org := seedOrg(t, user)
	state := beginSetupRow(t, org, user, time.Now().Add(time.Hour))

	require.NoError(t, redeemSetup(org, state, user, time.Now().UTC()))
	require.ErrorIs(t, redeemSetup(org, state, user, time.Now().UTC()), business.ErrGitHubAppSetupRejected)
}

// Two browsers returning with the same state at the same instant is the replay
// that matters: without the row lock both redemptions read consumed_at IS NULL
// and both proceed. Exactly one may win.
func TestPostgresConsumeGitHubAppSetupSerializesConcurrentReplay(t *testing.T) {
	user := seedUser(t)
	org := seedOrg(t, user)
	state := beginSetupRow(t, org, user, time.Now().Add(time.Hour))

	const racers = 4
	var (
		wg        sync.WaitGroup
		redeemed  atomic.Int64
		errs      = make([]error, racers)
		startLine = make(chan struct{})
	)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startLine
			if err := redeemSetup(org, state, user, time.Now().UTC()); err != nil {
				errs[i] = err
				return
			}
			redeemed.Add(1)
		}()
	}
	close(startLine)
	wg.Wait()

	require.Equal(t, int64(1), redeemed.Load(), "exactly one concurrent redemption may consume the state")
	for _, err := range errs {
		if err != nil {
			require.ErrorIs(t, err, business.ErrGitHubAppSetupRejected)
		}
	}
}

// The setup is redeemable only by the user who began it, so a leaked redirect
// cannot be completed by another member of the same organization — and the
// refusal must not burn the state for its rightful initiator.
func TestPostgresConsumeGitHubAppSetupRefusesAnotherInitiator(t *testing.T) {
	initiator := seedUser(t)
	bystander := seedUser(t)
	org := seedOrg(t, initiator)
	state := beginSetupRow(t, org, initiator, time.Now().Add(time.Hour))

	require.ErrorIs(t, redeemSetup(org, state, bystander, time.Now().UTC()), business.ErrGitHubAppSetupRejected)
	require.NoError(t, redeemSetup(org, state, initiator, time.Now().UTC()),
		"a refused redemption must leave the state redeemable by its initiator")
}

func TestPostgresConsumeGitHubAppSetupRefusesAnExpiredState(t *testing.T) {
	user := seedUser(t)
	org := seedOrg(t, user)
	state := beginSetupRow(t, org, user, time.Now().Add(-time.Minute))

	require.ErrorIs(t, redeemSetup(org, state, user, time.Now().UTC()), business.ErrGitHubAppSetupRejected)
}

// A state belongs to the organization it was begun for. Another tenant echoing it
// back is refused by the org predicate and, underneath it, by RLS — neither the
// row nor the fact that it exists is reachable.
func TestPostgresConsumeGitHubAppSetupRefusesAnotherOrganizationsState(t *testing.T) {
	holder := seedUser(t)
	intruder := seedUser(t)
	org := seedOrg(t, holder)
	otherOrg := seedOrg(t, intruder)
	state := beginSetupRow(t, org, holder, time.Now().Add(time.Hour))

	require.ErrorIs(t, redeemSetup(otherOrg, state, intruder, time.Now().UTC()), business.ErrGitHubAppSetupRejected)
	require.False(t, setupRowExists(t, otherOrg, state), "another tenant's setup row must not be readable")
	require.NoError(t, redeemSetup(org, state, holder, time.Now().UTC()))
}

// The cross-tenant substitution guard: an installation id is a small integer a
// browser hands back, so one organization naming another's installation must be
// refused rather than silently rebinding it. The guard is the primary key plus a
// read that RLS scopes to the caller, which no in-memory fake reproduces.
func TestPostgresClaimGitHubAppInstallationRefusesAnotherOrganizationsInstallation(t *testing.T) {
	holder := seedUser(t)
	intruder := seedUser(t)
	org := seedOrg(t, holder)
	otherOrg := seedOrg(t, intruder)
	installation := uniqueAppInstallationID()

	require.True(t, claimInstallation(t, org, installation, holder))
	require.False(t, claimInstallation(t, otherOrg, installation, intruder),
		"an installation another organization holds must not be claimable")

	require.True(t, installationHeldBy(t, org, installation))
	require.False(t, installationHeldBy(t, otherOrg, installation))
}

// Re-running setup for an installation this organization already holds is a
// normal repeat, not a conflict: the same caller must get the same answer.
func TestPostgresClaimGitHubAppInstallationIsIdempotentForTheHolder(t *testing.T) {
	user := seedUser(t)
	org := seedOrg(t, user)
	installation := uniqueAppInstallationID()

	require.True(t, claimInstallation(t, org, installation, user))
	require.True(t, claimInstallation(t, org, installation, user))
	require.True(t, installationHeldBy(t, org, installation))
}

// Nothing else deletes a setup row, so without the retention sweep the table
// grows by a row for every abandoned connect attempt. It runs cross-tenant under
// the control plane and must take only rows past their window. The suite's
// database is shared, so this asserts on its own rows rather than on the count.
func TestPostgresDeleteExpiredGitHubAppSetupsSweepsOnlyLapsedRows(t *testing.T) {
	user := seedUser(t)
	org := seedOrg(t, user)
	lapsed := beginSetupRow(t, org, user, time.Now().Add(-48*time.Hour))
	live := beginSetupRow(t, org, user, time.Now().Add(time.Hour))

	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		_, err := testStore.DeleteExpiredGitHubAppSetups(ctx, time.Now().Add(-24*time.Hour))
		return err
	}))

	require.False(t, setupRowExists(t, org, lapsed))
	require.True(t, setupRowExists(t, org, live))
}
