//go:build !pure

package infra_test

import (
	"context"
	"testing"

	"accounts/pkg/business"

	"github.com/stretchr/testify/require"
)

// TestPostgresDatasourceDegradeRoundTripClearsTheStoredReason pins, at the two
// UPDATEs that own it, the invariant the wire contract publishes: a source is
// degraded with a reason, and an active source carries none.
//
// The business-layer coverage of recovery runs against a fake store that
// hand-mirrors this SQL, so it cannot see the SQL change. Remove the
// status_reason reset from the real revive statement and that test stays green
// while every recovered source keeps projecting its stale degrade reason — to
// every organization member, since ListSources and GetSource are ORG_MEMBER
// reads.
func TestPostgresDatasourceDegradeRoundTripClearsTheStoredReason(t *testing.T) {
	owner := seedUser(t)
	org := seedOrg(t, owner)
	sourceID := seedDatasourceSource(t, org)

	reason := business.SnapshotTooLargeDegradeReason(1048576, 983040)
	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		return testStore.MarkDatasourceSourceDegraded(ctx, sourceID, reason)
	}))

	degraded, err := testStore.GetDatasourceSourceByID(testCtx, sourceID)
	require.NoError(t, err)
	require.Equal(t, business.DatasourceStatusDegraded, degraded.Status)
	require.Equal(t, reason.String(), degraded.StatusReason,
		"the degrade reason must reach the column the wire projection reads")

	require.NoError(t, testStore.WithControlPlane(testCtx, func(ctx context.Context) error {
		return testStore.ClearDatasourceSourceDegraded(ctx, sourceID, []string{
			business.DatasourceReasonInstallationSuspended,
			business.DatasourceReasonInstallationRepositoryUnavailable,
		})
	}))

	revived, err := testStore.GetDatasourceSourceByID(testCtx, sourceID)
	require.NoError(t, err)
	require.Equal(t, business.DatasourceStatusActive, revived.Status)
	require.Empty(t, revived.StatusReason,
		"an active source must carry no status_reason: the wire contract says it is empty while active")
}
