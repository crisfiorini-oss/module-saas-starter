package githubconnector_test

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"accounts/pkg/githubconnector"
)

// fakeInstallationEndpoint serves GET /app/installations/{id} and verifies that
// the caller authenticated as the app itself, which is the only credential
// GitHub accepts for it.
type fakeInstallationEndpoint struct {
	appPublicKey *rsa.PublicKey
	appID        string
	status       int
	body         string
}

func (f *fakeInstallationEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(
		r.Header.Get("Authorization")[len("Bearer "):], claims,
		func(*jwt.Token) (any, error) { return f.appPublicKey, nil },
	)
	if err != nil || claims.Issuer != f.appID {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return
	}
	if f.status != 0 {
		http.Error(w, f.body, f.status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(f.body))
}

func installationConnector(t *testing.T, fake *fakeInstallationEndpoint) (*githubconnector.Connector, githubconnector.AppCredential) {
	t.Helper()
	cred, key := credentialWithKey(t)
	fake.appPublicKey = &key.PublicKey
	fake.appID = cred.AppID
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return githubconnector.NewConnector(githubconnector.WithBaseURL(server.URL)), cred
}

// A suspended installation still exists; what changes is that every token
// minted from it is refused. The caller needs that distinction to say why a
// source stopped syncing, so the suspension instant is surfaced rather than
// flattened into an error.
func TestGetInstallationReportsSuspension(t *testing.T) {
	suspended := time.Date(2026, 9, 14, 10, 30, 0, 0, time.UTC)
	conn, cred := installationConnector(t, &fakeInstallationEndpoint{
		body: `{"id":4242,"suspended_at":"2026-09-14T10:30:00Z"}`,
	})

	installation, err := conn.GetInstallation(context.Background(), cred, "4242")
	require.NoError(t, err)
	require.Equal(t, "4242", installation.ID)
	require.NotNil(t, installation.SuspendedAt)
	require.WithinDuration(t, suspended, *installation.SuspendedAt, time.Second)
}

func TestGetInstallationReportsActiveInstallation(t *testing.T) {
	conn, cred := installationConnector(t, &fakeInstallationEndpoint{
		body: `{"id":4242,"suspended_at":null}`,
	})

	installation, err := conn.GetInstallation(context.Background(), cred, "4242")
	require.NoError(t, err)
	require.Equal(t, "4242", installation.ID)
	require.Nil(t, installation.SuspendedAt, "an installation nobody suspended carries no suspension instant")
}

// An uninstalled App answers 404. Callers branch on that to park a source
// rather than to retry, so it has to stay classifiable as a not-found.
func TestGetInstallationDeletedIsNotFound(t *testing.T) {
	conn, cred := installationConnector(t, &fakeInstallationEndpoint{
		status: http.StatusNotFound, body: `{"message":"Not Found"}`,
	})

	_, err := conn.GetInstallation(context.Background(), cred, "4242")
	require.Error(t, err)
	require.True(t, githubconnector.IsNotFound(err), "a deleted installation must be distinguishable from an outage")
}

// GitHub reports installation ids as JSON numbers large enough to lose
// precision through float64.
func TestGetInstallationKeepsLargeIDExact(t *testing.T) {
	conn, cred := installationConnector(t, &fakeInstallationEndpoint{
		body: `{"id":90071992547409911,"suspended_at":null}`,
	})

	installation, err := conn.GetInstallation(context.Background(), cred, "90071992547409911")
	require.NoError(t, err)
	require.Equal(t, "90071992547409911", installation.ID)
}
