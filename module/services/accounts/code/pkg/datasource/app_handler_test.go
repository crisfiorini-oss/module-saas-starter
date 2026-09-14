package datasource_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"accounts/pkg/datasource"

	"github.com/stretchr/testify/require"
)

const testAppWebhookSecret = "whsec_github_app_fake_secret"

// staticAppRegistration is the configured App webhook secret, the one value the
// App-level receiver needs at request time.
type staticAppRegistration struct {
	secret string
	err    error
}

func (r staticAppRegistration) AppWebhookSecret(context.Context) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	return r.secret, nil
}

func newAppTestServer(t *testing.T, producer *fakeJobProducer, registration datasource.AppWebhookSecretResolver) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(datasource.GitHubAppWebhookPath, datasource.NewAppHandler(datasource.AppHandlerDeps{
		Producer:     producer,
		Registration: registration,
	}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

type appDelivery struct {
	event      string
	delivery   string
	body       string
	signWith   string // signs with this secret instead of the configured one
	signature  string // overrides the computed signature entirely
	omitSigned bool   // sends no signature header at all
	method     string
}

func postAppDelivery(t *testing.T, server *httptest.Server, d appDelivery) *http.Response {
	t.Helper()
	if d.method == "" {
		d.method = http.MethodPost
	}
	if d.signWith == "" {
		d.signWith = testAppWebhookSecret
	}
	body := []byte(d.body)
	request, err := http.NewRequest(d.method, server.URL+datasource.GitHubAppWebhookPath, bytes.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	if d.event != "" {
		request.Header.Set("X-GitHub-Event", d.event)
	}
	if d.delivery != "" {
		request.Header.Set("X-GitHub-Delivery", d.delivery)
	}
	switch {
	case d.omitSigned:
	case d.signature != "":
		request.Header.Set("X-Hub-Signature-256", d.signature)
	default:
		request.Header.Set("X-Hub-Signature-256", signBody(d.signWith, body))
	}
	response, err := server.Client().Do(request)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

// A real delivery carries the installation's account and the person who acted,
// neither of which the reconciler reads.
const suspendDelivery = `{"action":"suspend","installation":{"id":4242,"account":{"login":"acme-org"}},"sender":{"login":"example-operator"}}`

// A verified lifecycle delivery is recorded durably and keyed so the reconciler
// can find the installation it concerns — and nothing more: the receiver does
// not call GitHub or touch a source on the request path.
func TestAppWebhookQueuesInstallationDelivery(t *testing.T) {
	producer := newFakeJobProducer()
	server := newAppTestServer(t, producer, staticAppRegistration{secret: testAppWebhookSecret})

	response := postAppDelivery(t, server, appDelivery{
		event: "installation", delivery: "delivery-1", body: suspendDelivery,
	})
	require.Equal(t, http.StatusOK, response.StatusCode)

	request, ok := producer.request("delivery-1")
	require.True(t, ok, "a verified delivery must be persisted")
	job := request.GetJob()
	require.Equal(t, datasource.GitHubAppWebhookQueue, job.GetQueue())
	require.Equal(t, datasource.GitHubAppWebhookTopic, job.GetTopic())
	require.Equal(t, "installation", job.GetAttributes()["github.event"])

	// Only the routing fact is retained. The reconciler re-derives everything
	// from GitHub and reads nothing out of the payload, so keeping the delivery
	// would durably store a third party's account and sender for no consumer.
	require.JSONEq(t, `{"installation_id":"4242"}`, string(job.GetPayload()))
	require.NotContains(t, string(job.GetPayload()), "example-operator")
	require.NotContains(t, string(job.GetPayload()), "acme-org")
	require.Equal(t, "4242", job.GetAttributes()["datasource.installation_id"])
	require.Equal(t, "delivery-1", job.GetAttributes()["datasource.delivery_id"])

	// Ordering is per installation, so a suspend and the unsuspend behind it
	// reconcile in the order GitHub sent them rather than racing.
	require.Equal(t, []string{"4242"}, job.GetOrdering().GetComponents())
}

// The tenant-driven half of the lifecycle: editing which repositories an
// installation covers arrives as its own event and must be reconciled too.
func TestAppWebhookQueuesRepositorySelectionDelivery(t *testing.T) {
	producer := newFakeJobProducer()
	server := newAppTestServer(t, producer, staticAppRegistration{secret: testAppWebhookSecret})

	response := postAppDelivery(t, server, appDelivery{
		event:    "installation_repositories",
		delivery: "delivery-2",
		body:     `{"action":"removed","installation":{"id":4242},"repositories_removed":[{"full_name":"acme/docs"}]}`,
	})
	require.Equal(t, http.StatusOK, response.StatusCode)
	_, ok := producer.request("delivery-2")
	require.True(t, ok)
}

// The App-wide secret is the only thing that admits a delivery here. A body
// signed with some other secret — a source's own push secret, say — is refused,
// and nothing is recorded.
func TestAppWebhookRejectsForgedSignature(t *testing.T) {
	producer := newFakeJobProducer()
	server := newAppTestServer(t, producer, staticAppRegistration{secret: testAppWebhookSecret})

	response := postAppDelivery(t, server, appDelivery{
		event: "installation", delivery: "forged", body: suspendDelivery, signWith: "whsec_some_other_secret",
	})
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	require.Zero(t, producer.inserts.Load(), "an unverified delivery must never be recorded")
}

func TestAppWebhookRejectsUnsignedDelivery(t *testing.T) {
	producer := newFakeJobProducer()
	server := newAppTestServer(t, producer, staticAppRegistration{secret: testAppWebhookSecret})

	response := postAppDelivery(t, server, appDelivery{
		event: "installation", delivery: "unsigned", body: suspendDelivery, omitSigned: true,
	})
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	require.Zero(t, producer.inserts.Load())
}

// A deployment with no App registration answers exactly like a signature
// failure rather than revealing that it has nothing configured.
func TestAppWebhookRejectsWhenNoSecretIsConfigured(t *testing.T) {
	producer := newFakeJobProducer()
	server := newAppTestServer(t, producer, staticAppRegistration{err: errors.New("unconfigured")})

	response := postAppDelivery(t, server, appDelivery{
		event: "installation", delivery: "unconfigured", body: suspendDelivery,
	})
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	require.Zero(t, producer.inserts.Load())
}

// An App receives every event its registration subscribes to. Anything that is
// not one of the two access-changing events is acknowledged so GitHub stops
// retrying it, and is never turned into reconcile work.
func TestAppWebhookAcknowledgesUnrelatedEvent(t *testing.T) {
	producer := newFakeJobProducer()
	server := newAppTestServer(t, producer, staticAppRegistration{secret: testAppWebhookSecret})

	for _, event := range []string{"ping", "installation_target", "github_app_authorization"} {
		response := postAppDelivery(t, server, appDelivery{
			event: event, delivery: "ack-" + event, body: `{"installation":{"id":4242}}`,
		})
		require.Equal(t, http.StatusOK, response.StatusCode, event)
	}
	require.Zero(t, producer.inserts.Load(), "only lifecycle events become reconcile work")
}

// Both lifecycle events always name their installation; a verified delivery
// without one cannot be routed and will not route on redelivery either.
func TestAppWebhookRejectsDeliveryWithoutInstallation(t *testing.T) {
	producer := newFakeJobProducer()
	server := newAppTestServer(t, producer, staticAppRegistration{secret: testAppWebhookSecret})

	response := postAppDelivery(t, server, appDelivery{
		event: "installation", delivery: "no-installation", body: `{"action":"deleted"}`,
	})
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	require.Zero(t, producer.inserts.Load())
}

func TestAppWebhookRequiresDeliveryHeaders(t *testing.T) {
	producer := newFakeJobProducer()
	server := newAppTestServer(t, producer, staticAppRegistration{secret: testAppWebhookSecret})

	response := postAppDelivery(t, server, appDelivery{event: "installation", body: suspendDelivery})
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	require.Zero(t, producer.inserts.Load())
}

// GitHub redelivers on its own and an operator can replay from the App's
// deliveries page; the delivery id keys the job, so a replay is recorded once.
func TestAppWebhookRedeliveryIsIdempotent(t *testing.T) {
	producer := newFakeJobProducer()
	server := newAppTestServer(t, producer, staticAppRegistration{secret: testAppWebhookSecret})

	first := postAppDelivery(t, server, appDelivery{event: "installation", delivery: "same", body: suspendDelivery})
	second := postAppDelivery(t, server, appDelivery{event: "installation", delivery: "same", body: suspendDelivery})
	require.Equal(t, http.StatusOK, first.StatusCode)
	require.Equal(t, http.StatusOK, second.StatusCode)
	require.EqualValues(t, 1, producer.inserts.Load())
}

func TestAppWebhookRejectsNonPost(t *testing.T) {
	producer := newFakeJobProducer()
	server := newAppTestServer(t, producer, staticAppRegistration{secret: testAppWebhookSecret})

	response := postAppDelivery(t, server, appDelivery{
		method: http.MethodGet, event: "installation", delivery: "get", body: suspendDelivery,
	})
	require.Equal(t, http.StatusMethodNotAllowed, response.StatusCode)
}
