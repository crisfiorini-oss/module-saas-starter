package datasource

// Inbound GitHub App lifecycle receipt.
//
// A second receiver beside the per-source push endpoint, deliberately not a
// branch inside it. `installation` and `installation_repositories` have GitHub
// availability "app": they are delivered only to the App registration's own
// webhook URL and cannot be subscribed to on a repository hook, so they never
// arrive at the per-source endpoint to be handled there. Nor could they be
// verified there — a GitHub App has exactly one webhook secret, set on the
// registration, while the per-source receiver verifies a secret the tenant
// pasted in for its own repository.
//
// What arrives is a claim that something about an installation changed. The
// receiver does not act on it: it verifies the signature, durably records which
// installation to re-examine — that routing fact alone, never the delivery body
// — and returns 2xx. The leased reconciler then re-derives each affected
// source's access from GitHub, because a delivery can be replayed, delayed or
// arrive out of order, and revoking a tenant's source on a stale claim is worse
// than acting a beat later.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	jobsv1 "accounts/pkg/gen/saas/jobs/v1"
	"accounts/pkg/jobs"

	"github.com/codefly-dev/core/wool"
)

// GitHubAppWebhookPath is the route the App registration's webhook URL points
// at. Unlike the per-source receiver it takes no path parameter: one App has
// one webhook URL, and each delivery names its installation in the body.
const GitHubAppWebhookPath = "/v1/datasource/github/app/webhook"

const (
	// GitHubAppWebhookQueue is the accounts-owned queue the installation
	// reconciler leases. It is separate from the push delivery queue because its
	// jobs are keyed by installation rather than by source: one delivery can
	// concern many sources across many tenants. It must match
	// business.DatasourceInstallationQueue — this package is imported by
	// business, so the constant cannot be shared without an import cycle.
	GitHubAppWebhookQueue         = "datasource.installations"
	GitHubAppWebhookTopic         = "datasource.github.installation"
	GitHubAppWebhookSource        = "github.app.webhook"
	GitHubAppWebhookSchemaVersion = 1
	GitHubAppWebhookMaxAttempts   = 24

	// installationOrderingNamespace serializes work per installation, so a
	// suspend and the unsuspend that follows it reconcile in the order GitHub
	// sent them instead of racing — and so the host's own re-check cannot run
	// beside a delivery for the same installation. It must match
	// business.datasourceInstallationOrderingNamespace, which the re-check sweep
	// stamps on the jobs it enqueues.
	installationOrderingNamespace = "datasource.installation"

	attrInstallationID = "datasource.installation_id"
)

// The two App-level events that change which repositories a source may read.
// `installation` covers created/deleted/suspend/unsuspend; the repository
// selection a tenant edits arrives as `installation_repositories`.
const (
	installationEvent             = "installation"
	installationRepositoriesEvent = "installation_repositories"
)

// AppWebhookSecretResolver hands the receiver the App registration's webhook
// secret. It is one deployment-wide value, not a per-source lookup, so it costs
// no database read on the request path.
type AppWebhookSecretResolver interface {
	AppWebhookSecret(ctx context.Context) (string, error)
}

// AppHandlerDeps are deliberately limited to receipt-time dependencies.
type AppHandlerDeps struct {
	Producer     jobs.Producer
	Registration AppWebhookSecretResolver
}

// NewAppHandler returns the public App-level webhook endpoint.
func NewAppHandler(deps AppHandlerDeps) http.Handler {
	return &appHandler{deps: deps}
}

type appHandler struct {
	deps AppHandlerDeps
}

func (h *appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	log := wool.Get(r.Context()).In("datasource.github.app.webhook")

	secret, err := h.deps.Registration.AppWebhookSecret(r.Context())
	if err != nil {
		log.Warn("resolve app webhook secret failed", wool.ErrField(err))
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxGitHubWebhookBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	if err := verifySignature(body, r.Header.Get(signatureHeader), secret); err != nil {
		log.Warn("signature verification failed", wool.ErrField(err))
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	deliveryID := strings.TrimSpace(r.Header.Get(deliveryHeader))
	event := strings.TrimSpace(r.Header.Get(eventHeader))
	if deliveryID == "" || event == "" {
		writeError(w, http.StatusBadRequest, "missing delivery headers")
		return
	}

	// An App receives every event its registration subscribes to, including the
	// setup ping. Only the two that change repository access are reconciled; the
	// rest are acknowledged so GitHub does not retry them.
	if event != installationEvent && event != installationRepositoriesEvent {
		log.Info("ignoring non-lifecycle event", wool.Field("event", event))
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}

	installationID, err := installationIDFromDelivery(body)
	if err != nil {
		// Both events always name their installation, so a verified delivery
		// without one cannot be routed and will not route on redelivery either.
		log.Warn("delivery names no installation", wool.ErrField(err))
		writeError(w, http.StatusBadRequest, "invalid delivery")
		return
	}

	// Only the routing fact is retained, never the delivery body. The reconciler
	// re-derives every source's access from GitHub and reads nothing out of the
	// payload, so keeping the original would durably store a third party's
	// repository list, account and sender for no consumer at all. A replay needs
	// the installation id and nothing else.
	retained, err := json.Marshal(map[string]string{"installation_id": installationID})
	if err != nil {
		log.Warn("encode installation reference failed", wool.ErrField(err))
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	response, err := h.deps.Producer.EnqueueJob(r.Context(), &jobsv1.EnqueueJobRequest{
		Job: &jobsv1.NewJob{
			Direction: jobsv1.JobDirection_JOB_DIRECTION_INBOX,
			Scope:     &jobsv1.JobScope{Value: &jobsv1.JobScope_Global{Global: true}},
			Queue:     GitHubAppWebhookQueue,
			Topic:     GitHubAppWebhookTopic,
			Source:    GitHubAppWebhookSource,
			Ordering: &jobsv1.JobOrderingKey{
				Namespace:  installationOrderingNamespace,
				Components: []string{installationID},
			},
			IdempotencyKey: deliveryID,
			SchemaVersion:  GitHubAppWebhookSchemaVersion,
			Payload:        retained,
			ContentType:    gitHubWebhookContentType,
			MaxAttempts:    GitHubAppWebhookMaxAttempts,
			Attributes: map[string]string{
				attrEvent:          event,
				attrInstallationID: installationID,
				attrDeliveryID:     deliveryID,
			},
		},
	})
	if err != nil {
		if errors.Is(err, jobs.ErrIdempotencyConflict) {
			writeError(w, http.StatusConflict, "delivery conflict")
			return
		}
		if errors.Is(err, jobs.ErrInvalidCommand) {
			log.Warn("reject invalid webhook command", wool.ErrField(err))
			writeError(w, http.StatusBadRequest, "invalid delivery")
			return
		}
		// The delivery was not durably recorded. A 5xx records it as failed on
		// the App's deliveries page, where an operator can redeliver it, rather
		// than acknowledging a revocation this host never persisted.
		log.Warn("persist webhook failed", wool.ErrField(err))
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	switch response.GetDisposition() {
	case jobsv1.JobEnqueueDisposition_JOB_ENQUEUE_DISPOSITION_DUPLICATE:
		writeJSON(w, http.StatusOK, map[string]string{"status": "duplicate"})
	case jobsv1.JobEnqueueDisposition_JOB_ENQUEUE_DISPOSITION_INSERTED:
		writeJSON(w, http.StatusOK, map[string]string{"status": "queued"})
	default:
		log.Warn("persist webhook returned no durable disposition")
		writeError(w, http.StatusInternalServerError, "internal")
	}
}

// installationIDFromDelivery reads the installation a delivery concerns. This
// is routing, not authority: the reconciler re-derives every source's access
// from GitHub rather than believing the body. GitHub reports the id as a JSON
// number, and json.Number keeps a 64-bit id exact rather than routing it
// through float64.
func installationIDFromDelivery(body []byte) (string, error) {
	var envelope struct {
		Installation struct {
			ID json.Number `json:"id"`
		} `json:"installation"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", err
	}
	if envelope.Installation.ID.String() == "" {
		return "", errors.New("datasource: delivery carries no installation id")
	}
	return envelope.Installation.ID.String(), nil
}
