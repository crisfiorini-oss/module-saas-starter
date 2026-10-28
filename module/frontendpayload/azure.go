package frontendpayload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	"github.com/codefly-dev/core/solutionhost"
	"oras.land/oras-go/v2/registry"
)

// The same workload-reader stopgap as workload.go, using Azure's credential,
// token exchange and renewal implementation rather than another auth flow.
type azureWorkloadSource struct {
	client     *azcontainerregistry.BlobClient
	repository string
}

func newAzureWorkloadSource(repository string) (Source, error) {
	ref, err := registry.ParseReference(repository)
	if err != nil || ref.Reference != "" || ref.Repository == "" {
		return nil, errors.New("frontend artifact repository must name one repository without a tag or digest")
	}
	credential, err := azidentity.NewWorkloadIdentityCredential(nil)
	if err != nil {
		return nil, &readerIdentityError{"Azure frontend artifact reads require the pod's bound workload identity"}
	}
	return azureRegistrySource(ref, credential, http.DefaultTransport)
}

func azureRegistrySource(ref registry.Reference, credential azcore.TokenCredential, base http.RoundTripper) (Source, error) {
	client, err := azcontainerregistry.NewBlobClient("https://"+ref.Registry, credential,
		&azcontainerregistry.BlobClientOptions{ClientOptions: azcore.ClientOptions{
			Transport: &http.Client{Timeout: 30 * time.Second,
				Transport: azureRegistryTransport{registry: ref.Registry, base: base},
				CheckRedirect: func(next *http.Request, via []*http.Request) error {
					if len(via) > 3 || next.URL.Scheme != "https" || next.URL.User != nil ||
						(next.URL.Host != ref.Registry && !azureDataEndpoint(ref.Registry, next.URL.Host)) {
						return errRedirectRefused
					}
					if next.URL.Host != ref.Registry {
						next.Header.Del("Authorization")
					}
					return nil
				}},
		}})
	if err != nil {
		return nil, &readerIdentityError{"could not configure the Azure frontend artifact reader"}
	}
	return &azureWorkloadSource{client: client, repository: ref.Repository}, nil
}

// Private-link ACR downloads redirect to this registry's regional data host.
// Neither arbitrary Azure storage hosts nor another registry are admitted.
func azureDataEndpoint(registry, host string) bool {
	name, ok := strings.CutSuffix(registry, ".azurecr.io")
	if !ok || strings.ContainsAny(name, ".:") {
		return false
	}
	parts := strings.Split(host, ".")
	if len(parts) != 5 || parts[0] != name || parts[2] != "data" || parts[3] != "azurecr" || parts[4] != "io" || parts[1] == "" {
		return false
	}
	for _, ch := range parts[1] {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

type azureRegistryTransport struct {
	registry string
	base     http.RoundTripper
}

func (t azureRegistryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.User != nil {
		return nil, errRedirectRefused
	}
	if r.URL.Host != t.registry && (!azureDataEndpoint(t.registry, r.URL.Host) || r.Method != http.MethodGet || r.Header.Get("Authorization") != "") {
		return nil, errRedirectRefused
	}
	return t.base.RoundTrip(r)
}

func (s *azureWorkloadSource) Open(ctx context.Context, digest solutionhost.PayloadDigest) (io.ReadCloser, error) {
	response, err := s.client.GetBlob(ctx, s.repository, string(digest), nil)
	if err != nil {
		var status *azcore.ResponseError
		if errors.As(err, &status) {
			return nil, fmt.Errorf("%w: the registry answered HTTP %d", ErrUnavailable, status.StatusCode)
		}
		return nil, unavailable(err)
	}
	// A redirected storage response may omit the registry-specific digest header.
	// Prepare verifies the downloaded bytes against the signed digest before serving.
	if (response.DockerContentDigest != nil && *response.DockerContentDigest != string(digest)) ||
		response.ContentLength == nil || *response.ContentLength < 0 || *response.ContentLength > MaxBundleBytes {
		response.BlobData.Close()
		return nil, errors.New("frontend artifact descriptor differs from the admitted bundle")
	}
	return response.BlobData, nil
}
