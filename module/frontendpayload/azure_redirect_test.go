package frontendpayload

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/registry"
)

type azureRedirectRoundTripper func(*http.Request) (*http.Response, error)

func (f azureRedirectRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAzureBundleDownloadFollowsRegistryDataRedirectWithoutCredentials(t *testing.T) {
	data := archiveFor(t, "azure-data-endpoint")
	frontend := frontendFor(data)
	digest := string(frontend.Payload.Digest)
	refresh := "e30." + base64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix()))) + ".sig"
	downloads := 0
	digestHeader := true
	tamper := false
	transport := azureRedirectRoundTripper(func(r *http.Request) (*http.Response, error) {
		response := &http.Response{StatusCode: 200, Header: make(http.Header), Request: r, Body: io.NopCloser(strings.NewReader(""))}
		switch {
		case r.URL.Host == "example.eastus2.data.azurecr.io":
			require.Equal(t, http.MethodGet, r.Method)
			require.Empty(t, r.Header.Get("Authorization"), "a registry bearer never reaches the download endpoint")
			downloads++
			if digestHeader {
				response.Header.Set("Docker-Content-Digest", digest)
			}
			response.Header.Set("Content-Length", fmt.Sprint(len(data)))
			body := append([]byte(nil), data...)
			if tamper {
				body[len(body)-1] ^= 1
			}
			response.Body = io.NopCloser(strings.NewReader(string(body)))
			response.ContentLength = int64(len(data))
		case r.URL.Path == "/oauth2/exchange":
			response.Body = io.NopCloser(strings.NewReader(fmt.Sprintf(`{"refresh_token":%q}`, refresh)))
		case r.URL.Path == "/oauth2/token":
			response.Body = io.NopCloser(strings.NewReader(`{"access_token":"registry-reader-token"}`))
		case r.Header.Get("Authorization") != "Bearer registry-reader-token":
			response.StatusCode = 401
			response.Header.Set("WWW-Authenticate", `Bearer realm="https://example.azurecr.io/oauth2/token",service="example.azurecr.io",scope="repository:frontend-bundles:pull"`)
		default:
			response.StatusCode = 307
			response.Header.Set("Location", "https://example.eastus2.data.azurecr.io/download?sig=private-download-capability")
		}
		return response, nil
	})
	ref, err := registry.ParseReference("example.azurecr.io/frontend-bundles")
	require.NoError(t, err)
	source, err := azureRegistrySource(ref, &azureTestCredential{}, transport)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	bundle, err := Prepare(ctx, source, frontend)
	require.NoError(t, err)
	require.Equal(t, "azure-data-endpoint", readAsset(t, bundle, "deferred.js"))
	require.Equal(t, 1, downloads)
	digestHeader = false
	bundle, err = Prepare(ctx, source, frontend)
	require.NoError(t, err, "the blob storage redirect response need not repeat registry-specific digest headers")
	require.Equal(t, "azure-data-endpoint", readAsset(t, bundle, "deferred.js"))
	tamper = true
	_, err = Prepare(ctx, source, frontend)
	require.ErrorContains(t, err, "digest mismatch", "signed bytes remain verified without a registry digest header")
	require.Equal(t, 3, downloads)
}

func TestAzureDownloadTransportRefusesOtherDestinationsAndCredentials(t *testing.T) {
	for _, target := range []struct{ url, method, bearer string }{
		{"https://other.eastus2.data.azurecr.io/blob", "GET", ""},
		{"https://example.eastus2.data.azurecr.io.evil.example/blob", "GET", ""},
		{"https://example..data.azurecr.io/blob", "GET", ""},
		{"http://example.eastus2.data.azurecr.io/blob", "GET", ""},
		{"https://example.eastus2.data.azurecr.io:8443/blob", "GET", ""},
		{"https://example.eastus2.data.azurecr.io/blob", "POST", ""},
		{"https://example.eastus2.data.azurecr.io/blob", "GET", "reader-secret"},
	} {
		t.Run(target.url+target.method+target.bearer, func(t *testing.T) {
			calls := 0
			transport := azureRegistryTransport{registry: "example.azurecr.io", base: azureRedirectRoundTripper(func(*http.Request) (*http.Response, error) { calls++; return nil, nil })}
			req, err := http.NewRequest(target.method, target.url, nil)
			require.NoError(t, err)
			if target.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+target.bearer)
			}
			_, err = transport.RoundTrip(req)
			require.ErrorIs(t, err, errRedirectRefused)
			require.Equal(t, 0, calls)
			require.NotContains(t, err.Error(), "reader-secret")
		})
	}
}
