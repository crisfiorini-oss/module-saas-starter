package githubconnector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// appJWTClockSkew backdates the app JWT's iat to tolerate clock drift between
// this host and GitHub; appJWTTTL is well under GitHub's 10-minute ceiling.
const (
	appJWTClockSkew = time.Minute
	appJWTTTL       = 9 * time.Minute
)

// InstallationToken is a short-lived GitHub App installation access token and
// the instant it stops being valid.
type InstallationToken struct {
	Token     string
	ExpiresAt time.Time
}

// AppInstallation is one installation's live state as GitHub reports it.
// SuspendedAt is set while the installation is suspended: it still exists, and
// every token minted from it is refused until an owner unsuspends it.
type AppInstallation struct {
	ID          string
	SuspendedAt *time.Time
}

// MintInstallationToken exchanges the App credential for an installation access
// token: it signs a short-lived app JWT with the app's private key and POSTs to
// the installation's access-tokens endpoint. The returned token authorizes REST
// calls scoped to that installation.
func (c *Connector) MintInstallationToken(ctx context.Context, cred AppCredential) (InstallationToken, error) {
	appJWT, err := c.appJWT(cred)
	if err != nil {
		return InstallationToken{}, err
	}

	body, err := scopedMintBody(cred.Scope)
	if err != nil {
		return InstallationToken{}, err
	}

	url := fmt.Sprintf("%s/app/installations/%s/access_tokens", c.baseURL, cred.InstallationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return InstallationToken{}, err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	setGitHubHeaders(req)

	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := c.do(req, &out); err != nil {
		return InstallationToken{}, fmt.Errorf("mint installation token: %w", err)
	}
	if out.Token == "" {
		return InstallationToken{}, fmt.Errorf("mint installation token: response missing token")
	}
	return InstallationToken{Token: out.Token, ExpiresAt: out.ExpiresAt}, nil
}

// FindRepositoryInstallation resolves which installation of the app covers
// owner/repo, authenticating as the app itself. The host asks GitHub rather
// than believing a caller: an installation id arriving from a browser redirect
// or a webhook body is a claim, not authority to bind that installation to a
// tenant. Only AppID and PrivateKeyPEM are read from cred; its InstallationID
// is what this call exists to discover. A repository the app is not installed
// on answers 404, which IsNotFound classifies.
func (c *Connector) FindRepositoryInstallation(ctx context.Context, cred AppCredential, owner, repo string) (string, error) {
	appJWT, err := c.appJWT(cred)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/installation",
		c.baseURL, url.PathEscape(owner), url.PathEscape(repo))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	setGitHubHeaders(req)

	// GitHub reports the installation id as a JSON number; json.Number keeps it
	// exact rather than routing a 64-bit id through float64.
	var out struct {
		ID json.Number `json:"id"`
	}
	if err := c.do(req, &out); err != nil {
		return "", fmt.Errorf("find repository installation: %w", err)
	}
	if out.ID.String() == "" {
		return "", fmt.Errorf("find repository installation: response missing installation id")
	}
	return out.ID.String(), nil
}

// GetInstallation reads one installation's live state, authenticating as the
// app itself. A delivery says what changed; this says what is true now, which
// is what the host acts on — a replayed or out-of-order delivery would
// otherwise revoke access that has since been restored, or leave revoked
// access in place. A deleted installation answers 404, which IsNotFound
// classifies. Only AppID and PrivateKeyPEM are read from cred.
func (c *Connector) GetInstallation(ctx context.Context, cred AppCredential, installationID string) (AppInstallation, error) {
	appJWT, err := c.appJWT(cred)
	if err != nil {
		return AppInstallation{}, err
	}

	endpoint := fmt.Sprintf("%s/app/installations/%s", c.baseURL, url.PathEscape(installationID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return AppInstallation{}, err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	setGitHubHeaders(req)

	var out struct {
		ID          json.Number `json:"id"`
		SuspendedAt *time.Time  `json:"suspended_at"`
	}
	if err := c.do(req, &out); err != nil {
		return AppInstallation{}, fmt.Errorf("get installation: %w", err)
	}
	return AppInstallation{ID: out.ID.String(), SuspendedAt: out.SuspendedAt}, nil
}

// scopedMintBody renders the narrowing request GitHub's create-installation-
// access-token endpoint accepts. An unset scope sends no body at all, which
// mints a token carrying everything the installation was granted.
func scopedMintBody(scope *InstallationScope) (io.Reader, error) {
	if scope == nil || (len(scope.Repositories) == 0 && len(scope.Permissions) == 0) {
		return nil, nil
	}
	payload, err := json.Marshal(scope)
	if err != nil {
		return nil, fmt.Errorf("encode installation token scope: %w", err)
	}
	return bytes.NewReader(payload), nil
}

// appJWT builds the RS256-signed JWT that authenticates as the GitHub App
// itself (iss = app id), the credential GitHub requires to mint installation
// tokens.
func (c *Connector) appJWT(cred AppCredential) (string, error) {
	key, err := cred.signingKey()
	if err != nil {
		return "", err
	}
	now := c.now()
	claims := jwt.RegisteredClaims{
		Issuer:    cred.AppID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-appJWTClockSkew)),
		ExpiresAt: jwt.NewNumericDate(now.Add(appJWTTTL)),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign github app jwt: %w", err)
	}
	return signed, nil
}
