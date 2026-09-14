package githubconnector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// maxUserInstallationPages bounds the user-installation walk. A person who can
// reach more installations than this through one App is not a case this flow
// serves, and an unbounded walk would let one request issue arbitrarily many
// round trips.
const maxUserInstallationPages = 20

// ErrUserCodeRejected is the single answer to every failed user-token exchange:
// an unknown, expired, already-redeemed or mismatched code. One error for all of
// them keeps the endpoint from reporting which codes exist.
var ErrUserCodeRejected = fmt.Errorf("github rejected the user authorization code")

// ExchangeUserCode trades the authorization code GitHub appends to the setup
// redirect for a user-to-server token — a token that acts as the human who came
// back from the install, not as the App.
//
// This is the only way the host can learn *who* is holding the redirect. The
// app JWT proves an installation exists; it says nothing about who controls it.
func (c *Connector) ExchangeUserCode(ctx context.Context, clientID, clientSecret, code string) (string, error) {
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {code},
	}
	endpoint := c.oauthBaseURL + "/login/oauth/access_token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// GitHub answers a rejected code with HTTP 200 and an `error` member rather
	// than a status code, so a successful transport says nothing on its own.
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := c.do(req, &out); err != nil {
		return "", fmt.Errorf("exchange user code: %w", err)
	}
	if out.Error != "" || strings.TrimSpace(out.AccessToken) == "" {
		return "", ErrUserCodeRejected
	}
	return out.AccessToken, nil
}

// UserAdministersInstallation reports whether the user behind userToken can
// actually reach the installation. GitHub answers this from the user's own
// authorization, so it is what binds an installation id — which arrives from a
// browser redirect and is trivially enumerable — to a human entitled to it.
func (c *Connector) UserAdministersInstallation(ctx context.Context, userToken, installationID string) (bool, error) {
	for page := 1; page <= maxUserInstallationPages; page++ {
		endpoint := fmt.Sprintf("%s/user/installations?per_page=%d&page=%d",
			c.baseURL, installationRepositoryPageSize, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("Authorization", "Bearer "+userToken)
		setGitHubHeaders(req)

		var out struct {
			Installations []struct {
				ID json.Number `json:"id"`
			} `json:"installations"`
		}
		if err := c.do(req, &out); err != nil {
			return false, fmt.Errorf("list user installations: %w", err)
		}
		for _, installation := range out.Installations {
			if installation.ID.String() == installationID {
				return true, nil
			}
		}
		if len(out.Installations) < installationRepositoryPageSize {
			return false, nil
		}
	}
	return false, nil
}
