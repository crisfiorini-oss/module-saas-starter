package githubconnector

import (
	"context"
	"fmt"
	"net/http"
)

// installationRepositoryPageSize is GitHub's maximum page size for the
// installation-repositories endpoint.
const installationRepositoryPageSize = 100

// maxInstallationRepositoryPages bounds the walk. Without it one connect call
// could issue arbitrarily many sequential round trips. Exceeding it is reported
// rather than silently truncated: a short list would hide repositories the
// tenant selected, and they would read that as the App not granting them.
const maxInstallationRepositoryPages = 20

// InstallationRepository is one repository an installation grants access to.
type InstallationRepository struct {
	// "owner/name".
	FullName      string
	DefaultBranch string
}

// ListInstallationRepositories enumerates the repositories an installation
// grants, using an installation token rather than the app JWT — this is the
// installation's own view, which is exactly the set a tenant may connect.
// Pages are followed to exhaustion so a tenant with more than one page of
// selected repositories does not silently see a truncated list.
func (c *Connector) ListInstallationRepositories(ctx context.Context, token string) ([]InstallationRepository, error) {
	var repos []InstallationRepository
	for page := 1; page <= maxInstallationRepositoryPages; page++ {
		endpoint := fmt.Sprintf("%s/installation/repositories?per_page=%d&page=%d",
			c.baseURL, installationRepositoryPageSize, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		setGitHubHeaders(req)

		var out struct {
			Repositories []struct {
				FullName      string `json:"full_name"`
				DefaultBranch string `json:"default_branch"`
			} `json:"repositories"`
		}
		if err := c.do(req, &out); err != nil {
			return nil, fmt.Errorf("list installation repositories: %w", err)
		}
		for _, repo := range out.Repositories {
			repos = append(repos, InstallationRepository{
				FullName:      repo.FullName,
				DefaultBranch: repo.DefaultBranch,
			})
		}
		if len(out.Repositories) < installationRepositoryPageSize {
			return repos, nil
		}
	}
	return nil, fmt.Errorf("list installation repositories: installation grants more than %d repositories",
		maxInstallationRepositoryPages*installationRepositoryPageSize)
}
