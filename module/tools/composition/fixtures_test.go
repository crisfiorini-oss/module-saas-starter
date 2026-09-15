package composition

import (
	"os"
	"path/filepath"
	"testing"

	corecomposition "github.com/codefly-dev/core/composition"
	"gopkg.in/yaml.v3"
)

// seedUser is the minimal view of a seeded identity this test needs. The
// fixture validator authenticates a development login by provider_id, so
// provider_id is the token the package manifest publishes for that principal.
type seedUser struct {
	ID         string `yaml:"id"`
	Email      string `yaml:"email"`
	Role       string `yaml:"role"`
	ProviderID string `yaml:"provider_id"`
}

type seedDocument struct {
	Users []seedUser `yaml:"users"`
}

func loadFixtureSeed(t *testing.T, moduleRoot, name string) []seedUser {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(moduleRoot, "fixtures", name+".yaml"))
	if err != nil {
		t.Fatalf("read fixture seed %s: %v", name, err)
	}
	var document seedDocument
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode fixture seed %s: %v", name, err)
	}
	if len(document.Users) == 0 {
		t.Fatalf("fixture seed %s creates no users", name)
	}
	return document.Users
}

// TestDeclaredFixturesMatchTheirSeedDocuments keeps the manifest's fixture
// declarations honest. A solution composing this package resolves a seeded
// principal by role against the version it composed, so a principal that is
// renamed, re-provisioned or dropped in a seed document has to fail here —
// against the package — instead of surfacing downstream as a login failure.
func TestDeclaredFixturesMatchTheirSeedDocuments(t *testing.T) {
	moduleRoot := findModuleRoot(t)

	manifest, err := corecomposition.LoadPackageManifest(moduleRoot)
	if err != nil {
		t.Fatalf("load package manifest: %v", err)
	}
	if len(manifest.Fixtures) == 0 {
		t.Fatal("package manifest declares no fixtures; expected dev-admin and simple")
	}

	declared := make(map[string]struct{}, len(manifest.Fixtures))
	for _, fixture := range manifest.Fixtures {
		declared[fixture.Name] = struct{}{}

		seeded := make(map[string]seedUser)
		undeclaredRoles := make(map[string]struct{})
		for _, user := range loadFixtureSeed(t, moduleRoot, fixture.Name) {
			seeded[user.ID] = user
			undeclaredRoles[user.Role] = struct{}{}
		}

		for _, principal := range fixture.Principals {
			delete(undeclaredRoles, principal.Role)
			user, exists := seeded[principal.ID]
			if !exists {
				t.Errorf("fixture %s declares principal %s, which %s.yaml does not seed", fixture.Name, principal.ID, fixture.Name)
				continue
			}
			if user.Email != principal.Email || user.Role != principal.Role || user.ProviderID != principal.Token {
				t.Errorf("fixture %s declares principal %s as %s/%s/%s, seeded as %s/%s/%s",
					fixture.Name, principal.ID,
					principal.Email, principal.Role, principal.Token,
					user.Email, user.Role, user.ProviderID)
			}
		}

		for role := range undeclaredRoles {
			t.Errorf("fixture %s seeds role %q with no declared principal", fixture.Name, role)
		}
	}

	entries, err := os.ReadDir(filepath.Join(moduleRoot, "fixtures"))
	if err != nil {
		t.Fatalf("read fixtures directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		name := entry.Name()[:len(entry.Name())-len(".yaml")]
		if _, exists := declared[name]; !exists {
			t.Errorf("fixtures/%s ships in the package but no fixture declares it", entry.Name())
		}
	}
}
