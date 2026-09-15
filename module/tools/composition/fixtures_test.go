package composition

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	corecomposition "github.com/codefly-dev/core/composition"
	"gopkg.in/yaml.v3"
)

// seedUser is the minimal view of a seeded identity this test needs.
type seedUser struct {
	ID           string `yaml:"id"`
	Email        string `yaml:"email"`
	Role         string `yaml:"role"`
	ProviderID   string `yaml:"provider_id"`
	FixtureToken string `yaml:"fixture_token"`
}

type seedDocument struct {
	Users []seedUser `yaml:"users"`
}

// loginToken mirrors how the development validator resolves a credential:
// fixture_token is the login credential and provider_id only stands in when
// it is absent. Once a seed sets fixture_token the validator rejects the
// provider subject, so publishing provider_id would advertise a credential
// that cannot log in.
func (user seedUser) loginToken() string {
	if user.FixtureToken != "" {
		return user.FixtureToken
	}
	return user.ProviderID
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

func TestFixtureLoginTokenPrefersTheFixtureToken(t *testing.T) {
	for name, test := range map[string]struct {
		user seedUser
		want string
	}{
		"fixture token is the credential": {seedUser{ProviderID: "dev-admin", FixtureToken: "login-admin"}, "login-admin"},
		"provider id stands in":           {seedUser{ProviderID: "dev-admin"}, "dev-admin"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := test.user.loginToken(); got != test.want {
				t.Errorf("loginToken() = %q, want %q", got, test.want)
			}
		})
	}
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
			// A declared principal requires a non-empty id, so a seeded user
			// without a pinned one cannot be declared at all. Say that,
			// rather than reporting its role as merely undeclared.
			if user.ID == "" {
				t.Errorf("fixture %s seeds %s (role %q) without a pinned id, so no principal can declare it; pin an id in %s.yaml",
					fixture.Name, user.Email, user.Role, fixture.Name)
				continue
			}
			if previous, exists := seeded[user.ID]; exists {
				t.Errorf("fixture %s seeds id %s twice, for %s and %s", fixture.Name, user.ID, previous.Email, user.Email)
				continue
			}
			seeded[user.ID] = user
			undeclaredRoles[user.Role] = struct{}{}
		}

		for _, principal := range fixture.Principals {
			user, exists := seeded[principal.ID]
			if !exists {
				t.Errorf("fixture %s declares principal %s, which %s.yaml does not seed", fixture.Name, principal.ID, fixture.Name)
				continue
			}
			delete(undeclaredRoles, principal.Role)
			if user.Email != principal.Email || user.Role != principal.Role || user.loginToken() != principal.Token {
				t.Errorf("fixture %s declares principal %s as %s/%s/%s, seeded as %s/%s/%s",
					fixture.Name, principal.ID,
					principal.Email, principal.Role, principal.Token,
					user.Email, user.Role, user.loginToken())
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

	// A base topology claim is what reserves a fixture name against a consumer
	// contribution. The two lists name the same fixtures, so a declaration
	// without a claim leaves the name takeable, and a claim without a
	// declaration blocks a consumer from a name this package no longer ships.
	reserved := make(map[string]struct{})
	for _, claim := range manifest.Claims {
		if claim.Kind != corecomposition.CollisionTopology {
			continue
		}
		if name, found := strings.CutPrefix(claim.Key, "fixture/"); found {
			reserved[name] = struct{}{}
		}
	}
	for name := range declared {
		if _, exists := reserved[name]; !exists {
			t.Errorf("fixture %s is declared but no topology claim reserves fixture/%s, so a consumer contribution could take the name", name, name)
		}
	}
	for name := range reserved {
		if _, exists := declared[name]; !exists {
			t.Errorf("a topology claim reserves fixture/%s, which no fixture declares; it blocks consumers from a name this package does not ship", name)
		}
	}
}
