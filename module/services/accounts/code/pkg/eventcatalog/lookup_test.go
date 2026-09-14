package eventcatalog

import "testing"

// TestResolvePartition covers the declared ordering domains a contribution may
// write. The composed catalog only carries "{tenant_id}" today, so the
// boundary-scoped template — the finer partition EVENTS.md documents — has no
// route through the generated table and is pinned here directly. Shapes compose
// rejects (an unknown placeholder, a template with no {tenant_id}) are not
// pinned here: they cannot reach this function.
func TestResolvePartition(t *testing.T) {
	for _, tc := range []struct {
		name     string
		template string
		want     string
	}{
		{name: "no declaration is no partition", template: "", want: ""},
		{name: "tenant scope", template: "{tenant_id}", want: "org-1"},
		{name: "boundary scope", template: "{tenant_id}/{boundary_id}", want: "org-1/node-7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolvePartition(tc.template, "org-1", "node-7"); got != tc.want {
				t.Fatalf("ResolvePartition(%q) = %q, want %q", tc.template, got, tc.want)
			}
		})
	}
}

// TestLookupPublishedReportsCatalogMembership pins the signal a publisher needs
// to tell "this type declares no ordering" apart from "this deployment's catalog
// has never heard of this type" — two states that must not collapse into one
// empty partition key.
func TestLookupPublishedReportsCatalogMembership(t *testing.T) {
	declared, ok := LookupPublished("scope.granted")
	if !ok {
		t.Fatal("scope.granted must be declared in the composed catalog")
	}
	if got := ResolvePartition(declared.Partition, "org-1", "node-7"); got != "org-1" {
		t.Fatalf("scope.granted partition resolved to %q, want the tenant", got)
	}
	if _, ok := LookupPublished("scope.unregistered"); ok {
		t.Fatal("an uncatalogued type must not report as declared")
	}
}

// TestLookupFollowable pins the resolution the follows fan-out runs for every
// delivered event: a type answers with the one resource type whose followers it
// concerns, and the host then matches on (ResourceType, envelope subject). No
// composed contribution declares a followable resource yet — that declaration is
// a module's to make — so the table is substituted here rather than asserted
// against the generated one.
func TestLookupFollowable(t *testing.T) {
	original := followableIndex
	t.Cleanup(func() { followableIndex = original })
	entry := FollowableResource{
		ResourceType: "documents.entry",
		Namespace:    "documents",
		Events:       []string{"documents.entry.renamed", "documents.entry.version_minted"},
	}
	followableIndex = map[string]FollowableResource{
		"documents.entry.renamed":        entry,
		"documents.entry.version_minted": entry,
	}

	for _, eventType := range entry.Events {
		declared, ok := LookupFollowable(eventType)
		if !ok {
			t.Fatalf("%q must resolve to its followable resource", eventType)
		}
		if declared.ResourceType != "documents.entry" {
			t.Fatalf("%q resolved to resource type %q", eventType, declared.ResourceType)
		}
	}
	if _, ok := LookupFollowable("documents.entry.ingested"); ok {
		t.Fatal("an event no contribution declares followable must not resolve")
	}
}

// TestFollowableIndexCoversTheComposedTable guards the wiring the test above
// cannot: substituting the index would keep passing even if the generated
// `followable` array were never indexed at all. The composed table is empty
// today, so it is the invariant — every declared event resolves to its own
// resource type — and not a count that has to hold.
func TestFollowableIndexCoversTheComposedTable(t *testing.T) {
	for _, declared := range followable {
		for _, eventType := range declared.Events {
			resolved, ok := LookupFollowable(eventType)
			if !ok || resolved.ResourceType != declared.ResourceType {
				t.Fatalf("composed followable event %q does not resolve to %q", eventType, declared.ResourceType)
			}
		}
	}
}

// TestUnorderedPublishedTypesSelectsUndeclaredPartitions pins the selection the
// Subscribe ordering gate depends on. The composed catalog declares a partition
// on every type today, so the list is empty — the invariant, not the length, is
// what must hold: a type is listed exactly when it declares no partition, so
// inverting the condition (and rejecting every ordered subscription, or none)
// fails here rather than in a deployment.
func TestUnorderedPublishedTypesSelectsUndeclaredPartitions(t *testing.T) {
	listed := map[string]struct{}{}
	for _, eventType := range UnorderedPublishedTypes() {
		listed[eventType] = struct{}{}
	}
	for _, e := range published {
		_, isListed := listed[e.Type]
		if declaresNone := e.Partition == ""; declaresNone != isListed {
			t.Fatalf("type %q declares partition %q but listed-as-unordered = %v", e.Type, e.Partition, isListed)
		}
	}
}
