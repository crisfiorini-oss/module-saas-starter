package composition

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/codefly-dev/agents/modules/saas-starter/module/tools/modulepackage"
)

func eventsProtoRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "documents/events/v1/entry.proto"), `syntax = "proto3";
package documents.events.v1;
message EntryIngested {
  string id = 1;
  string boundary_id = 2;
}
`)
	writeFile(t, filepath.Join(root, "documents/events/v2/entry.proto"), `syntax = "proto3";
package documents.events.v2;
message EntryIngested {
  string id = 1;
}
`)
	return root
}

func documentsContribution() EventsContribution {
	return EventsContribution{
		Schema:    eventsContributionSchema,
		Namespace: "documents",
		Queues:    []string{"documents.ingest"},
		Publishes: []PublishedEvent{{
			Type:       "documents.entry.ingested",
			Schema:     "documents/events/v1/entry.proto#EntryIngested",
			Visibility: "tenant",
			Partition:  "{tenant_id}/{boundary_id}",
			Retention:  "30d",
		}},
		Consumes: []ConsumedEvent{{
			Type:     "documents.entry.ingested",
			Queue:    "documents.ingest",
			Delivery: "ordered",
		}},
	}
}

func TestBuildEventCatalogMergesPublishesAndConsumes(t *testing.T) {
	catalog, err := buildEventCatalog([]EventsContribution{documentsContribution()}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err != nil {
		t.Fatalf("buildEventCatalog: %v", err)
	}
	if len(catalog.Publishes) != 1 || catalog.Publishes[0].Type != "documents.entry.ingested" {
		t.Fatalf("unexpected publishes: %+v", catalog.Publishes)
	}
	if catalog.Publishes[0].Major != 1 || len(catalog.Publishes[0].Fields) != 2 {
		t.Fatalf("schema fields not resolved: %+v", catalog.Publishes[0])
	}
	if len(catalog.Consumes) != 1 || catalog.Consumes[0].Subscriber != "documents" {
		t.Fatalf("unexpected consumes: %+v", catalog.Consumes)
	}
}

func TestBuildEventCatalogRejectsNamespaceOwnership(t *testing.T) {
	contribution := documentsContribution()
	contribution.Publishes[0].Type = "billing.invoice.paid"
	contribution.Consumes = nil
	_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "outside namespace") {
		t.Fatalf("expected namespace-ownership error, got %v", err)
	}
}

// TestBuildEventCatalogRejectsUnknownPartitionField is the global-lock
// regression. A partition template is substituted into a live partition key at
// publish time, and that key is what publish_domain_event takes its advisory
// lock on. An unknown placeholder is not caught by substitution — it survives
// verbatim, so every tenant resolves the SAME literal key, collapsing the whole
// deployment onto one lock and interleaving unrelated tenants into one FIFO
// order. Compose is where a typo has to die.
func TestBuildEventCatalogRejectsUnknownPartitionField(t *testing.T) {
	contribution := documentsContribution()
	contribution.Publishes[0].Partition = "{org_id}"
	contribution.Consumes = nil
	_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-partition-field error, got %v", err)
	}
}

// TestBuildEventCatalogRejectsCrossTenantPartition guards the same blast radius
// from the other direction: a template made only of resolvable fields can still
// name a key shared by every tenant. "{boundary_id}" resolves fine and puts two
// tenants that happen to use the same boundary id into one ordering domain.
func TestBuildEventCatalogRejectsCrossTenantPartition(t *testing.T) {
	contribution := documentsContribution()
	contribution.Publishes[0].Partition = "{boundary_id}"
	contribution.Consumes = nil
	_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "without {tenant_id}") {
		t.Fatalf("expected cross-tenant-partition error, got %v", err)
	}
}

// TestBuildEventCatalogAcceptsNoPartition pins that declaring no partition stays
// legal — it is how a producer says the type is unordered, which is what keeps
// it from paying for an advisory lock it does not need.
func TestBuildEventCatalogAcceptsNoPartition(t *testing.T) {
	contribution := documentsContribution()
	contribution.Publishes[0].Partition = ""
	contribution.Consumes[0].Delivery = "unordered"
	catalog, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err != nil {
		t.Fatalf("an unordered type must compose: %v", err)
	}
	if catalog.Publishes[0].Partition != "" {
		t.Fatalf("expected no partition, got %q", catalog.Publishes[0].Partition)
	}
}

// A reserved namespace belongs to the module that declared the reservation. It
// is refused on the publish side already; refusing it on the consume side is
// what stops a downstream contribution from subscribing itself to a
// platform-owned stream by declaring it.
func TestBuildEventCatalogRejectsReservedNamespaceConsume(t *testing.T) {
	manifest := modulepackage.Manifest{ReservedNamespaces: []string{"saas"}}
	platform := documentsContribution()
	platform.Namespace = "saas"
	platform.Publishes[0].Type = "saas.session.revoked"
	platform.Consumes = nil
	platform.BaseOwned = true

	consumer := documentsContribution()
	consumer.Consumes = []ConsumedEvent{{
		Type: "saas.session.revoked", Queue: "documents.ingest", Delivery: "unordered",
	}}

	_, err := buildEventCatalog([]EventsContribution{platform, consumer}, manifest, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "reserved namespace") {
		t.Fatalf("expected reserved-namespace consume error, got %v", err)
	}

	// The module that owns the reservation may still consume its own namespace.
	platform.Consumes = []ConsumedEvent{{
		Type: "saas.session.revoked", Queue: "documents.ingest", Delivery: "unordered",
	}}
	if _, err := buildEventCatalog([]EventsContribution{platform}, manifest, eventsProtoRoot(t), eventCatalog{}); err != nil {
		t.Fatalf("base-owned contribution must consume its own namespace: %v", err)
	}
}

func TestBuildEventCatalogRejectsUnresolvedSchema(t *testing.T) {
	contribution := documentsContribution()
	contribution.Publishes[0].Schema = "documents/events/v1/entry.proto#Missing"
	contribution.Consumes = nil
	_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected unresolved-schema error, got %v", err)
	}
}

func TestBuildEventCatalogRejectsDuplicateType(t *testing.T) {
	contribution := documentsContribution()
	contribution.Publishes = append(contribution.Publishes, PublishedEvent{
		Type:       "documents.entry.ingested",
		Schema:     "documents/events/v1/entry.proto#EntryIngested",
		Visibility: "tenant",
	})
	contribution.Consumes = nil
	_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("expected duplicate-type error, got %v", err)
	}
}

func TestBuildEventCatalogRejectsUnregisteredConsume(t *testing.T) {
	contribution := documentsContribution()
	contribution.Consumes[0].Type = "datasource.source.changed"
	_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "not a registered published type") {
		t.Fatalf("expected unregistered-consume error, got %v", err)
	}
}

func TestBuildEventCatalogRejectsUndeclaredQueue(t *testing.T) {
	contribution := documentsContribution()
	contribution.Consumes[0].Queue = "documents.other"
	_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "did not declare") {
		t.Fatalf("expected undeclared-queue error, got %v", err)
	}
}

func TestBuildEventCatalogRejectsBreakingFieldRemoval(t *testing.T) {
	prior := eventCatalog{Schema: eventsCatalogSchema, Publishes: []eventCatalogPublish{{
		Type:  "documents.entry.ingested",
		Major: 1,
		Fields: []eventField{
			{Name: "id", Number: 1, Type: "string"},
			{Name: "boundary_id", Number: 2, Type: "string"},
			{Name: "removed", Number: 3, Type: "string"},
		},
	}}}
	contribution := documentsContribution()
	contribution.Consumes = nil
	_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), prior)
	if err == nil || !strings.Contains(err.Error(), "removes field") {
		t.Fatalf("expected breaking-change error, got %v", err)
	}
}

func TestBuildEventCatalogCatchesBreakingOneofFieldRemoval(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "documents/events/v1/choice.proto"), `syntax = "proto3";
package documents.events.v1;
message Choice {
  string id = 1;
  oneof body {
    string a = 2;
  }
}
`)
	prior := eventCatalog{Schema: eventsCatalogSchema, Publishes: []eventCatalogPublish{{
		Type:  "documents.entry.ingested",
		Major: 1,
		Fields: []eventField{
			{Name: "id", Number: 1, Type: "string"},
			{Name: "a", Number: 2, Type: "string"},
			{Name: "b", Number: 3, Type: "string"},
		},
	}}}
	contribution := documentsContribution()
	contribution.Publishes[0].Schema = "documents/events/v1/choice.proto#Choice"
	contribution.Consumes = nil
	_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, root, prior)
	if err == nil || !strings.Contains(err.Error(), "removes field") {
		t.Fatalf("removing a oneof member without a major bump must fail compose, got %v", err)
	}
}

func TestBuildEventCatalogAllowsBreakingChangeBehindMajorBump(t *testing.T) {
	prior := eventCatalog{Schema: eventsCatalogSchema, Publishes: []eventCatalogPublish{{
		Type:  "documents.entry.ingested",
		Major: 1,
		Fields: []eventField{
			{Name: "id", Number: 1, Type: "string"},
			{Name: "boundary_id", Number: 2, Type: "string"},
		},
	}}}
	contribution := documentsContribution()
	contribution.Publishes[0].Schema = "documents/events/v2/entry.proto#EntryIngested"
	contribution.Consumes = nil
	catalog, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), prior)
	if err != nil {
		t.Fatalf("major bump should permit a breaking change: %v", err)
	}
	if catalog.Publishes[0].Major != 2 {
		t.Fatalf("expected major 2, got %d", catalog.Publishes[0].Major)
	}
}

func TestRenderEventCatalogEmitsJSONAndGo(t *testing.T) {
	catalog, err := buildEventCatalog([]EventsContribution{documentsContribution()}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err != nil {
		t.Fatalf("buildEventCatalog: %v", err)
	}
	files, err := renderEventCatalog(catalog)
	if err != nil {
		t.Fatalf("renderEventCatalog: %v", err)
	}
	jsonBody := string(files[EventCatalogOutput])
	if !strings.Contains(jsonBody, `"schema": "codefly/saas/events-catalog/v1"`) || !strings.Contains(jsonBody, `"documents.entry.ingested"`) {
		t.Fatalf("event catalog JSON is malformed:\n%s", jsonBody)
	}
	goBody := string(files[EventGoOutput])
	if !strings.Contains(goBody, "package eventcatalog") || !strings.Contains(goBody, `Type: "documents.entry.ingested"`) {
		t.Fatalf("event catalog Go is malformed:\n%s", goBody)
	}
}

func TestRenderEventCatalogEmitsEmptyArrays(t *testing.T) {
	files, err := renderEventCatalog(eventCatalog{Schema: eventsCatalogSchema, Publishes: []eventCatalogPublish{}, Consumes: []eventCatalogConsume{}})
	if err != nil {
		t.Fatalf("renderEventCatalog: %v", err)
	}
	if !strings.Contains(string(files[EventCatalogOutput]), `"publishes": []`) {
		t.Fatalf("empty catalog must emit an empty publishes array:\n%s", files[EventCatalogOutput])
	}
}

func TestRenderEventCatalogEmitsAsyncAPIAndDocs(t *testing.T) {
	catalog, err := buildEventCatalog([]EventsContribution{documentsContribution()}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err != nil {
		t.Fatalf("buildEventCatalog: %v", err)
	}
	files, err := renderEventCatalog(catalog)
	if err != nil {
		t.Fatalf("renderEventCatalog: %v", err)
	}

	async := string(files[AsyncAPIOutput])
	for _, want := range []string{
		`"asyncapi": "3.0.0"`,
		`"version": "1.0.0"`,
		`"send:documents.entry.ingested"`,
		`"receive:documents.entry.ingested:documents:documents.ingest"`,
		`"action": "send"`,
		`"action": "receive"`,
		`"x-visibility": "tenant"`,
		`"#/channels/documents.entry.ingested"`,
	} {
		if !strings.Contains(async, want) {
			t.Fatalf("asyncapi.json missing %q:\n%s", want, async)
		}
	}

	docs := string(files[CommunicationOutput])
	for _, want := range []string{
		"## documents.entry.ingested",
		"- **Publisher:** documents",
		"- **Consumers:**",
		"documents (queue `documents.ingest`, delivery ordered)",
	} {
		if !strings.Contains(docs, want) {
			t.Fatalf("communication.md missing %q:\n%s", want, docs)
		}
	}
}

func TestRenderAsyncAPIIsDeterministic(t *testing.T) {
	catalog, err := buildEventCatalog([]EventsContribution{documentsContribution()}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err != nil {
		t.Fatalf("buildEventCatalog: %v", err)
	}
	first, err := renderAsyncAPI(catalog)
	if err != nil {
		t.Fatalf("renderAsyncAPI: %v", err)
	}
	second, err := renderAsyncAPI(catalog)
	if err != nil {
		t.Fatalf("renderAsyncAPI: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("asyncapi.json is not byte-deterministic")
	}
}

// followsContribution declares the documents module's own noun as followable
// over its own tenant-visible fact — the shape FOLLOWS.md specifies.
func followsContribution() EventsContribution {
	contribution := documentsContribution()
	contribution.Follows = []FollowableResource{{
		ResourceType: "documents.entry",
		Events:       []string{"documents.entry.ingested"},
	}}
	return contribution
}

func TestBuildEventCatalogMergesFollows(t *testing.T) {
	catalog, err := buildEventCatalog([]EventsContribution{followsContribution()}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err != nil {
		t.Fatalf("buildEventCatalog: %v", err)
	}
	if len(catalog.Follows) != 1 {
		t.Fatalf("unexpected follows: %+v", catalog.Follows)
	}
	follow := catalog.Follows[0]
	if follow.ResourceType != "documents.entry" || follow.Namespace != "documents" {
		t.Fatalf("follow lost its identity: %+v", follow)
	}
	if len(follow.Events) != 1 || follow.Events[0] != "documents.entry.ingested" {
		t.Fatalf("follow lost its events: %+v", follow)
	}
}

// TestBuildEventCatalogRejectsFollowsOverAnotherNamespacesFact is the ownership
// rule. A follow declaration is what makes the host fan an event into a
// stranger's inbox, so letting a module name a type it does not publish would
// let it mint notifications about another module's resources.
func TestBuildEventCatalogRejectsFollowsOverAnotherNamespacesFact(t *testing.T) {
	billing := documentsContribution()
	billing.Namespace = "billing"
	billing.Queues = nil
	billing.Publishes = nil
	billing.Consumes = nil
	billing.Follows = []FollowableResource{{
		ResourceType: "billing.entry",
		Events:       []string{"documents.entry.ingested"},
	}}
	_, err := buildEventCatalog([]EventsContribution{documentsContribution(), billing}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "does not publish") {
		t.Fatalf("expected a foreign-fact error, got %v", err)
	}
}

// A followable event must be tenant-visible. An internal type is short-circuited
// by the relay before any subscriber sees it, so declaring one followable
// promises an inbox item that can never arrive.
func TestBuildEventCatalogRejectsNonTenantFollowableEvent(t *testing.T) {
	for _, visibility := range []string{"internal", "external"} {
		t.Run(visibility, func(t *testing.T) {
			contribution := followsContribution()
			contribution.Publishes[0].Visibility = visibility
			contribution.Consumes = nil
			_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
			if err == nil || !strings.Contains(err.Error(), "must be tenant-visible") {
				t.Fatalf("expected a visibility error, got %v", err)
			}
		})
	}
}

// The platform namespace is refused to module principals, so a resource under it
// could be followed by nobody the follow path serves. The reservation has to mean
// the same thing on the follows side as it already does on publish and consume.
func TestBuildEventCatalogRejectsFollowsInReservedNamespace(t *testing.T) {
	manifest := modulepackage.Manifest{ReservedNamespaces: []string{"saas"}}
	platform := documentsContribution()
	platform.Namespace = "saas"
	platform.Publishes[0].Type = "saas.session.revoked"
	platform.Consumes = nil
	platform.BaseOwned = true
	platform.Follows = []FollowableResource{{
		ResourceType: "saas.session",
		Events:       []string{"saas.session.revoked"},
	}}
	_, err := buildEventCatalog([]EventsContribution{platform}, manifest, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected a reserved-namespace follows error, got %v", err)
	}
}

func TestBuildEventCatalogRejectsDuplicateFollowableResourceType(t *testing.T) {
	first := followsContribution()
	first.Consumes = nil
	second := followsContribution()
	second.Namespace = "records"
	second.Queues = nil
	second.Consumes = nil
	second.Publishes[0].Type = "records.entry.ingested"
	second.Follows[0].Events = []string{"records.entry.ingested"}

	_, err := buildEventCatalog([]EventsContribution{first, second}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "more than one contribution") {
		t.Fatalf("expected a duplicate-resource-type error, got %v", err)
	}
}

// TestBuildEventCatalogRejectsEventFollowableByTwoResourceTypes keeps the
// event→resource mapping single-valued. The host matches a delivery on
// (resource_type, envelope subject), and a subject is one resource's id: two
// resource types over one event would ask that id to be both of them, and the
// generated lookup could only answer with whichever declaration sorted last.
func TestBuildEventCatalogRejectsEventFollowableByTwoResourceTypes(t *testing.T) {
	contribution := followsContribution()
	contribution.Consumes = nil
	contribution.Follows = append(contribution.Follows, FollowableResource{
		ResourceType: "documents.folder",
		Events:       []string{"documents.entry.ingested"},
	})
	_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "more than one resource type") {
		t.Fatalf("expected a doubly-followable-event error, got %v", err)
	}
}

func TestBuildEventCatalogRejectsMalformedFollowsDeclaration(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		follows []FollowableResource
		want    string
	}{
		{
			name:    "resource type is not a logical id",
			follows: []FollowableResource{{ResourceType: "Documents Entry", Events: []string{"documents.entry.ingested"}}},
			want:    "not a valid logical id",
		},
		{
			name:    "no events",
			follows: []FollowableResource{{ResourceType: "documents.entry"}},
			want:    "declares no events",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			contribution := documentsContribution()
			contribution.Consumes = nil
			contribution.Follows = testCase.follows
			_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("expected %q, got %v", testCase.want, err)
			}
		})
	}
}

func TestRenderEventCatalogProjectsFollows(t *testing.T) {
	catalog, err := buildEventCatalog([]EventsContribution{followsContribution()}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err != nil {
		t.Fatalf("buildEventCatalog: %v", err)
	}
	files, err := renderEventCatalog(catalog)
	if err != nil {
		t.Fatalf("renderEventCatalog: %v", err)
	}
	for artifact, want := range map[string]string{
		EventCatalogOutput:  `"resource_type": "documents.entry"`,
		EventGoOutput:       `{ResourceType: "documents.entry", Namespace: "documents", Events: []string{"documents.entry.ingested"}},`,
		AsyncAPIOutput:      `"x-followable-resource": "documents.entry"`,
		CommunicationOutput: "- **Follows:** `documents.entry`",
	} {
		if !strings.Contains(string(files[artifact]), want) {
			t.Fatalf("%s missing %q:\n%s", artifact, want, files[artifact])
		}
	}
	// The worker resolves an event to its target through this accessor.
	if !strings.Contains(string(files[EventGoOutput]), "func Followable() []FollowableResource {") {
		t.Fatalf("the Go projection must expose Followable():\n%s", files[EventGoOutput])
	}
}

func TestRenderEventDocsHandlesNoConsumers(t *testing.T) {
	docs := string(renderEventDocs(eventCatalog{
		Schema: eventsCatalogSchema,
		Publishes: []eventCatalogPublish{{
			Type: "documents.entry.ingested", Namespace: "documents", Schema: "documents/events/v1/entry.proto#EntryIngested", Major: 1, Visibility: "tenant",
		}},
	}))
	if !strings.Contains(docs, "- **Consumers:** _none_") {
		t.Fatalf("a type with no consumers must render _none_:\n%s", docs)
	}
}
