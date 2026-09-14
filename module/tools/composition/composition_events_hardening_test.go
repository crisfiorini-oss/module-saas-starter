package composition

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codefly-dev/agents/modules/saas-starter/module/tools/modulepackage"
)

// twoQueueContribution declares one published type consumed twice by its own
// namespace on two different queues. That is legal — a subscriber may fan one
// type into two workloads — and it is the shape whose ordering the Consumes
// comparator has to settle, because the pair ties on both Type and Subscriber.
func twoQueueContribution() EventsContribution {
	contribution := documentsContribution()
	contribution.Queues = []string{"documents.ingest", "documents.audit"}
	contribution.Consumes = []ConsumedEvent{
		{Type: "documents.entry.ingested", Queue: "documents.ingest", Delivery: "ordered"},
		{Type: "documents.entry.ingested", Queue: "documents.audit", Delivery: "unordered"},
	}
	return contribution
}

// TestBuildEventCatalogOrdersTiedConsumesByQueue pins the comparator that keeps
// four generated artifacts byte-stable. Two consumes of one type by one
// subscriber differ only in queue, so a comparator keyed on (Type, Subscriber)
// alone calls them equal — and sort.Slice, which is not stable, is then free to
// emit them in either order. Nothing about the inputs would have changed when
// the bytes did: event-catalog.json, catalog_gen.go, asyncapi.json and
// communication.md are all base-manifest-tracked, so the drift surfaces as a
// "Base manifest integrity" CI failure with an empty-looking cause. Sorting on
// the queue (and then delivery) leaves no pair tied.
func TestBuildEventCatalogOrdersTiedConsumesByQueue(t *testing.T) {
	// Feed the tied pair in the reverse of the expected order, so a comparator
	// that cannot separate them has to move them to pass.
	contribution := twoQueueContribution()
	contribution.Consumes[0], contribution.Consumes[1] = contribution.Consumes[1], contribution.Consumes[0]

	catalog, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err != nil {
		t.Fatalf("buildEventCatalog: %v", err)
	}
	if len(catalog.Consumes) != 2 {
		t.Fatalf("expected both consumes, got %+v", catalog.Consumes)
	}
	if catalog.Consumes[0].Queue != "documents.audit" || catalog.Consumes[1].Queue != "documents.ingest" {
		t.Fatalf("consumes tied on (type, subscriber) must order by queue, got %q then %q",
			catalog.Consumes[0].Queue, catalog.Consumes[1].Queue)
	}
}

// TestBuildEventCatalogRejectsDuplicateConsume covers the input that made three
// artifacts disagree. event-catalog.json and catalog_gen.go are built from the
// Consumes slice and would carry the duplicate twice; renderAsyncAPI keys its
// receive operation on (type, subscriber, queue) and silently keeps whichever
// row it wrote last. Rejecting the duplicate is what keeps the projections from
// describing two different systems.
func TestBuildEventCatalogRejectsDuplicateConsume(t *testing.T) {
	contribution := documentsContribution()
	contribution.Consumes = append(contribution.Consumes, ConsumedEvent{
		Type:     "documents.entry.ingested",
		Queue:    "documents.ingest",
		Delivery: "unordered",
	})
	_, err := buildEventCatalog([]EventsContribution{contribution}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("expected duplicate-consume error, got %v", err)
	}
}

// TestReadEventCatalogRejectsUntrustworthyBaseline covers the fail-open half of
// the breaking-change gate. The catalog this reader returns is the ONLY baseline
// checkBreakingChange compares against, and an entry it fails to recover is
// indistinguishable from a type that has never been published — so a removed
// field passes the gate unnoticed. A plain json.Unmarshal accepts every document
// below; each must now stop the compose instead.
func TestReadEventCatalogRejectsUntrustworthyBaseline(t *testing.T) {
	valid := eventCatalog{
		Schema: eventsCatalogSchema,
		Publishes: []eventCatalogPublish{{
			Type: "documents.entry.ingested", Namespace: "documents",
			Schema: "documents/events/v1/entry.proto#EntryIngested", Major: 1,
			Visibility: "tenant",
			Fields:     []eventField{{Name: "id", Number: 1, Type: "string"}},
		}},
		Consumes: []eventCatalogConsume{},
	}
	body, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown field",
			// A misspelled or newer key: json.Unmarshal drops it, so a field the
			// gate should compare simply vanishes from the baseline.
			body: `{"schema":"` + eventsCatalogSchema + `","publishes":[{"type":"documents.entry.ingested","fieldz":[]}],"consumes":[]}`,
			want: "unknown field",
		},
		{
			name: "wrong schema",
			// Some other generated JSON pointed at this path decodes into mostly
			// zero values and reads as an empty catalog — every type unpublished.
			body: `{"schema":"codefly/saas/topology-catalog/v1","publishes":[],"consumes":[]}`,
			want: "schema must be",
		},
		{
			name: "trailing content",
			// A concatenated or half-rewritten file: Unmarshal takes the first
			// value and ignores the rest, silently using a stale baseline.
			body: string(body) + `{"schema":"` + eventsCatalogSchema + `"}`,
			want: "multiple JSON values",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, filepath.FromSlash(EventCatalogOutput)), testCase.body)
			if _, err := readEventCatalog(root); err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("expected %q error, got %v", testCase.want, err)
			}
		})
	}
}

// TestReadEventCatalogAcceptsGeneratedBaseline is the other half: the hardening
// must not reject the artifact the compiler itself emits, or every compose after
// the first would fail.
func TestReadEventCatalogAcceptsGeneratedBaseline(t *testing.T) {
	catalog, err := buildEventCatalog([]EventsContribution{documentsContribution()}, modulepackage.Manifest{}, eventsProtoRoot(t), eventCatalog{})
	if err != nil {
		t.Fatalf("buildEventCatalog: %v", err)
	}
	files, err := renderEventCatalog(catalog)
	if err != nil {
		t.Fatalf("renderEventCatalog: %v", err)
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, filepath.FromSlash(EventCatalogOutput)), string(files[EventCatalogOutput]))

	reread, err := readEventCatalog(root)
	if err != nil {
		t.Fatalf("the generated catalog must be readable as a baseline: %v", err)
	}
	if len(reread.Publishes) != 1 || reread.Publishes[0].Type != "documents.entry.ingested" {
		t.Fatalf("baseline lost its publishes: %+v", reread.Publishes)
	}
	if len(reread.Publishes[0].Fields) != 2 {
		t.Fatalf("baseline lost the fields the breaking-change gate compares: %+v", reread.Publishes[0])
	}
}

// TestReadEventCatalogTreatsMissingFileAsNoBaseline keeps the first-ever compose
// working: no artifact yet is not a corrupt artifact.
func TestReadEventCatalogTreatsMissingFileAsNoBaseline(t *testing.T) {
	catalog, err := readEventCatalog(t.TempDir())
	if err != nil {
		t.Fatalf("a missing catalog is not an error: %v", err)
	}
	if len(catalog.Publishes) != 0 {
		t.Fatalf("expected an empty baseline, got %+v", catalog)
	}
}

// TestRenderAsyncAPIRejectsCollidingSchemaKeys covers the case sanitizeComponentKey
// used to claim was impossible. Component keys admit only [A-Za-z0-9._-], and a
// schema ref is a "<path>#<Message>" string, so both the path separator and the
// message separator collapse to the same "_" — which means two genuinely
// different refs can land on one key, unlike event types, whose grammar contains
// no character the sanitizer touches at all. Whichever type rendered first would
// then own the payload schema for both, publishing a contract the second type
// never declared, so the collision has to be reported rather than resolved by
// arrival order.
func TestRenderAsyncAPIRejectsCollidingSchemaKeys(t *testing.T) {
	// Both refs sanitize to documents_entry.proto_Ingested: "/" and "#" map to
	// the same replacement, so swapping which separator appears where preserves
	// the key while changing the ref.
	first := "documents/entry.proto#Ingested"
	second := "documents#entry.proto/Ingested"
	if sanitizeComponentKey(first) != sanitizeComponentKey(second) {
		t.Fatalf("test premise broken: %q and %q no longer collide", first, second)
	}
	catalog := eventCatalog{
		Schema: eventsCatalogSchema,
		Publishes: []eventCatalogPublish{
			{
				Type: "documents.entry.archived", Namespace: "documents",
				Schema: first, Major: 1, Visibility: "tenant",
				Fields: []eventField{{Name: "id", Number: 1, Type: "string"}},
			},
			{
				Type: "documents.entry.ingested", Namespace: "documents",
				Schema: second, Major: 1, Visibility: "tenant",
				Fields: []eventField{{Name: "other", Number: 1, Type: "string"}},
			},
		},
		Consumes: []eventCatalogConsume{},
	}
	if _, err := renderAsyncAPI(catalog); err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("expected a component-key collision error, got %v", err)
	}
}

// TestRenderAsyncAPIReusesOneSchemaKeyAcrossTypes is the negative control for the
// collision check: sharing one schema ref between two types is the normal case
// (every base contribution resolves to the same EventEnvelope) and must keep
// emitting a single shared component.
func TestRenderAsyncAPIReusesOneSchemaKeyAcrossTypes(t *testing.T) {
	shared := "documents/events/v1/entry.proto#EntryIngested"
	catalog := eventCatalog{
		Schema: eventsCatalogSchema,
		Publishes: []eventCatalogPublish{
			{Type: "documents.entry.archived", Namespace: "documents", Schema: shared, Major: 1, Visibility: "tenant"},
			{Type: "documents.entry.ingested", Namespace: "documents", Schema: shared, Major: 1, Visibility: "tenant"},
		},
		Consumes: []eventCatalogConsume{},
	}
	body, err := renderAsyncAPI(catalog)
	if err != nil {
		t.Fatalf("two types sharing one schema ref is not a collision: %v", err)
	}
	var doc asyncAPIDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components.Schemas) != 1 {
		t.Fatalf("expected one shared schema component, got %d", len(doc.Components.Schemas))
	}
}

// TestComposeEventsGeneratesEveryProjection is the Core-path regression. The
// events wiring used to exist only in Generate's flags branch, while codefly
// always drives the Core branch (module-compose defaults -input to
// CODEFLY_COMPOSITION_INPUT) — so the --events arguments the generator command
// passes on every invocation were parsed and then ignored, and no event artifact
// was ever regenerated on the path that actually runs. Both branches now call
// this one helper, so exercising it directly pins the behaviour both share.
func TestComposeEventsGeneratesEveryProjection(t *testing.T) {
	moduleRoot := t.TempDir()
	writeFile(t, filepath.Join(moduleRoot, "services/accounts/proto/documents/events/v1/entry.proto"), `syntax = "proto3";
package documents.events.v1;
message EntryIngested {
  string id = 1;
  string boundary_id = 2;
}
`)
	writeFile(t, filepath.Join(moduleRoot, "documents.events.codefly.yaml"), `schema: codefly/saas/events-contribution/v1
namespace: documents
queues:
  - documents.ingest
publishes:
  - type: documents.entry.ingested
    schema: documents/events/v1/entry.proto#EntryIngested
    visibility: tenant
    partition: "{tenant_id}"
    retention: 30d
consumes:
  - type: documents.entry.ingested
    queue: documents.ingest
    delivery: ordered
follows:
  - resource_type: documents.entry
    events:
      - documents.entry.ingested
`)

	options := Options{Events: []string{filepath.Join(moduleRoot, "documents.events.codefly.yaml")}}
	files := map[string][]byte{}
	if err := composeEvents(options, modulepackage.Manifest{}, moduleRoot, t.TempDir(), files); err != nil {
		t.Fatalf("composeEvents: %v", err)
	}
	for _, want := range []string{EventCatalogOutput, EventGoOutput, AsyncAPIOutput, CommunicationOutput} {
		if len(files[want]) == 0 {
			t.Fatalf("composeEvents did not produce %s", want)
		}
	}
	if !strings.Contains(string(files[EventGoOutput]), `Type: "documents.entry.ingested"`) {
		t.Fatalf("the Go projection lost the contributed type:\n%s", files[EventGoOutput])
	}
	// The contribution is decoded with KnownFields(true), so this also proves the
	// follows block is a field the loader accepts rather than one that fails the
	// whole document — the unit tests above construct the struct directly and
	// would not catch a missing yaml tag.
	if !strings.Contains(string(files[EventGoOutput]), `{ResourceType: "documents.entry", Namespace: "documents", Events: []string{"documents.entry.ingested"}},`) {
		t.Fatalf("the Go projection lost the contributed followable resource:\n%s", files[EventGoOutput])
	}
}

// TestComposeEventsLeavesArtifactsAloneWithoutContributions guards the other
// direction. Composing with no --events arguments must not write an empty
// catalog over the committed one: an empty catalog retracts every declared type,
// and because visibility is read from that catalog (eventcatalog.IsInternalPublished),
// retracting it would reclassify every internal event as deliverable and fan
// intra-platform events out to tenant subscribers.
func TestComposeEventsLeavesArtifactsAloneWithoutContributions(t *testing.T) {
	files := map[string][]byte{}
	if err := composeEvents(Options{}, modulepackage.Manifest{}, t.TempDir(), t.TempDir(), files); err != nil {
		t.Fatalf("composeEvents with no contributions: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("no contributions must write no event artifacts, got %v", keysOf(files))
	}
}

func keysOf(files map[string][]byte) []string {
	var out []string
	for path := range files {
		out = append(out, path)
	}
	return out
}
