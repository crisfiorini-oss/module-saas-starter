package composition

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/codefly-dev/agents/modules/saas-starter/module/tools/modulepackage"
	protoparser "github.com/yoheimuta/go-protoparser/v4"
	"github.com/yoheimuta/go-protoparser/v4/parser"
)

const (
	eventsContributionSchema = "codefly/saas/events-contribution/v1"
	eventsCatalogSchema      = "codefly/saas/events-catalog/v1"
)

var (
	eventTypePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$`)
	eventQueuePattern  = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	versionDirPattern  = regexp.MustCompile(`^v([0-9]+)$`)
	eventVisibilitySet = map[string]struct{}{"internal": {}, "tenant": {}, "external": {}}
	eventDeliverySet   = map[string]struct{}{"ordered": {}, "unordered": {}}
	// eventPartitionPlaceholder matches one {...} substitution in a partition
	// template. Anything a producer writes between braces must name an envelope
	// scope field the publisher can actually resolve.
	eventPartitionPlaceholder = regexp.MustCompile(`\{([^{}]*)\}`)
	eventPartitionFieldSet    = map[string]struct{}{"tenant_id": {}, "boundary_id": {}}
)

// validatePartitionTemplate rejects a partition declaration the publisher cannot
// honour. The template is substituted into a live partition key at publish time,
// and that key is what publish_domain_event takes its advisory lock on, so an
// unresolvable template is not a cosmetic error: an unknown placeholder survives
// substitution verbatim and yields the same literal key for every tenant, which
// collapses the whole deployment onto one lock and interleaves unrelated
// tenants' events into a single FIFO order. Requiring {tenant_id} is the same
// guarantee stated positively — a partition is an ordering domain within one
// tenant, never across tenants. An empty declaration is valid and means the type
// is unordered.
func validatePartitionTemplate(eventType, template string) error {
	if template == "" {
		return nil
	}
	for _, match := range eventPartitionPlaceholder.FindAllStringSubmatch(template, -1) {
		if _, known := eventPartitionFieldSet[match[1]]; !known {
			return fmt.Errorf("event type %q declares partition %q naming unknown field %q; use {tenant_id} and {boundary_id}", eventType, template, match[1])
		}
	}
	if !strings.Contains(template, "{tenant_id}") {
		return fmt.Errorf("event type %q declares partition %q without {tenant_id}; a partition orders events within one tenant, so its key must be tenant-scoped", eventType, template)
	}
	return nil
}

// EventsContribution is one module's declaration of the domain events it
// publishes and consumes, a sibling of PermissionsContribution. It is discovered
// and merged into the base-manifest-tracked event catalog exactly like a
// permissions contribution.
type EventsContribution struct {
	Schema    string               `yaml:"schema"`
	Namespace string               `yaml:"namespace"`
	Queues    []string             `yaml:"queues"`
	Publishes []PublishedEvent     `yaml:"publishes"`
	Consumes  []ConsumedEvent      `yaml:"consumes"`
	Follows   []FollowableResource `yaml:"follows"`
	Owner     string               `yaml:"-"`
	// BaseOwned marks a contribution shipped by the module that owns the
	// reserved-namespace list, which is what lets it publish under one.
	BaseOwned bool `yaml:"-"`
}

type PublishedEvent struct {
	Type       string `yaml:"type"`
	Schema     string `yaml:"schema"`
	Visibility string `yaml:"visibility"`
	Partition  string `yaml:"partition"`
	Retention  string `yaml:"retention"`
}

type ConsumedEvent struct {
	Type     string `yaml:"type"`
	Queue    string `yaml:"queue"`
	Delivery string `yaml:"delivery"`
}

// FollowableResource is one noun of the declaring module that a person may
// follow, together with the committed changes worth notifying a follower about.
// The host matches a delivery on (ResourceType, envelope subject) and never
// decodes the payload, which is what keeps the fan-out free of any
// owner-specific knowledge.
type FollowableResource struct {
	ResourceType string   `yaml:"resource_type"`
	Events       []string `yaml:"events"`
}

type eventCatalog struct {
	Schema    string                `json:"schema"`
	Publishes []eventCatalogPublish `json:"publishes"`
	Consumes  []eventCatalogConsume `json:"consumes"`
	Follows   []eventCatalogFollow  `json:"follows"`
}

type eventCatalogPublish struct {
	Type       string       `json:"type"`
	Namespace  string       `json:"namespace"`
	Schema     string       `json:"schema"`
	Major      int          `json:"major"`
	Visibility string       `json:"visibility"`
	Partition  string       `json:"partition,omitempty"`
	Retention  string       `json:"retention,omitempty"`
	Fields     []eventField `json:"fields"`
}

type eventField struct {
	Name   string `json:"name"`
	Number int    `json:"number"`
	Type   string `json:"type"`
}

type eventCatalogConsume struct {
	Type       string `json:"type"`
	Subscriber string `json:"subscriber"`
	Queue      string `json:"queue"`
	Delivery   string `json:"delivery"`
}

type eventCatalogFollow struct {
	ResourceType string   `json:"resource_type"`
	Namespace    string   `json:"namespace"`
	Events       []string `json:"events"`
}

// consumedKey identifies one subscription: a namespace consuming one event type
// on one of its queues. It is the uniqueness key buildEventCatalog enforces, and
// it matches the tuple renderAsyncAPI keys its receive operations on.
type consumedKey struct {
	namespace string
	eventType string
	queue     string
}

// buildEventCatalog validates every events contribution and merges them into the
// deterministic catalog. It fails compose on namespace-ownership, unresolved
// schema, duplicate type, unregistered or undeclared-queue consumes, a follows
// declaration that reaches outside the contribution's own tenant-visible facts,
// and any breaking field change against the previously generated catalog.
func buildEventCatalog(contributions []EventsContribution, manifest modulepackage.Manifest, protoRoot string, prior eventCatalog) (eventCatalog, error) {
	catalog := eventCatalog{Schema: eventsCatalogSchema, Publishes: []eventCatalogPublish{}, Consumes: []eventCatalogConsume{}, Follows: []eventCatalogFollow{}}
	namespaces := map[string]struct{}{}
	publishedTypes := map[string]struct{}{}
	followedResources := map[string]struct{}{}
	followedEvents := map[string]struct{}{}
	priorByType := map[string]eventCatalogPublish{}
	for _, entry := range prior.Publishes {
		priorByType[entry.Type] = entry
	}

	type pendingConsume struct {
		contribution EventsContribution
		consume      ConsumedEvent
	}
	var consumes []pendingConsume
	consumedKeys := map[consumedKey]struct{}{}

	for _, contribution := range contributions {
		if contribution.Schema != eventsContributionSchema {
			return eventCatalog{}, fmt.Errorf("events contribution schema must be %s", eventsContributionSchema)
		}
		if !logicalIDPattern.MatchString(contribution.Namespace) ||
			(!contribution.BaseOwned && isReserved(manifest.ReservedNamespaces, contribution.Namespace)) {
			return eventCatalog{}, fmt.Errorf("events namespace %q is invalid or reserved", contribution.Namespace)
		}
		if _, duplicate := namespaces[contribution.Namespace]; duplicate {
			return eventCatalog{}, fmt.Errorf("events namespace %q is duplicated", contribution.Namespace)
		}
		namespaces[contribution.Namespace] = struct{}{}

		declaredQueues := map[string]struct{}{}
		for _, queue := range contribution.Queues {
			if !eventQueuePattern.MatchString(queue) {
				return eventCatalog{}, fmt.Errorf("events namespace %q declares invalid queue %q", contribution.Namespace, queue)
			}
			declaredQueues[queue] = struct{}{}
		}

		// declaredHere is this contribution's own published surface, keyed to the
		// visibility each type declared. It is what a follows block may draw from,
		// which is how "a module cannot declare follows over another namespace's
		// facts" becomes structural rather than a second lookup.
		declaredHere := map[string]string{}
		for _, published := range contribution.Publishes {
			if !eventTypePattern.MatchString(published.Type) {
				return eventCatalog{}, fmt.Errorf("event type %q is not a valid <namespace>.<aggregate>.<event> name", published.Type)
			}
			if !strings.HasPrefix(published.Type, contribution.Namespace+".") {
				return eventCatalog{}, fmt.Errorf("event type %q is outside namespace %q", published.Type, contribution.Namespace)
			}
			if _, exists := eventVisibilitySet[published.Visibility]; !exists {
				return eventCatalog{}, fmt.Errorf("event type %q has invalid visibility %q", published.Type, published.Visibility)
			}
			if err := validatePartitionTemplate(published.Type, published.Partition); err != nil {
				return eventCatalog{}, err
			}
			if _, duplicate := publishedTypes[published.Type]; duplicate {
				return eventCatalog{}, fmt.Errorf("event type %q is published by more than one namespace", published.Type)
			}
			fields, err := resolveProtoMessage(protoRoot, published.Schema)
			if err != nil {
				return eventCatalog{}, fmt.Errorf("event type %q schema: %w", published.Type, err)
			}
			major := majorFromSchema(published.Schema)
			if err := checkBreakingChange(published.Type, major, fields, priorByType); err != nil {
				return eventCatalog{}, err
			}
			publishedTypes[published.Type] = struct{}{}
			declaredHere[published.Type] = published.Visibility
			catalog.Publishes = append(catalog.Publishes, eventCatalogPublish{
				Type:       published.Type,
				Namespace:  contribution.Namespace,
				Schema:     published.Schema,
				Major:      major,
				Visibility: published.Visibility,
				Partition:  published.Partition,
				Retention:  published.Retention,
				Fields:     fields,
			})
		}

		// The platform namespace is refused to module principals, so a resource
		// under it could be followed by nobody the follow path serves. Refusing the
		// declaration keeps the reservation meaning one thing on every side of the
		// contribution, publish and consume included.
		if len(contribution.Follows) > 0 && isReserved(manifest.ReservedNamespaces, contribution.Namespace) {
			return eventCatalog{}, fmt.Errorf("events namespace %q is reserved and may not declare followable resources", contribution.Namespace)
		}
		for _, followable := range contribution.Follows {
			if !logicalIDPattern.MatchString(followable.ResourceType) {
				return eventCatalog{}, fmt.Errorf("followable resource type %q is not a valid logical id", followable.ResourceType)
			}
			if _, duplicate := followedResources[followable.ResourceType]; duplicate {
				return eventCatalog{}, fmt.Errorf("followable resource type %q is declared by more than one contribution", followable.ResourceType)
			}
			followedResources[followable.ResourceType] = struct{}{}
			if len(followable.Events) == 0 {
				return eventCatalog{}, fmt.Errorf("followable resource type %q declares no events", followable.ResourceType)
			}
			events := make([]string, 0, len(followable.Events))
			for _, eventType := range followable.Events {
				visibility, published := declaredHere[eventType]
				if !published {
					return eventCatalog{}, fmt.Errorf("followable resource type %q declares event %q that namespace %q does not publish", followable.ResourceType, eventType, contribution.Namespace)
				}
				// An internal event is short-circuited by the relay before any
				// subscriber sees it, and an external one is the outbound-webhook
				// spine rather than a tenant-visible fact. Only a tenant event can
				// actually reach the fan-out that a follower's inbox item comes from.
				if visibility != "tenant" {
					return eventCatalog{}, fmt.Errorf("followable resource type %q declares event %q with visibility %q; a followable event must be tenant-visible", followable.ResourceType, eventType, visibility)
				}
				// The host matches a delivery on (resource_type, envelope subject),
				// and a subject is one resource's id. Two resource types over one
				// event would ask that id to belong to both, so the declaration that
				// resolves an event to its target stays single-valued.
				if _, duplicate := followedEvents[eventType]; duplicate {
					return eventCatalog{}, fmt.Errorf("event %q is declared followable by more than one resource type", eventType)
				}
				followedEvents[eventType] = struct{}{}
				events = append(events, eventType)
			}
			sort.Strings(events)
			catalog.Follows = append(catalog.Follows, eventCatalogFollow{
				ResourceType: followable.ResourceType,
				Namespace:    contribution.Namespace,
				Events:       events,
			})
		}

		for _, consume := range contribution.Consumes {
			if _, exists := eventDeliverySet[consume.Delivery]; !exists {
				return eventCatalog{}, fmt.Errorf("consumed event %q has invalid delivery %q", consume.Type, consume.Delivery)
			}
			// A reserved namespace is refused to a contribution that does not own
			// it on the publish side; refusing it here too keeps the runtime
			// Subscribe gate from being the only thing standing between a declared
			// consume and a platform-owned stream.
			consumedNamespace, _, _ := strings.Cut(consume.Type, ".")
			if !contribution.BaseOwned && isReserved(manifest.ReservedNamespaces, consumedNamespace) {
				return eventCatalog{}, fmt.Errorf("consumed event %q is in reserved namespace %q", consume.Type, consumedNamespace)
			}
			if _, declared := declaredQueues[consume.Queue]; !declared {
				return eventCatalog{}, fmt.Errorf("consumed event %q names queue %q that namespace %q did not declare", consume.Type, consume.Queue, contribution.Namespace)
			}
			// A subscriber consuming one type on one queue is a single
			// subscription; declaring it twice is a contribution bug, and letting
			// it through makes the generated artifacts contradict each other.
			// event-catalog.json and catalog_gen.go would carry both rows, while
			// asyncapi.json keys its receive operation on
			// (type, subscriber, queue) and silently keeps only the last — three
			// artifacts, two answers. Rejecting the duplicate at its source is
			// what keeps the projections in agreement; it also makes the
			// (Type, Subscriber, Queue) sort key above genuinely total.
			consumed := consumedKey{namespace: contribution.Namespace, eventType: consume.Type, queue: consume.Queue}
			if _, duplicate := consumedKeys[consumed]; duplicate {
				return eventCatalog{}, fmt.Errorf("namespace %q consumes event %q on queue %q more than once", contribution.Namespace, consume.Type, consume.Queue)
			}
			consumedKeys[consumed] = struct{}{}
			consumes = append(consumes, pendingConsume{contribution: contribution, consume: consume})
		}
	}

	for _, pending := range consumes {
		if _, registered := publishedTypes[pending.consume.Type]; !registered {
			return eventCatalog{}, fmt.Errorf("consumed event %q is not a registered published type", pending.consume.Type)
		}
		catalog.Consumes = append(catalog.Consumes, eventCatalogConsume{
			Type:       pending.consume.Type,
			Subscriber: pending.contribution.Namespace,
			Queue:      pending.consume.Queue,
			Delivery:   pending.consume.Delivery,
		})
	}

	// Both comparators must be TOTAL over the values they can see, because
	// sort.Slice is not stable: any pair it considers equal may come out in
	// either order, and these slices are written straight into four
	// base-manifest-tracked artifacts. A tie there would let an unchanged input
	// regenerate to different bytes on a different toolchain and fail the
	// base-integrity gate with nothing in the diff to explain it. Publishes ties
	// on Type alone are impossible — a duplicate type is rejected above — but
	// Consumes are only unique across the whole (Type, Subscriber, Queue) tuple,
	// so all three sort, with Delivery last to leave no field outside the key.
	sort.Slice(catalog.Publishes, func(i, j int) bool { return catalog.Publishes[i].Type < catalog.Publishes[j].Type })
	sort.Slice(catalog.Consumes, func(i, j int) bool {
		left, right := catalog.Consumes[i], catalog.Consumes[j]
		if left.Type != right.Type {
			return left.Type < right.Type
		}
		if left.Subscriber != right.Subscriber {
			return left.Subscriber < right.Subscriber
		}
		if left.Queue != right.Queue {
			return left.Queue < right.Queue
		}
		return left.Delivery < right.Delivery
	})
	// Resource types are unique across contributions, so this comparator is total
	// for the same reason the Publishes one is.
	sort.Slice(catalog.Follows, func(i, j int) bool {
		return catalog.Follows[i].ResourceType < catalog.Follows[j].ResourceType
	})
	return catalog, nil
}

// followableIndex resolves a published event type to the followable resource it
// targets. It is a function, not a multimap, because buildEventCatalog refuses a
// second resource type over one event.
func followableIndex(catalog eventCatalog) map[string]string {
	index := map[string]string{}
	for _, follow := range catalog.Follows {
		for _, eventType := range follow.Events {
			index[eventType] = follow.ResourceType
		}
	}
	return index
}

// checkBreakingChange reuses the CONTRACT_VERSIONING.md rule that a field can
// never be removed or re-typed within one package major. A breaking change is
// only allowed behind a new major.
func checkBreakingChange(eventType string, major int, fields []eventField, prior map[string]eventCatalogPublish) error {
	previous, exists := prior[eventType]
	if !exists || previous.Major != major {
		return nil
	}
	current := map[int]eventField{}
	for _, field := range fields {
		current[field.Number] = field
	}
	for _, was := range previous.Fields {
		now, present := current[was.Number]
		if !present {
			return fmt.Errorf("event type %q removes field %q (%d) without a major bump", eventType, was.Name, was.Number)
		}
		if now.Type != was.Type {
			return fmt.Errorf("event type %q re-types field %d from %q to %q without a major bump", eventType, was.Number, was.Type, now.Type)
		}
	}
	return nil
}

func resolveProtoMessage(protoRoot, schema string) ([]eventField, error) {
	path, message, ok := strings.Cut(schema, "#")
	if !ok || path == "" || message == "" {
		return nil, fmt.Errorf("%q must be <path>#<Message>", schema)
	}
	if !safeRelativePath(path) || filepath.Ext(path) != ".proto" {
		return nil, fmt.Errorf("schema path %q is not a safe .proto reference", path)
	}
	file, err := os.Open(filepath.Join(protoRoot, filepath.FromSlash(path)))
	if err != nil {
		return nil, fmt.Errorf("open proto %q: %w", path, err)
	}
	defer file.Close()

	proto, err := protoparser.Parse(file)
	if err != nil {
		return nil, fmt.Errorf("parse proto %q: %w", path, err)
	}
	for _, body := range proto.ProtoBody {
		if definition, ok := body.(*parser.Message); ok && definition.MessageName == message {
			return messageFields(definition)
		}
	}
	return nil, fmt.Errorf("message %q not found in %q", message, path)
}

func messageFields(message *parser.Message) ([]eventField, error) {
	var fields []eventField
	for _, body := range message.MessageBody {
		switch field := body.(type) {
		case *parser.Field:
			number, err := strconv.Atoi(field.FieldNumber)
			if err != nil {
				return nil, fmt.Errorf("field %q has non-numeric number %q", field.FieldName, field.FieldNumber)
			}
			fieldType := field.Type
			if field.IsRepeated {
				fieldType = "repeated " + fieldType
			}
			fields = append(fields, eventField{Name: field.FieldName, Number: number, Type: fieldType})
		case *parser.MapField:
			number, err := strconv.Atoi(field.FieldNumber)
			if err != nil {
				return nil, fmt.Errorf("field %q has non-numeric number %q", field.MapName, field.FieldNumber)
			}
			fields = append(fields, eventField{Name: field.MapName, Number: number, Type: fmt.Sprintf("map<%s, %s>", field.KeyType, field.Type)})
		case *parser.Oneof:
			for _, member := range field.OneofFields {
				number, err := strconv.Atoi(member.FieldNumber)
				if err != nil {
					return nil, fmt.Errorf("field %q has non-numeric number %q", member.FieldName, member.FieldNumber)
				}
				fields = append(fields, eventField{Name: member.FieldName, Number: number, Type: member.Type})
			}
		}
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Number < fields[j].Number })
	return fields, nil
}

func majorFromSchema(schema string) int {
	path, _, _ := strings.Cut(schema, "#")
	major := 1
	for _, segment := range strings.Split(filepath.ToSlash(path), "/") {
		if match := versionDirPattern.FindStringSubmatch(segment); match != nil {
			if value, err := strconv.Atoi(match[1]); err == nil {
				major = value
			}
		}
	}
	return major
}

// readEventCatalog loads the previously generated catalog, which is the baseline
// checkBreakingChange compares against. That makes it a security-relevant read,
// not a convenience one: every field this decoder fails to recover is a field
// the breaking-change gate can no longer defend, and it fails *open* — an
// unreadable prior entry looks exactly like a type that has never been published
// before, so a field removal sails through. A plain json.Unmarshal accepts a
// truncated object, an unknown or misspelled key, a document of the wrong
// schema, and trailing garbage, all silently. It is therefore held to the same
// contract as its sibling readers (generateCoreComposition,
// readFrontendInstallCatalog): unknown fields rejected, no trailing content, and
// the schema constant checked, so a catalog that cannot be trusted stops the
// compose instead of quietly weakening it. A genuinely absent file still means
// "no baseline yet" and is not an error.
func readEventCatalog(outputRoot string) (eventCatalog, error) {
	body, err := os.ReadFile(filepath.Join(outputRoot, filepath.FromSlash(EventCatalogOutput)))
	if os.IsNotExist(err) {
		return eventCatalog{}, nil
	}
	if err != nil {
		return eventCatalog{}, fmt.Errorf("read previous event catalog: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var catalog eventCatalog
	if err := decoder.Decode(&catalog); err != nil {
		return eventCatalog{}, fmt.Errorf("decode previous event catalog: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return eventCatalog{}, fmt.Errorf("decode previous event catalog: %w", err)
	}
	if catalog.Schema != eventsCatalogSchema {
		return eventCatalog{}, fmt.Errorf("previous event catalog schema must be %s, got %q", eventsCatalogSchema, catalog.Schema)
	}
	return catalog, nil
}

func renderEventCatalog(catalog eventCatalog) (map[string][]byte, error) {
	catalogBody, err := marshalJSON(catalog)
	if err != nil {
		return nil, err
	}
	goBody, err := format.Source([]byte(renderEventCatalogGo(catalog)))
	if err != nil {
		return nil, fmt.Errorf("format Go event catalog: %w", err)
	}
	asyncapiBody, err := renderAsyncAPI(catalog)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		EventCatalogOutput:  catalogBody,
		EventGoOutput:       goBody,
		AsyncAPIOutput:      asyncapiBody,
		CommunicationOutput: renderEventDocs(catalog),
	}, nil
}

func renderEventCatalogGo(catalog eventCatalog) string {
	var body strings.Builder
	body.WriteString("// Code generated by module-compose. DO NOT EDIT.\npackage eventcatalog\n\n")
	body.WriteString("type PublishedEvent struct {\n\tType string\n\tNamespace string\n\tSchema string\n\tMajor int\n\tVisibility string\n\tPartition string\n\tRetention string\n}\n\n")
	body.WriteString("type ConsumedEvent struct {\n\tType string\n\tSubscriber string\n\tQueue string\n\tDelivery string\n}\n\n")
	body.WriteString("type FollowableResource struct {\n\tResourceType string\n\tNamespace string\n\tEvents []string\n}\n\n")
	body.WriteString("var published = [...]PublishedEvent{\n")
	for _, entry := range catalog.Publishes {
		fmt.Fprintf(&body, "\t{Type: %q, Namespace: %q, Schema: %q, Major: %d, Visibility: %q, Partition: %q, Retention: %q},\n",
			entry.Type, entry.Namespace, entry.Schema, entry.Major, entry.Visibility, entry.Partition, entry.Retention)
	}
	body.WriteString("}\n\nvar consumed = [...]ConsumedEvent{\n")
	for _, entry := range catalog.Consumes {
		fmt.Fprintf(&body, "\t{Type: %q, Subscriber: %q, Queue: %q, Delivery: %q},\n",
			entry.Type, entry.Subscriber, entry.Queue, entry.Delivery)
	}
	body.WriteString("}\n\nvar followable = [...]FollowableResource{\n")
	for _, entry := range catalog.Follows {
		fmt.Fprintf(&body, "\t{ResourceType: %q, Namespace: %q, Events: []string{", entry.ResourceType, entry.Namespace)
		for index, eventType := range entry.Events {
			if index > 0 {
				body.WriteString(", ")
			}
			fmt.Fprintf(&body, "%q", eventType)
		}
		body.WriteString("}},\n")
	}
	body.WriteString("}\n\nfunc Published() []PublishedEvent {\n\treturn append([]PublishedEvent(nil), published[:]...)\n}\n\nfunc Consumed() []ConsumedEvent {\n\treturn append([]ConsumedEvent(nil), consumed[:]...)\n}\n\nfunc Followable() []FollowableResource {\n\treturn append([]FollowableResource(nil), followable[:]...)\n}\n")
	return body.String()
}

// asyncAPIVersion pins the generated document's info.version. It is a constant
// on purpose: the AsyncAPI projection is a deterministic view of the catalog,
// so it must not couple to a release number that would churn the artifact (and
// the base-integrity manifest) on every unrelated version bump.
const asyncAPIVersion = "1.0.0"

var componentKeyUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

type asyncAPIDoc struct {
	AsyncAPI   string                       `json:"asyncapi"`
	Info       asyncAPIInfo                 `json:"info"`
	Channels   map[string]asyncAPIChannel   `json:"channels"`
	Operations map[string]asyncAPIOperation `json:"operations"`
	Components asyncAPIComponents           `json:"components"`
}

type asyncAPIInfo struct {
	Title       string `json:"title"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type asyncAPIChannel struct {
	Address    string                 `json:"address"`
	Title      string                 `json:"title"`
	Messages   map[string]asyncAPIRef `json:"messages"`
	Visibility string                 `json:"x-visibility"`
	Partition  string                 `json:"x-partition,omitempty"`
	Retention  string                 `json:"x-retention,omitempty"`
	Followable string                 `json:"x-followable-resource,omitempty"`
}

type asyncAPIRef struct {
	Ref string `json:"$ref"`
}

type asyncAPIOperation struct {
	Action  string      `json:"action"`
	Channel asyncAPIRef `json:"channel"`
	Title   string      `json:"title"`
	Summary string      `json:"summary,omitempty"`
}

type asyncAPIComponents struct {
	Messages map[string]asyncAPIMessage `json:"messages"`
	Schemas  map[string]asyncAPISchema  `json:"schemas"`
}

type asyncAPIMessage struct {
	Name    string      `json:"name"`
	Title   string      `json:"title"`
	Payload asyncAPIRef `json:"payload"`
}

type asyncAPISchema struct {
	Type       string                  `json:"type"`
	Properties map[string]asyncAPIProp `json:"properties"`
}

type asyncAPIProp struct {
	Type        string        `json:"type"`
	Format      string        `json:"format,omitempty"`
	Items       *asyncAPIProp `json:"items,omitempty"`
	Description string        `json:"description,omitempty"`
}

// renderAsyncAPI projects the event catalog into an AsyncAPI 3.0.0 document:
// one channel per published type, a `send` operation for its publisher, and a
// `receive` operation for every consumer. All map keys and the sorted catalog
// slices make the output deterministic, so it passes the base-integrity gate.
func renderAsyncAPI(catalog eventCatalog) ([]byte, error) {
	doc := asyncAPIDoc{
		AsyncAPI: "3.0.0",
		Info: asyncAPIInfo{
			Title:       "SaaS Starter Domain Events",
			Version:     asyncAPIVersion,
			Description: "Generated from event-catalog.json by module-compose. DO NOT EDIT.",
		},
		Channels:   map[string]asyncAPIChannel{},
		Operations: map[string]asyncAPIOperation{},
		Components: asyncAPIComponents{
			Messages: map[string]asyncAPIMessage{},
			Schemas:  map[string]asyncAPISchema{},
		},
	}

	// A schema ref is a "<path>#<Message>" string, so sanitizing it collapses
	// runs of "/", "#" and "." into "_" — and unlike an event type, two distinct
	// refs can collapse onto one key (documents/v1/a.proto#M and
	// documents_v1_a_proto#M both become documents_v1_a_proto_M). The winner
	// would then supply the payload schema for both types, silently publishing a
	// contract nobody declared, so the collision is caught rather than assumed
	// away. Keys are tracked by the ref they came from: the same ref reaching the
	// same key is reuse, a different ref reaching it is a conflict.
	schemaKeySource := map[string]string{}
	followable := followableIndex(catalog)
	for _, published := range catalog.Publishes {
		schemaKey := sanitizeComponentKey(published.Schema)
		if source, exists := schemaKeySource[schemaKey]; exists {
			if source != published.Schema {
				return nil, fmt.Errorf("event schemas %q and %q collide on AsyncAPI component key %q", source, published.Schema, schemaKey)
			}
		} else {
			schemaKeySource[schemaKey] = published.Schema
			doc.Components.Schemas[schemaKey] = eventEnvelopeSchema(published.Fields)
		}
		messageKey := sanitizeComponentKey(published.Type)
		doc.Components.Messages[messageKey] = asyncAPIMessage{
			Name:    published.Type,
			Title:   published.Type,
			Payload: asyncAPIRef{Ref: "#/components/schemas/" + schemaKey},
		}
		doc.Channels[published.Type] = asyncAPIChannel{
			Address:    published.Type,
			Title:      published.Type,
			Messages:   map[string]asyncAPIRef{"envelope": {Ref: "#/components/messages/" + messageKey}},
			Visibility: published.Visibility,
			Partition:  published.Partition,
			Retention:  published.Retention,
			Followable: followable[published.Type],
		}
		doc.Operations["send:"+published.Type] = asyncAPIOperation{
			Action:  "send",
			Channel: asyncAPIRef{Ref: "#/channels/" + published.Type},
			Title:   published.Namespace + " publishes " + published.Type,
		}
	}

	for _, consumed := range catalog.Consumes {
		key := strings.Join([]string{"receive", consumed.Type, consumed.Subscriber, consumed.Queue}, ":")
		doc.Operations[key] = asyncAPIOperation{
			Action:  "receive",
			Channel: asyncAPIRef{Ref: "#/channels/" + consumed.Type},
			Title:   consumed.Subscriber + " consumes " + consumed.Type,
			Summary: "queue " + consumed.Queue + ", delivery " + consumed.Delivery,
		}
	}

	return marshalJSON(doc)
}

// eventEnvelopeSchema turns the catalog's resolved proto fields into a JSON
// Schema object. Field order is irrelevant (properties is a keyed object), so
// the map keeps the output deterministic.
func eventEnvelopeSchema(fields []eventField) asyncAPISchema {
	schema := asyncAPISchema{Type: "object", Properties: map[string]asyncAPIProp{}}
	for _, field := range fields {
		schema.Properties[field.Name] = protoTypeToJSONSchema(field.Type)
	}
	return schema
}

func protoTypeToJSONSchema(protoType string) asyncAPIProp {
	if inner, ok := strings.CutPrefix(protoType, "repeated "); ok {
		item := protoTypeToJSONSchema(inner)
		return asyncAPIProp{Type: "array", Items: &item}
	}
	switch protoType {
	case "string":
		return asyncAPIProp{Type: "string"}
	case "bytes":
		return asyncAPIProp{Type: "string", Format: "byte"}
	case "bool":
		return asyncAPIProp{Type: "boolean"}
	case "double", "float":
		return asyncAPIProp{Type: "number"}
	case "int32", "int64", "uint32", "uint64", "sint32", "sint64",
		"fixed32", "fixed64", "sfixed32", "sfixed64":
		return asyncAPIProp{Type: "integer"}
	case "google.protobuf.Timestamp":
		return asyncAPIProp{Type: "string", Format: "date-time"}
	default:
		// A nested message or map<…> field: keep the proto type as a hint.
		return asyncAPIProp{Type: "object", Description: protoType}
	}
}

// sanitizeComponentKey maps a catalog identifier (an event type or a
// "<path>#<Message>" schema ref) to a valid AsyncAPI component key
// (^[A-Za-z0-9._-]+$). Event types cannot collide: they are already unique and
// their grammar admits no unsafe character, so sanitizing is the identity. A
// schema ref can collide, because "/" and "#" both map to "_"; renderAsyncAPI
// detects that rather than relying on this function to prevent it.
func sanitizeComponentKey(id string) string {
	return componentKeyUnsafe.ReplaceAllString(id, "_")
}

// renderEventDocs emits the human-facing communication page: every published
// type with its publisher, schema, and the list of consumers. The catalog
// slices are pre-sorted, so the Markdown is deterministic.
func renderEventDocs(catalog eventCatalog) []byte {
	consumersByType := map[string][]eventCatalogConsume{}
	for _, consumed := range catalog.Consumes {
		consumersByType[consumed.Type] = append(consumersByType[consumed.Type], consumed)
	}
	followable := followableIndex(catalog)

	var body strings.Builder
	body.WriteString("# Event communication\n\n")
	body.WriteString("_Generated from `event-catalog.json` by module-compose. DO NOT EDIT._\n\n")
	body.WriteString("Every domain event type, who publishes it, and who consumes it. ")
	body.WriteString("The machine-readable projection is [`asyncapi.json`](./asyncapi.json).\n")

	if len(catalog.Publishes) == 0 {
		body.WriteString("\n_No event types are registered._\n")
		return []byte(body.String())
	}

	for _, published := range catalog.Publishes {
		fmt.Fprintf(&body, "\n## %s\n\n", published.Type)
		fmt.Fprintf(&body, "- **Publisher:** %s\n", published.Namespace)
		fmt.Fprintf(&body, "- **Visibility:** %s\n", published.Visibility)
		fmt.Fprintf(&body, "- **Schema:** `%s` (major v%d)\n", published.Schema, published.Major)
		if published.Partition != "" {
			fmt.Fprintf(&body, "- **Partition:** `%s`\n", published.Partition)
		}
		if published.Retention != "" {
			fmt.Fprintf(&body, "- **Retention:** %s\n", published.Retention)
		}
		if resourceType := followable[published.Type]; resourceType != "" {
			fmt.Fprintf(&body, "- **Follows:** `%s` (target is the envelope subject)\n", resourceType)
		}
		consumers := consumersByType[published.Type]
		if len(consumers) == 0 {
			body.WriteString("- **Consumers:** _none_\n")
			continue
		}
		body.WriteString("- **Consumers:**\n")
		for _, consumed := range consumers {
			fmt.Fprintf(&body, "  - %s (queue `%s`, delivery %s)\n", consumed.Subscriber, consumed.Queue, consumed.Delivery)
		}
	}

	return []byte(body.String())
}
