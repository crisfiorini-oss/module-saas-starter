package eventcatalog

import "strings"

// PlatformAuditNamespace is reserved for audit events delivered only to tenant-owned webhooks.
const PlatformAuditNamespace = "saas"

// Namespace returns the leading dotted segment of an event type — the namespace
// a producer must own to publish it. "reference.console.viewed" → "reference".
// A type with no dot is its own namespace; an empty type yields "".
func Namespace(eventType string) string {
	namespace, _, _ := strings.Cut(eventType, ".")
	return namespace
}

// publishedIndex resolves an event type to its declared published contract. It
// is built once over the compose-generated table; the table is small (one entry
// per published event across the composed solutions) so an exact-match map is
// sufficient — pattern matching against it is the caller's job.
var publishedIndex = func() map[string]PublishedEvent {
	m := make(map[string]PublishedEvent, len(published))
	for _, e := range published {
		m[e.Type] = e
	}
	return m
}()

// LookupPublished returns the declared contract for a published event type and
// whether the type is declared in the composed catalog at all.
func LookupPublished(eventType string) (PublishedEvent, bool) {
	e, ok := publishedIndex[eventType]
	return e, ok
}

// followableIndex resolves an event type to the followable resource it reports a
// change to. Compose keeps the mapping single-valued — an event may be declared
// followable by at most one resource type — so this is a function rather than a
// multimap, which is what lets a follow be matched on one (resource_type,
// subject) pair.
var followableIndex = func() map[string]FollowableResource {
	m := make(map[string]FollowableResource, len(followable))
	for _, f := range followable {
		for _, eventType := range f.Events {
			m[eventType] = f
		}
	}
	return m
}()

// LookupFollowable returns the followable resource an event type reports a change
// to, and whether the type is declared followable at all. The target instance is
// the envelope subject: the host matches a follow on (ResourceType, subject) and
// never decodes the payload, so a declared followable event carries no usable
// target without one — which is why an empty subject is refused at publish time
// rather than silently matching no follower.
func LookupFollowable(eventType string) (FollowableResource, bool) {
	f, ok := followableIndex[eventType]
	return f, ok
}

// IsInternalPublished reports whether the event type is a published type declared
// with internal visibility — an intra-platform event that must never be delivered
// to a subscriber principal. A type absent from the catalog is not internal (only
// an explicit internal declaration suppresses delivery). The relay consults this
// at fan-out time so an internal event is refused delivery even to a subscription
// that predates the type's registration, which the subscribe-time gate over
// InternalPublishedTypes cannot retract.
func IsInternalPublished(eventType string) bool {
	e, ok := publishedIndex[eventType]
	return ok && e.Visibility == "internal"
}

// IsExternalPublished reports whether the event type is declared with external
// visibility — the only kind an outbound webhook may carry. A type absent from
// the catalog is not external: eligibility is granted by declaration, never by
// omission, so an unregistered type is never delivered outside the platform.
func IsExternalPublished(eventType string) bool {
	e, ok := publishedIndex[eventType]
	return ok && e.Visibility == "external"
}

// InternalPublishedTypes returns the types of every published event declared
// with internal visibility. The Subscribe authority gate rejects a solution
// principal whose type pattern would match any of these, so an internal event
// is never delivered to a tenant-scoped subscriber. The list is small; callers
// match their pattern against it directly.
func InternalPublishedTypes() []string {
	var out []string
	for _, e := range published {
		if e.Visibility == "internal" {
			out = append(out, e.Type)
		}
	}
	return out
}

// UnorderedPublishedTypes returns the types of every published event that
// declares no partition. Such a type has no ordering domain at all, so an
// ordered subscription to it cannot be honoured: the relay orders a delivery
// only when the event carries a partition key, and silently treats the rest as
// unordered. The Subscribe authority gate consults this so a subscriber is told
// at subscribe time, rather than discovering reordered deliveries in production.
// The list is small; callers match their pattern against it directly.
func UnorderedPublishedTypes() []string {
	var out []string
	for _, e := range published {
		if e.Partition == "" {
			out = append(out, e.Type)
		}
	}
	return out
}

// UnorderedPublishedTypesInNamespace is UnorderedPublishedTypes confined to one
// namespace. A subscription pattern is either an exact type or a single trailing
// ".*", so every type it can match shares its leading segment — scanning the rest
// can only ever fail to match. The distinction matters because the platform
// namespace alone contributes one unordered type per registered audit event, and
// that set grows with the registry.
func UnorderedPublishedTypesInNamespace(namespace string) []string {
	var out []string
	for _, e := range published {
		if e.Partition == "" && Namespace(e.Type) == namespace {
			out = append(out, e.Type)
		}
	}
	return out
}

// ResolvePartition substitutes one envelope's scope fields into the partition
// template a published event declares ("{tenant_id}", "{tenant_id}/{boundary_id}").
// An empty template is a type that declares no ordering domain and resolves to
// the empty key.
//
// The empty key is load-bearing, not a fallback: publish_domain_event takes a
// transaction-scoped advisory lock on any non-empty partition, held until the
// producing transaction commits, so inventing a partition an event never
// declared serializes every publish sharing it for an ordering nobody consumes.
// Callers resolve against a declaration they looked up, so that a type missing
// from the catalog is a decision the caller makes explicitly rather than a
// silent slide into "unordered" — see LookupPublished.
//
// Templates are validated at compose time: every placeholder names a field this
// substitutes, and every non-empty template carries {tenant_id}, so a resolved
// key is always scoped to one tenant.
func ResolvePartition(template, tenantID, boundaryID string) string {
	if template == "" {
		return ""
	}
	return strings.NewReplacer("{tenant_id}", tenantID, "{boundary_id}", boundaryID).Replace(template)
}
