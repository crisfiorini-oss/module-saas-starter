# Authorization — scope nodes, kinds, and data boundaries

This is the prose companion to the generated [`AUTHZ_MATRIX.md`](./AUTHZ_MATRIX.md)
(the RPC → policy projection). It records the conventions the generated
artifacts cannot: what the scope tree's node **kinds** mean, and how data below
the tenant is named and bound.

## The scope tree (RFC-0001 / ADR-0002)

`scope_nodes` (migration 98) is the org's hierarchical scope registry: one
row per node, a dotted `ltree` path per org, `kind` and `label` as free text,
and — for a **placed record** — a `(resource_type, resource_id)` pair that binds
the node to a real product row. Grants (`scope_grants`) attach a role to a
subject at a node and inherit to the whole subtree; per-record shares
(`record_shares`) attach a role to a subject on a single placed record.

`kind` is stored verbatim and the enforcement path never branches on it — the
authorization decision reads only paths, grants, shares, and role permissions.
Kinds are therefore **conventions for humans and tooling**, not an enforced
enum.

## Who may place a record

The access oracles resolve a record's scope from its own node, so a record is
reachable only once it is **placed** — registered with its `(resource_type,
resource_id)`. Two callers may place one, under different bounds:

| Caller | RPC | Bound |
| ------ | --- | ----- |
| Org administrator | `PermissionService.RegisterScopeNode` | the caller's tenant; any resource type |
| Composed module | `ModuleCapabilitiesService.PlaceRecord` | its bound tenant, and only the resource types its own principal grant declares |

The module bound is the `resources` list of `MODULE_PRINCIPALS` — the same
declaration that says which content this host will authorize reads of, so a
module's placement authority and its read authority cannot drift apart. A module
that declares no resources places nothing: the surface fails closed on an absent
composition rather than inventing an authority for it.

Placement is idempotent on the record — re-placing it at the same path returns
the same node, which is what the module surface's at-least-once contract needs.
Re-pointing it at a **different** path is refused. A record resolves through
exactly one node, so moving it rewrites who can reach it; that is an
authorization change, and no surface performs it today.

## Data boundary = scope node

The data boundary *below the tenant* is not a new container table; it is a scope
node. Two kinds carry a reserved meaning (constants
`business.ScopeNodeKind{Solution,Collection}`):

| Kind         | Meaning |
| ------------ | ------- |
| `solution`   | One node per solution install, a child of the org root. |
| `collection` | A data container a solution creates under its solution node — the **data boundary** that content (datasources, documents) is bound to and that grants are placed against. |

Everything else stays product-defined (`space`, `customer`, `record`, …).

Because a boundary is an ordinary scope node, "share this collection with team
B" is an ordinary `GrantScope(team B, <collection path>, role)` — the boundary
is grantable, which a free-text collection string never was.

### Datasources bind to a boundary

`datasource_sources.boundary_node_id` (migration 111) references the
`collection` node a source's pulled Entries land in, replacing the old free-text
`target_collection`. `AddSource` / `AddGitHubSource` take either an existing
`boundary_node_id` or a `collection_label` that mints a new `collection` node.
Every ingest job carries that node id as the `datasource.boundary_id` attribute;
a source with no resolvable boundary is rejected at enqueue, so nothing
downstream ever writes into an unnamed, ungrantable boundary.

Until installation identity (#474) lands there is no org-root/solution node to
parent under, so a minted `collection` node is registered as a **root**; it will
be reparented under the org's solution node when that identity exists.

Who *triggered* a source's sync is not a datasource field. `ListSources` and
`GetSource` project `Datasource` to any org member under no declared permission,
while `SyncSource` is org-admin only and reading its actor goes through
`QueryAuditLog`'s `audit:read` gate — so a `last_synced_by` column would route
audit-classified provenance around that gate, and would flatten the impersonation
chain the audit row keeps. The audit trail is the record; see
[ADR 0008](../../docs/adr/0008-datasource-sync-actor-provenance.md).

## Listing what a subject may see

`PermissionService.ListAccessibleScopes(subject, kind, resource_type, action)`
(`EXPOSURE_INTERNAL`) is the Zanzibar "ListObjects" companion to `CheckAccess`:
it returns the scope nodes a subject may act on, so a module can pre-filter
`boundary_id IN (…)` before loading content. It resolves through the same
grant + share union as `CheckAccess` — a node is returned exactly when
`CheckAccess` would allow the same `(resource_type, action)` on it — so the two
never disagree.

## Deferred

Boundary-level RLS inside module stores (an `app.current_boundaries` GUC) stays
deferred (RFC-0001 resolution 2); the org remains the RLS floor.
