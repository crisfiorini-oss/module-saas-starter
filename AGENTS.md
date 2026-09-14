# AGENTS.md

Orientation for anyone — human or agent — working in this repository. It links
to the authoritative docs rather than restating them; when this file and a
linked doc disagree, the linked doc wins.

## What this repo is

`saas-starter` is a Codefly **module**: a multi-tenant SaaS backend
(three-layer authorization, Postgres RLS, RBAC, impersonation, audit), an
authenticated Next.js product, a separately deployable marketing site, and the
supporting cache/store/vault/telemetry services. It is published as an
immutable module package that downstream workspaces **compose** (never fork).

- Architecture, service graph, and capability ownership: [MODULE.md](./MODULE.md)
- Feature inventory: [module/FEATURES.md](./module/FEATURES.md)
- First-run walkthrough: [module/GETTING_STARTED.md](./module/GETTING_STARTED.md)

## Naming and confidentiality

Everything in this repository — issues, PRs, docs, specs, code, comments, tests,
fixtures, commit messages — must use **only generic placeholder names** for any
company, product, person, team, or dataset: `Acme`, `ExampleCorp`, `Example
Solution`, `Jane Doe`, `user@example.com`, and the like. Never write the name of
a real customer, partner, employer, or downstream consumer of this module, and
never describe the module as a dependency of any specific named product.

This is a hard boundary, not a style preference. This module sits **below** its
consumers in the dependency graph: consumers depend on it, never the reverse, so
it must carry no build-time or documentation-level knowledge of who consumes it.
Describe any consumer generically — "a consuming solution", "the downstream
product", "the agent runtime". Capabilities belong here in their **generic**
form (RBAC, delegation, Work Contexts, permission enforcement, audit) so every
consumer reuses them; consumer-specific wiring stays in the consumer's own repo.
The rule holds for public **and** private files alike, and for records as much
as for files: a pull request's title, its body and its commit messages are
checked in CI before it can merge (see [Building, testing, and
CI](#building-testing-and-ci)). Prevention is the whole of the remedy there — a
published record cannot be retracted, because GitHub keeps prior revisions of an
edited body and a commit message cannot be changed without rewriting history.

## Boundaries — non-negotiable

This repo is a **module** — the **host**, the root every other module composes
into. Its whole responsibility is one sentence: the first paragraph of its
handbook page, `modules/saas-starter.md` in the handbook of the workspace that
composes this host. Read that page before changing anything here. If the
change would make that sentence need another clause, the change does not
belong in this repo.

- **Owns:** identity, tenancy, permissions, jobs, audit, approvals,
  notifications, data sources, and the product surfaces.
- **Never contains:** domain content of any kind — documents, rows, models,
  agents and deals are the other modules'; a flag never grants an entitlement,
  raises a quota, or replaces authorisation.
- **Depends on:** nothing from other modules. It is the root of the
  composition.

The rules, governed by the handbook's `concepts/boundaries.md`:

1. **Dependencies go one way**: solution → module → service, with the host
   beneath every module. Never import, read the tables of, or hard-code the
   internals of another module. Cross a module boundary only through the four
   seam contracts (Ref, journal, host ports, provenance).
2. **Nothing here names what sits above it.** A service never names a module,
   a tenant or a permission. A module never names a solution, a customer or a
   business line. If the task needs that word, stop: the thing belongs above,
   through an extension point.
3. **One consumer's need is not a feature of this repo.** Ship it in the
   consumer through the extension point; if no extension point exists, open a
   handbook track. Do not add a special case here, however small, however
   temporary.
4. **The boundary test in CI is part of the definition of done.** Never
   weaken, skip, or allowlist past it to land a change.
5. **If you cannot finish without breaking one of these, stop and say so.**
   Half-done inside the boundary beats done across it.

The test is `scripts/check-boundaries.sh` (denylist in
`scripts/boundaries.denylist`, baseline in `scripts/boundaries.baseline`),
run by `.github/workflows/boundaries.yml`. It is additive to the naming gate,
the SDK-boundary job and the boundary tests this repo already runs. The
baseline shrinks and never grows: clean a file, delete its line.

## Repository layout

- `module/` — the canonical module source that ships to consumers. **This is
  the tree the base-integrity tooling and CI run against.**
- `modules/saas-starter` — a symlink to `module/` (the workspace-composed view
  Codefly expects under `modules/<name>/`).
- `module/deployment/topology.bindings.codefly.yaml` — **the source of truth**
  for the service graph and the agent version each service pins.
- `module/services/<svc>/service.codefly.yaml` — **generated** from the
  bindings file. The header says `DO NOT EDIT`; edit the bindings source and
  regenerate instead (see below).
- `main.go` / `gitops.go` — this repo is itself the `saas-starter` **module
  agent** binary; composing the module runs this code to regenerate the
  per-service manifests.
- `agent.codefly.yaml` — the module's own name, publisher, and **release
  version**.

## Running the starter locally

Boots the whole dependency graph (vault → store → cache → telemetry → accounts
→ auth-gateway → frontend, plus marketing) with a fake-auth fixture:

```bash
codefly run service --fixture dev-admin
```

- Agents resolve from their published GitHub releases by default; add
  `--local-agents` to resolve only from `~/.codefly/agents/` (offline / local
  agent builds).
- No TTY (CI, pipes, MCP) auto-enables `--headless`.
- Docker must be running; `codefly doctor` checks prerequisites and
  `codefly clear` reaps stray processes/containers between runs.

For a real external identity provider (WorkOS) and the production-grade
provider stack (Stripe, Resend, PostHog, Sentry, OTEL, Turnstile), use the
`local-dogfood` environment and the setup scripts:

- Runnable local product: [LOCAL_DOGFOODING.md](./LOCAL_DOGFOODING.md)
- Feature-by-feature dogfood checklist: [DOGFOODING.md](./DOGFOODING.md)
- Provider bootstrap scripts: [scripts/setup/README.md](./scripts/setup/README.md)

## Solutions composed on top (runtime registry)

A **solution** is an independently deployed module the host has no build-time
knowledge of. Solutions self-register with this host at runtime — as a
Module-Federation remote in the frontend and as an upstream in the gateway — so
the host learns to render and proxy them with no rebuild. Nothing in the module
names a specific solution; the seam is generic.

Both halves are **one durable record**, not two process-local maps.
`solution_registrations` in the store (accounts owns it, migration
`126_solution_registrations`) holds the solution identity, its publisher, the
frontend and backend halves, a registry-wide `revision`, and a per-half lease.
A registration therefore survives a restart, reaches every replica, and is only
served when it is *whole*: a solution that registered its page but not its
backend is a durable `pending` record and is deliberately absent from the
navigation. Writes are compare-and-swap on the revision, so a stale publisher
cannot overwrite newer state, and a deregistration leaves a **tombstone** that a
retiring deployment's delayed heartbeat cannot resurrect. accounts serves this
as `SolutionRegistryService` on the internal listener; the auth-gateway is its
only client and brokers the frontend's half, exactly as it brokers module
registration. Both surfaces hold a short-lived cache rebuilt from that snapshot,
so convergence after any write is bounded (gateway ~10s reconcile plus an
on-demand refresh on a cache miss; frontend a 5s snapshot TTL).

- **Frontend registration** — `POST /api/solutions/register` (and `DELETE
  ?id=…`) at
  `module/services/frontend/code/src/app/api/solutions/register/route.ts`. The
  POST body is the solution manifest (`id`, `nav`, `frontend.manifestUrl` +
  `exposedModule`, optional `backend.serviceAlias`, optional compatibility
  requirements), validated in `src/solutions/registry.ts`, which then writes the
  frontend half through the gateway (`POST /solutions/_frontend`). The route
  relays the registry's own answer: `409` for a revision conflict, `403` when
  the id belongs to another publisher, `503` when the registry cannot be
  reached — a registrant is never told it is serving when it is not.
  Re-registering a deregistered solution requires an explicit
  `reactivate: true`. `GET` on that route is unauthenticated and returns exactly
  the public navigation projection — `{id, nav}` per solution and nothing
  else — which is what the sidebar polls, answering `503` (never an empty list)
  when this replica cannot read the registry. Everything else a manifest carries
  (`frontend`, `backend`) is deployment topology and is served instead by `GET
  /api/internal/solutions`
  (`src/app/api/internal/solutions/route.ts`), gated on the cluster-internal
  token. The dashboard graph is on neither: the solution page reads it
  in-process through `findSolution`.
- **Gateway upstream registration** — `POST /solutions/_register` on the
  auth-gateway (`module/services/auth-gateway/code/gateway_solutions.go`), with
  a `{id, upstream}` JSON payload (the gateway supplies the compare-and-swap
  revision it last saw). `GET /solutions/_registry` returns this replica's
  snapshot — id, publisher, revision, and status (`active` / `pending` /
  `expired` / `incompatible` / `tombstoned`), never an upstream — which is both
  what the frontend rebuilds from and what an operator reads to tell those
  states apart. The gateway then proxies `/solutions/{id}/…`
  to the registered upstream, running the same ext_authz Check and
  identity-header discipline as catalog routes; only the public `/assets` and
  `/.well-known` sub-paths are served unauthenticated (GET/HEAD).
- **Both halves take the same owner-bound credential.** Neither is gated on the
  shared cluster-internal token: the caller presents a signed, solution-bound
  registration token in `X-Codefly-Solution-Registration`, obtained from `POST
  /solutions/_registration-token` against the solution's own secret
  (`SOLUTION_REGISTRATION_SECRETS` in the `federation` group, declared
  separately from the module secrets). The credential names one solution id and
  one publisher, so a holder can neither claim nor re-point another solution.
  The frontend additionally enforces the declared runtime compatibility
  requirements before activating a remote. A solution remote executes in the
  host origin with the viewer's credentials — the trust model, the full
  authority contract, and the registration/installation/entitlement boundary are
  in [module/SOLUTION_REGISTRATION.md](./module/SOLUTION_REGISTRATION.md).
- **Composed-module REST federation** — a composed module that serves its own
  `/v1/<module>/*` surface registers it with `POST /modules/_register`
  (`gateway_modules.go`), and the gateway proxies that prefix once the generated
  catalog has no match. Unlike solution registration this is **not** gated on
  the shared internal token: the caller must present a signed, prefix-bound
  registration token in `X-Codefly-Module-Registration`, so a module holding the
  credential for `documents` cannot claim `billing`. The handshake is three
  calls:
  1. `POST /modules/_registration-token` on the auth-gateway, with the
     cluster-internal token in `X-Codefly-Internal-Token` **and** the module's
     own registration secret in `X-Codefly-Module-Secret`, body `{prefix}`.
  2. The gateway brokers to accounts over the internal listener
     (`ModuleCapabilitiesService/MintModuleRegistration`, EXPOSURE_INTERNAL, so
     the generated mesh policy admits the gateway's service account and denies
     everyone else). accounts compares the secret against the digest declared for
     that prefix in the `federation` configuration group's
     `MODULE_REGISTRATION_SECRETS` and, on a match, mints a 5-minute Ed25519
     token (`aud=module-registration`, `sub=module:<prefix>`) with the key the
     gateway already trusts through JWKS, emitting a
     `module.registration_minted` audit event. Unset means no module may
     federate.
  3. `POST /modules/_register` with that token and `{prefix, upstream}`.

  Composition provisions the pair: the SHA-256 digest into this host's
  `federation` group, the plaintext into the module. The token is short-lived and
  fetched per registration attempt, not cached across a gateway restart. Registration only adds a proxy target —
  every proxied `/v1/<module>/*` request still runs the full ext_authz check.
- **Composed-module service principal** — a module consuming the module-facing
  capability surface (`ModuleCapabilitiesService`: job enqueue/claim, notify,
  approvals, audit, events) calls it as its own **service principal**, whose id is
  derived from the same registration prefix (`business.ModulePrincipalID`), so
  nothing is hand-authored as an opaque id. Its authority is declared in the
  `module-capabilities` group's `MODULE_PRINCIPALS`, a JSON map keyed by that
  prefix: `queues` (enqueue and claim), `namespaces` (event publish), `tenant`
  (the org it is bound to), `cross_tenant` (an inbox worker serving every
  tenant). Unset means no module may call the surface.

  The identity itself is a **Work Context**, obtained with a second exchange that
  mirrors the registration one: `POST /modules/_work-context` on the auth-gateway
  with the cluster-internal token and the module's identity secret, body
  `{prefix}`. The gateway brokers to accounts
  (`ModuleCapabilitiesService/MintModuleWorkContext`, EXPOSURE_INTERNAL), which
  authorizes the secret against the independent `MODULE_IDENTITY_SECRETS` digest,
  refuses a prefix that is not a declared module principal, and mints a
  capability owned and actored by the module principal
  (`aud=module-capabilities`), emitting a `module.work_context_minted` audit
  event once the capability exists. The response carries
  `{token, expiresAt, principalId, tenant}`.

  An empty or absent `MODULE_IDENTITY_SECRETS` denies every module identity
  exchange. Compositions must provision identity digests and distribute their
  matching secrets before modules can obtain Work Contexts; registration
  credentials never substitute for missing identity digests.

  The tenant is **not requestable** — it is the one `MODULE_PRINCIPALS` declares
  for that principal, so a module cannot name a tenant by asking. The capability
  seals identity and tenant only: what the principal may do is re-read from the
  declared grant on every call, so narrowing a grant takes effect immediately
  rather than when the outstanding token expires.

  The module presents that token in `x-codefly-work-context` on every capability
  call; accounts takes the calling principal and its bound tenant from the
  verified token, never from request metadata. Work Contexts cap at 15 minutes, so
  a long-running worker re-runs the exchange rather than holding one open.

  **Mesh reachability is the composition's to grant.** The generated
  `AuthorizationPolicy` allowlists accounts' internal surface to the service
  accounts of services that *declare a dependency on accounts* in the workspace
  topology. This module's own topology names no composed module (it must carry no
  build-time knowledge of its consumers), so a composed module reaches the
  capability surface in a mesh-enforced deployment only when its own workspace
  declares that dependency and regenerates the policy. A valid Work Context does
  not substitute for it: mTLS refuses the call before any token is read.
- **Host page** — `/s/[solutionId]`
  (`src/app/(dashboard)/s/[solutionId]/page.tsx`) loads the remote via
  `SolutionOutlet` from the registered `manifestUrl` + `exposedModule`, read
  in-process from the registry. `src/proxy.ts` cannot read that registry (Next
  runs the proxy in a context that shares no module singletons with route
  handlers), so it asks the internal detail lookup over loopback with the
  cluster-internal token, and adds every registered manifest origin to the CSP
  of every signed-in document — so a freshly registered cross-origin remote
  loads with no rebuild, including after a client-side navigation. Without that
  token the policy stays self-only and says so in the log.

To run a solution against this host locally, drive it from the **solution's own**
codefly workspace, which composes this repo as a module by path (`codefly add
module --source <this-repo>/module`). Composition provisions this host's
`configurations/local/*` groups — `legal`, `identity`, `internal-auth` (token
included), and the rest — into the solution workspace automatically, so the
solution need not hand-author them; it overrides any group only by declaring one
of the same name. Then `codefly run service --fixture dev-admin` from the
solution root boots this whole host underneath; a well-behaved solution runtime
self-registers with both the host and the gateway autonomously via the codefly
SDK. See the solution repo for its own instructions.

## Building, testing, and CI

- Canonical **service** gate: `codefly ci run`. It owns lint,
  compile/typecheck, tests, dependency/vuln audit, SBOM, and container build for
  every service in the graph. See [RELEASE_GATES.md](./RELEASE_GATES.md).
- Beside it, CI runs nine repository-specific gates that no service owns —
  base-file integrity (below), authorization coverage, the release-gate
  contract, interface docs and story tests, the published frontend kit's
  version, provider shims, marketing isolation, the SDK boundary, and the
  immutable module package. They are listed with what each runs in
  [RELEASE_GATES.md § Repository-specific
  gates](./RELEASE_GATES.md#repository-specific-gates), which
  `release-gates.test.mjs` holds to the enforced set.
- Inside the `base-integrity` job, five more checks run as steps rather than as
  gates of their own: tenant RLS coverage, migration up/down pairing, pinned
  plugin versions on generated Go, generic placeholder names across the tree,
  and the same names in the pull request's title, body and commit messages. The
  last two enforce §"Naming and confidentiality" above — the first over every
  file's contents and path, the second over the records around them:

  ```bash
  node module/tools/naming-gate.mjs check     # the tree
  git config core.hooksPath scripts/hooks     # opt in: reject a bad commit message locally
  ```

  The record check names only the matching mode, never the term, because its log
  is public. A pushed message can no longer be edited, so fix a failure by
  amending or rebasing rather than by adding a commit on top.
- Go checks: this repository holds **six independent Go modules** — the root
  module, `module/tools`, and one per Go service (`accounts`, `auth-gateway`,
  `store`, `telemetry`) — and there is no `go.work`, so `go test ./...` covers
  only the module you run it in. From the root that is the module agent, the
  host, and the generated reference composition; every service's own module is
  outside it, because each has its own `go.mod`. To exercise a service, run its
  suite from its own directory (its DB-backed suites need Codefly and Docker),
  or let `codefly ci run` do it.
- Vulnerability policy: the complete audit runs non-blocking
  (`--fail-on-vuln=false`) so vendor-image findings stay in the evidence report,
  and a separate fail-closed step enforces first-party services and production
  frontend dependencies. Details and the exact commands are in
  [RELEASE_GATES.md § Vulnerability policy](./RELEASE_GATES.md#vulnerability-policy-and-its-one-exemption).
- Publication of any artifact additionally requires the aggregate
  `release-gates` job to have seen every mandatory gate actually succeed, plus
  three release-only secrets. See [RELEASE_GATES.md §
  Publication gating](./RELEASE_GATES.md#publication-gating).

## Agent version pins

Each service pins the version of its Codefly service agent (`go-grpc`,
`nextjs`, `redis`, `postgres`, `vault`). To see what is pinned and whether a
newer release exists:

```bash
codefly agent list        # PINNED vs LATEST-RESOLVABLE, resolvability, how far behind
codefly agent versions <agent>
```

To change a pin, **edit the version in
`module/deployment/topology.bindings.codefly.yaml`** (the source), then
regenerate the per-service manifests and refresh the base manifest. Do not
hand-edit `service.codefly.yaml` — it is generated. `codefly update workspace`
does **not** rewrite the bindings for this repo (it skips the generated
manifests by design), so the bindings edit is manual.

Latest is not always safe: verify the newer agent actually boots the graph
(`codefly run service`) before pinning it. Agent releases can carry breaking
changes to service manifests.

## Base-file integrity manifest — the easy gate to trip

`module/tools/base-manifest.json` hashes every base file. Editing a tracked
base file (including `topology.bindings.codefly.yaml`) without refreshing the
manifest fails two CI checks ("Base manifest integrity" and "Codefly CI").
Regenerate it **from a clean checkout**, because `gen`'s tree walk otherwise
hashes gitignored harness artifacts CI never sees:

```bash
git worktree add --detach /tmp/bm-clean HEAD
cd /tmp/bm-clean/module && node tools/base-integrity.mjs gen && node tools/base-integrity.mjs verify
# copy module/tools/base-manifest.json back, confirm the diff is only your files, commit
git worktree remove /tmp/bm-clean --force
```

## How pull requests land

`main` merges through a **GitHub merge queue**, not by pressing Merge. The queue
builds each entry as `main + the pull request` and runs the required checks
against that merged ref, so a pull request never has to be rebased merely because
`main` moved — "require branches to be up to date" is deliberately off, since
with a queue it re-imposes the rebase race it was meant to replace.

Two consequences worth knowing before you lose time to them:

- **Verify queue membership after requesting a merge.** `gh 2.100.0` documents
  that `gh pr merge` enqueues when required checks have passed and enables
  auto-merge otherwise. A successful exit alone does not establish that the PR
  is queued or merged. Set `PR_NUMBER` to the pull request number and inspect
  its state:

  ```bash
  PR_NUMBER=626 # replace with the pull request number
  gh api graphql -f query='query($number:Int!){repository(owner:"codefly-dev",name:"module-saas-starter")
    {pullRequest(number:$number){id state autoMergeRequest{enabledAt} mergeQueueEntry{position state}}}}' \
    -F number="$PR_NUMBER" --jq '.data.repository.pullRequest'
  ```

  `state: MERGED` confirms completion; a non-null `mergeQueueEntry` confirms
  queue membership. An `autoMergeRequest` alone confirms neither. If the PR
  is open, eligible, and has no queue entry, explicitly request enqueue using
  its id (this can fail if requirements are unmet), then repeat the lookup:

  ```bash
  PRID=$(gh api graphql -f query='query($number:Int!){repository(owner:"codefly-dev",name:"module-saas-starter")
    {pullRequest(number:$number){id}}}' -F number="$PR_NUMBER" \
    --jq '.data.repository.pullRequest.id') &&
  gh api graphql -f query='mutation($id:ID!){enqueuePullRequest(input:{pullRequestId:$id})
    {mergeQueueEntry{position state}}}' -f id="$PRID"
  ```

- **Every required check must run on `merge_group`.** A required context that
  never reports leaves its entry queued until the queue evicts it, and entries
  merge in order, so one missing context stalls every merge in the repository —
  and no pull request run shows it, because the same job is green there. The
  `release-contract` gate checks publication dependencies and action pins; it
  does **not** enforce merge-queue trigger coverage or compare required check
  names with the live ruleset. Whenever workflows or required checks change,
  read the effective required contexts:

  ```bash
  gh api repos/codefly-dev/module-saas-starter/rules/branches/main \
    --jq '.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[].context'
  ```

  Compare each context with the reporting job's `name` (or job id when unnamed)
  in `.github/workflows/`, including any matrix-expanded name. Check that its
  workflow subscribes to `merge_group` and that job conditions and dependencies
  permit it to report on that event. Confirm those contexts actually report on
  the queue entry's merged commit; a green PR run or `release-contract` alone
  cannot establish this. See [RELEASE_GATES.md § The contract
  test](./RELEASE_GATES.md#the-contract-test) for the existing guard's scope.

## Cutting a release

Two tag tracks live here on separate version axes (see
[RELEASE_GATES.md](./RELEASE_GATES.md) for the recipes):

- The **deploy counter** — the `v0.0.N` tag series consumers adopt via
  `codefly sync module`. The counter advances per release; it is not derived
  from `agent.codefly.yaml`'s `version:` (that field carries the module agent's
  own version and can lag the tags).
- The **immutable module package** — a `version:` bump on
  `module/module.package.codefly.yaml` and a `module-package/vX.Y.Z` tag. Only
  this track triggers the immutable module-package publication job (strict
  manifest validation, SBOM, provenance signing).

## Doc index

Deep references live under `module/` — authorization
([module/AUTHORIZATION_CATALOG.md](./module/AUTHORIZATION_CATALOG.md),
[AUTHZ.md](./AUTHZ.md), the authority-checking epic scoping record
[AUTHORITY_CHECKING_PLAN.md](./AUTHORITY_CHECKING_PLAN.md)), database/RLS
([module/DATABASE_AUTHORITY.md](./module/DATABASE_AUTHORITY.md)), the approval
primitive design ([APPROVALS_DESIGN.md](./APPROVALS_DESIGN.md)), the per-org
non-human Principal registration decision for delegated Work Context flows
([DELEGATION_PRINCIPAL_DESIGN.md](./DELEGATION_PRINCIPAL_DESIGN.md)), the dashboard
authoring API design decisions
([DASHBOARD_AUTHORING_DESIGN.md](./DASHBOARD_AUTHORING_DESIGN.md)), deployment
topology ([module/DEPLOYMENT_TOPOLOGY.md](./module/DEPLOYMENT_TOPOLOGY.md)),
signing-key rotation ([module/KEY_ROTATION.md](./module/KEY_ROTATION.md)),
frontend ([FRONTEND_ARCHITECTURE.md](./FRONTEND_ARCHITECTURE.md),
[module/FRONTEND_PLUGINS.md](./module/FRONTEND_PLUGINS.md)), dynamic dashboards
([DYNAMIC_DASHBOARDS.md](./DYNAMIC_DASHBOARDS.md),
[DASHBOARD_AUTHORING_DESIGN.md](./DASHBOARD_AUTHORING_DESIGN.md)), REST/gateway
([module/REST_SURFACE.md](./module/REST_SURFACE.md),
[module/GATEWAY_ROUTES.md](./module/GATEWAY_ROUTES.md)), email
([EMAIL_PROVIDER_ADAPTERS.md](./EMAIL_PROVIDER_ADAPTERS.md)), supply chain
([SUPPLY_CHAIN_SECURITY.md](./SUPPLY_CHAIN_SECURITY.md)), security review and
hardening ([SECURITY_REVIEW.md](./SECURITY_REVIEW.md)), and production
readiness ([PRODUCTION_READY.md](./PRODUCTION_READY.md)), and a cross-domain
platform-functionality reference mapping an external multi-tenant-platform audit
to what this starter ships, partially ships, or lacks
([PLATFORM_REFERENCE.md](./PLATFORM_REFERENCE.md)). Which claim in those
documents is backed by what, and which are kept only as history, is registered in
[CLAIM_INVENTORY.md](./CLAIM_INVENTORY.md). Start from
[MODULE.md](./MODULE.md), whose "Quick links" section indexes the full set.
