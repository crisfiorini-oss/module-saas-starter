# Release gates

The SaaS Starter has one canonical **service** gate: `codefly ci run`. It owns
every language-, framework- and container-specific command — lint, compile,
tests, dependency and vulnerability audit, SBOM, artifact build — for every
service in the graph, and provider YAML never reimplements any of it. That
ownership is what keeps a consumer's CI and a maintainer's laptop running the
same gate as this repository.

`codefly ci run` is not, however, the whole workflow. Alongside it,
`.github/workflows/ci.yml` runs a set of **repository-specific gates** that
guard artifacts and contracts no single service owns: the canonical base
manifest that seeds every consumer, the authorization catalog, the release
gating graph itself, the interface docs, the published frontend kit's version,
the provider shims, the marketing isolation build, the SDK boundary, and the
immutable module package. They run
`node --test`, `go test`, `buf breaking`, and `npm` commands directly — see
[Repository-specific gates](#repository-specific-gates) for the full list and
why each one lives here rather than in a plugin.

For a service concern, the rule is unchanged: extend the generic Codefly/Core
contract and the applicable plugin; never add a service-specific implementation
to provider YAML.

Quality phases run in four independent matrix jobs: `verify,sync-drift`,
`lint`, `compile`, and `test`. Each uses a fresh checkout and the same affected
service plan. All four must succeed for `codefly-quality` to succeed; matrix
fail-fast is disabled so one failed phase does not cancel the other evidence.
The release aggregate still requires the complete quality result. Disk setup
checks for 12 GiB free under Docker's storage directory and removes unused
runner toolchains only when below that threshold. Go caches include the
checksums of the root, tools, and service modules.

Accounts also exposes a runtime-free pure check and four database targets; see
[Accounts test targets](module/services/accounts/TESTING.md) for commands, timing
evidence and the conservative planner handoff. The canonical service gate still
runs the full default suite.

Measured bottlenecks, remaining work toward a five-minute gate, and validation
limits are recorded in [CI_PERFORMANCE.md](./CI_PERFORMANCE.md).

For version tags, successful completion of this gate — together with every other
mandatory check, through the aggregate described in [Publication
gating](#publication-gating) — unlocks the immutable module-package publication
job. That job handles only the release transport: strict package-manifest
validation, deterministic archive construction, digest, aggregate SBOM,
provenance signing, and immutable GitHub Release publication. It does not
duplicate service build or test policy.

Publication requires three release-only repository secrets: the read-only
Administration token `RELEASE_ADMIN_TOKEN` for immutable-release policy checks,
the base64 Ed25519 key `RELEASE_PROVENANCE_PRIVATE_KEY` for Core's detached
module provenance signature, and its independently configured trust-policy key
`RELEASE_PROVENANCE_PUBLIC_KEY`. Missing, malformed, or mismatched credentials
fail before a release is created.

## Publication gating

No job that writes an artifact runs unless every mandatory check has *actually
succeeded*. That is enforced by a single aggregate job, `release-gates`, which
is the only entry in every publisher's `needs`:

```
base-integrity ───────┐
authz-coverage ───────┤
release-contract ─────┤
docs-sync ────────────┤
kit-version ──────────┤
provider-shim ────────┤                     ┌─▶ publish-module-package  (module-package/v*)
marketing ────────────┼─▶ release-gates ────┼─▶ publish-frontend-kit    (v*)
sdk-boundary ─────────┤   (!cancelled() +   └─▶ handbook-surface-bump   (v*)
module-package ───────┤     decide)
codefly-plan ─────────┤
codefly-quality ──────┤
codefly-supply-chain ─┤
codefly-build ────────┘
```

Before this aggregate existed, `authz-coverage` was an independent job that no
publisher listed in `needs`, directly or transitively. A tag run could therefore
publish while the authorization gate was red, and a red overall workflow does not
retract an artifact that is already public. Branch protection on pull requests
narrows the opportunity but creates no tag-time dependency.

`release-gates` runs with `!cancelled()`, so a failed dependency does not skip it
— it reaches its own step, which calls `scripts/ci/release-gates.mjs decide` with
`toJSON(needs)`. A bare `needs:` list cannot tell a check that passed from one
that never ran; `decide` fails the aggregate unless every mandatory gate reports
`success`, so `failure`, `cancelled`, and an unexpected `skipped` all block
publication identically. The publishers carry no `always()` of their own, so a
failed aggregate skips them. (`always()` would work too, and the contract accepts
either; `!cancelled()` additionally lets a run superseded by `cancel-in-progress`
skip the aggregate rather than record a failure nobody should read.)

`decide` also refuses a release ref whose plan was **delta-scoped**. `codefly-plan`
forces `--all` from the ref, not from the push payload: `github.event.before` is
the zero sha only for a *new* tag, so force-moving an existing tag would otherwise
scope the mandatory gates to a delta and publish services that were never rebuilt
or re-audited for that release. The aggregate re-checks `codefly-plan`'s `all`
output on every release ref, so a scoped release fails even with all thirteen gates
green.

### Mandatory gates per tag track

Both tracks publish from the same tree, so both require the same gates. There is
no per-track exemption.

| Gate | `v*` (deploy counter) | `module-package/v*` | Note |
| --- | --- | --- | --- |
| `base-integrity` | required | required | canonical manifest freshness |
| `authz-coverage` | required | required | RBAC, audit, and no-broadening |
| `release-contract` | required | required | this gating graph itself |
| `docs-sync` | required | required | interface docs and story tests |
| `kit-version` | required | required | published frontend kit version vs. content |
| `provider-shim` | required | required | non-writing provider shims |
| `marketing` | required | required | marketing isolation build |
| `sdk-boundary` | required | required | Codefly SDK boundary and contracts |
| `module-package` | required | required | package contract, determinism, buf breaking |
| `codefly-plan` | required | required | affected-service resolution |
| `codefly-quality` | required | required | affected-scoped (see below) |
| `codefly-supply-chain` | required | required | affected-scoped (see below) |
| `codefly-build` | required | required | affected-scoped (see below) |

The three affected-scoped Codefly jobs carry the **one** deliberate exemption:
off a release tag, a plan that explicitly reports no affected service
(`has_work=false`) legitimately skips them, and `decide` accepts that skip so a
docs-only pull request is a near-instant no-op. On either release tag the
exemption does not apply — those jobs force themselves to run there via their own
`if:`, so a skip is a defect, not a scoping decision. The exemption also requires
`codefly-plan` itself to have succeeded **and** to have said `false` in so many
words: an absent or unrecognized `has_work` (a renamed output, a lost
`GITHUB_OUTPUT` write) exempts nothing, so a broken plan job cannot silently
retire the three heaviest gates while this one stays green.

`handbook-surface-bump` counts as a publisher alongside the two package jobs: it
dispatches the release to a downstream repository, an outward-facing write with
the same "cannot be retracted" property.

Its dispatch is not, however, a publication of the release itself: every artifact
is already public by the time it runs, and nothing is retracted when it does not
happen. `scripts/ci/announce-release.mjs` splits the two cases that follow from
that. Missing either the `HANDBOOK_REPOSITORY` variable or the
`HANDBOOK_DISPATCH_TOKEN` secret, it records a `::warning::` and succeeds without
dispatching — an unconfigured docs announcement must not mark a correct release
red beside a real publication failure. Provisioning is two operator commands, so
a half-configured repository warns on the same footing rather than failing in the
window between them; the annotation repeats on every release until both are set.
With both present, a dispatch the handbook rejects still fails the job.
`node --test scripts/ci/announce-release.test.mjs` covers all three outcomes —
including that an unconfigured run dispatches nothing at all — and runs in
`release-contract`.

### The contract test

`release-contract` runs `scripts/ci/release-gates.mjs check`, which parses every
file in `.github/workflows` and rejects any artifact-writing job whose transitive
`needs` closure does not contain `release-gates`. A job counts as artifact-writing
when it holds `packages`, `id-token`, or `attestations` write permission (or the
scalar `permissions: write-all`, which grants all three), when a step mutates a
GitHub release, publishes an npm package, pushes an image, sends a
`repository_dispatch`, or attests provenance, or when it `uses:` a publishing,
release, or repository-dispatch action — those authenticate with a secret in
`with:` rather than through `permissions`, so nothing else would see them.
(`contents: write` alone does not count: `dep-audit.yml` holds it only to push a
remediation branch.)

Every `uses:` must also resolve to a digest — a commit digest, or an image digest
for a `docker://` step — and carry its version in a trailing comment. The digest
is the security property; the comment is the only thing that makes it reviewable,
and `.github/dependabot.yml` now rewrites these pins on a schedule, so the
convention had to become a rule.

### The dependabot contract

`release-contract` also runs `scripts/ci/dependabot-coverage.mjs check`, which
compares `.github/dependabot.yml` against the manifests actually in the tree.

A dependency manifest hashed in `module/tools/base-manifest.json` must **not** be
configured. Dependabot would bump it, the recorded hash would go stale, and
`base-integrity` — mandatory — would fail with no way for Dependabot to repair
it: it cannot run `base-integrity.mjs gen`, and regenerating the manifest onto
its branch from a workflow does not help, because a commit pushed with
`GITHUB_TOKEN` starts no workflow run and the required checks would never report
against the new head. The pull request could never merge, and it would hold that
ecosystem's `open-pull-requests-limit` open indefinitely, silently starving every
later update behind it. That is why npm, pip and the five in-module `go.mod`
files are absent: they are base files, owned by the canonical module.

The mirror rule closes the other gap: a non-generated manifest that is *not*
base-tracked must be configured, so an ecosystem nobody wired up fails the gate instead of quietly
receiving nothing. An entry pointing at a directory with no manifest of its
ecosystem fails too, since it can never open a pull request.

Agent-generated `module/services/*/builder/Dockerfile` recipes must **not** be
configured in Dependabot: agents replace them before building. The coverage gate
rejects those entries. `scripts/ci/build-images.json` records the expected build
images and the owning agent source for Go,
Next.js and the Postgres migration builder (including telemetry's generated Go
recipe, which is not checked in).

The weekly `build-images.yml` monitor compares registry digests for the effective
tags, their current release lines, and latest release lines. An available update
fails that monitoring run and writes a summary linking the authoritative agent
source; it creates no generated-file PR. Vendor runtime images remain covered by
the Codefly supply-chain audit. This monitor requires Docker Buildx and registry
access; it does not qualify or automatically adopt an upgrade.

To upgrade an image:

1. Update the owning service agent's template/constants and qualify its release.
2. Adopt that release in `module/deployment/topology.bindings.codefly.yaml`,
   regenerate service manifests, refresh the base manifest, and update the
   expected images in `scripts/ci/build-images.json` in the same PR.
3. Run `codefly ci run --all` and boot the graph with `codefly run service`
   before adopting a runtime/compiler major. A successful build alone does not
   establish runtime compatibility. Do not bump Node or Go majors by editing a
   generated recipe.

CI rejects edits to generated recipes; deleting obsolete generated copies is
allowed. Image proposals belong in the image contract alongside topology adoption.
Every topology service must declare image coverage, even if its recipe is absent
from the checkout. Redis and Vault explicitly use the existing Codefly vendor
image audit; an unknown agent is an error.

Changes to the image contract force the full service graph through CI. Before
each canonical build attempt, CI snapshots Buildx history. After the build,
`build-images.mjs evidence` reads the executor's structured materials from new
build records, matched to each service context and recipe. BuildKit owns Dockerfile
syntax and stage reachability: unused stages are not required, and whitespace,
build arguments and stage aliases cannot hide effective dependencies. Both missing
and unexpected materials fail verification. Command output is never evidence.
Missing, failed or ambiguous build records fail closed, and previous attempts or
other workspaces cannot supply a service's materials.

The `effective-build-images` artifact retains Codefly reports, build logs, recipe
text, agent pins and per-build material digests. Floating tags (currently the
migration builder's Alpine 3.21) retain the digest BuildKit actually used, never a
later registry lookup. CI pins Buildx v0.33.0 with the Docker driver to obtain this
executor evidence without changing Codefly's build path.

The same check fails if `authz-coverage` — or any other gate in `REQUIRED_GATES`
— is dropped from the aggregate's `needs` or removed from the workflow, if the
aggregate would skip past a failed gate, if it stops calling `decide`, or if a
workflow becomes unparsable. `node --test scripts/ci/release-gates.test.mjs`
covers both halves against fixtures, including a synthetic future publisher wired
to the wrong dependency, and cross-checks the bundled workflow reader against an
independent scan of the raw text so a job the reader silently drops fails the
suite rather than vanishing from the graph.

The same job also enforces that every action the workflows call is pinned to a
40-character commit digest, with the human-readable version in a trailing
comment. A mutable tag is a standing write into this repository's build by
whoever can move it upstream — including into `release-gates` itself, the one
job whose verdict authorizes publication. Only a `./`-prefixed action from this
repository is exempt, since it is already as trustworthy as the tree calling it.
The scan covers a job's own `uses:` as well as its steps', so a reusable
workflow cannot enter unpinned either. A `docker://` step pins to an image
digest instead, since no commit digest exists for it.

Resolve a new action's tag to its commit with
`gh api repos/OWNER/REPO/commits/TAG --jq .sha`. Read the tag ref directly
(`git/ref/tags/TAG`) and you get the *tag object's* SHA whenever the tag is
annotated, which names no commit and will not resolve in `uses:`.

The same job also enforces the merge queue's prerequisite. `main` merges through
a queue, which builds each entry as `main + the pull request` and gates the merge
on the required contexts reported from *that* ref — the guarantee "require
branches to be up to date" used to buy by making every author rebase by hand.
Every required context must therefore report on `merge_group` too. One that does
not leaves its entry waiting on a check that never arrives until the queue evicts
it, and entries merge in order, so a single missing context stalls every merge in
the repository. No pull request run reveals this, because the same job is green
there.

`REQUIRED_CONTEXTS` names those contexts as the ruleset spells them. The check
fails if a workflow holding one of the jobs that report them has no
`merge_group:` trigger; if `cancel-in-progress` is unconditionally `true` at
either the workflow or the job level, since a cancelled `merge_group` run never
reports and stalls the queue exactly as never running would; if `codefly-plan`
stops *reading* `github.event.merge_group.base_sha`, without which an entry has
no base and verifies the full topology every time; if a job that reports a
required context is renamed away from it, since the ruleset matches a job by its
`name:` and a rename leaves it waiting on a context nothing reports; or if a
declared context has no job reporting it at all. An *expression* for
`cancel-in-progress` is taken at its word as the author discriminating by event —
only the bare literal is rejected, because evaluating workflow expressions is not
something this reader can honestly claim to do. "Reading" the base sha likewise
means naming it inside a `${{ … }}` interpolation in something other than a
comment: `run:` bodies reach the reader raw, and the prose in `ci.yml` explaining
merge-queue base scoping sits three lines under the expression it describes, so a
plain substring match would go vacuous the moment someone documented it by name.

**The one thing `check` cannot verify is the list itself.** `REQUIRED_CONTEXTS`
is this tree's copy of a set that really lives in GitHub's branch configuration,
and no token available to a workflow run can read that — it needs
`Administration: read`, which `GITHUB_TOKEN` cannot hold. A context added there
but not to this list is the dangerous direction: nothing holds it to running on
`merge_group`, so the first queued pull request waits out
`check_response_timeout_minutes` and is evicted, with `check` green throughout.
Reconcile the two from your own credentials, and do it whenever either side
moves:

```bash
node scripts/ci/release-gates.mjs contexts        # defaults to this repository
node scripts/ci/release-gates.mjs contexts owner/repo
```

It fails naming each context that only one side has, and also fails if nothing
requires a check on the default branch at all — on an unprotected branch a merge
queue gates nothing.

A branch can be gated two ways, and **neither mechanism is visible to the
other's endpoint**. A ruleset shows up in `rules/branches/<branch>`, which is
what the queue rule lives in; classic branch protection shows up only in
`branches/<branch>/protection`, and `rules/branches` answers `[]` for a branch
it gates. So `contexts` reads both and unions them. Reading one alone is how the
fleet audit below called a repository advisory while three checks gated its
merges.

Two limits are worth stating plainly. The contract **cannot protect its own job**:
delete `release-contract` from the workflow and both the check and its tests stop
running, with nothing in-repo left to notice — branch protection is the only
backstop for that, and it is why `release-contract` belongs in the repository's
required-checks list alongside `release-gates`. And artifact-writing detection is
a pattern list, not a proof: a publisher that writes by some means outside the
signals above would not be classified. Extend `PUBLICATION_STEP_PATTERNS` and
`PUBLICATION_PERMISSIONS` when a new publication mechanism arrives.

### The fleet beyond this repository

Everything above is about this repository, and that is a decision rather than an
oversight. `main` here is the **only** default branch in the organization that
merges through a queue, and the merge queue is only reachable through a ruleset's
`merge_queue` rule, so there is no rollout to inherit it: on a branch that
requires nothing, a queue gates nothing.

Enumerate rather than believe a count, including this paragraph's:

```bash
node scripts/ci/release-gates.mjs fleet           # defaults to codefly-dev
node scripts/ci/release-gates.mjs fleet owner
```

Every non-archived repository gets one line — `gated`, `advisory`,
`unavailable`, or `unknown` — and every gated one lists the contexts it requires,
whether it has a queue rule, and whether it still requires branches to be up to
date. `unavailable` is a private repository on an account whose plan offers
neither mechanism, recognised by the upgrade notice GitHub answers with, which
can require nothing until that changes. `unknown` is every other read that did
not answer, and it exits non-zero listing what each one said, because a sweep
that quietly skipped a repository reads exactly like one that cleared it — and
because the cause matters: a missing permission, an exhausted rate limit and an
outage all land there and want different responses.

**Run it with admin on the repositories you are sweeping, or read `unknown` as
the answer it is.** Classic branch protection is readable only by a repository
admin, and GitHub masks that permission error as `404 Not Found` — the same
answer it gives for a branch that genuinely has no protection. `cli/cli`'s
`trunk` reports `protected: true` on the branch object while
`branches/trunk/protection` 404s for anyone who does not administer it. So a
protection 404 counts as "unprotected" only when the credential holds admin
(`permissions.admin`, which rides along on the listing at no extra request);
otherwise the repository is `unknown` rather than quietly `advisory`. The
ruleset half needs no such care — GitHub returns every active rule that applies
regardless of where it is configured, omitting only `evaluate` and `disabled`
rulesets, which gate nothing anyway.

The audit that #617 records was a hand-written list of 17 repository names, and
it reported that no repository but this one required a check. It was wrong:
`secure-saas-platform` requires three, through classic protection, with
`strict: true` and no queue — the same livelock configuration #611 was filed
about. Two failure modes produced that, and the command exists because both are
invisible from the inside: a list of names cannot report what it never looked at
(the sweep that replaced it enumerated 60 active repositories), and the endpoint
everyone reaches for cannot see classic protection.

**Making a repository's CI blocking is its own decision, not a follow-through.**
It takes effect the moment it lands: every required context must be a job name
that actually reports on every pull request under its real, matrix-expanded
name, or nothing in that repository can merge; and whatever is red or flaky there
becomes a merge blocker on day one, having never had a reason to stay green.
Nothing here schedules that. Per repository, if it is taken: confirm the default
branch is green and its job names are stable, require those contexts
**non-strict** (strict is what livelocked this repository — see #611), and only
then, and only if merge volume warrants it, add the `merge_group` prerequisites
to that repository's workflow before adding a `merge_queue` rule. This repository
is the reference implementation for that last step, and the order is
load-bearing: a queue enabled before its workflow reports on `merge_group`
strands every entry behind checks that never arrive.

## What Codefly owns

The complete gate runs these ordered phases:

1. base integrity verification;
2. non-mutating generated-source drift detection;
3. plugin-owned lint;
4. plugin-owned native compilation or typechecking;
5. plugin-owned named test suites;
6. plugin-owned dependency and vulnerability audit;
7. plugin-owned CycloneDX SBOM generation; and
8. plugin-owned deployable artifact/container build.

Codefly computes directly changed services and their transitive dependents from
the workspace graph. Independent tasks run concurrently, while tasks that share
runtime dependency closures are serialized. Pushes and pull requests provide a
base revision; manual runs and first pushes fall back to `--all`.

Language commands, protobuf toolchains, dependency lifecycle, container build
logic, and evidence normalization belong to the service plugins. If a required
*service* gate is missing, extend the generic Codefly/Core contract and the
applicable plugin; never add a service-specific implementation to provider YAML.

## Repository-specific gates

These jobs are not service gates and have no plugin to live in: each guards an
artifact or a cross-service contract that belongs to the repository as a whole.
Every one of them is mandatory on both release tracks (see the table above), and
this list is held to `REQUIRED_GATES` in `scripts/ci/release-gates.mjs` by
`release-gates.test.mjs` — a gate added there and not documented here, or the
reverse, fails the `release-contract` job.

| Job | What it guards | What it runs |
| --- | --- | --- |
| `base-integrity` | the canonical base manifest that seeds every consumer sync, plus the RLS-migration, migration-pairing, reference-aware migration upgrade, and generated-pin gates | `node --test` for each gate's own suite, then `node module/tools/<gate>.mjs check`; migration reference validation runs on every candidate, with PostgreSQL upgrade and clean-install replay scoped to migration/runner inputs (see [migration policy](module/services/store/migrations/README.md)) |
| `authz-coverage` | the generated authorization catalog: RBAC coverage, audit coverage, and permission no-broadening against `main` | `node module/tools/authz-coverage-gate.mjs`, plus `go test` for the gateway header-lockstep and adapter enforcement tests |
| `release-contract` | this gating graph itself, and the Dependabot configuration that feeds it | `node --test scripts/ci/release-gates.test.mjs`, `node --test scripts/ci/dependabot-coverage.test.mjs`, `node scripts/ci/release-gates.mjs check`, `node scripts/ci/dependabot-coverage.mjs check` |
| `docs-sync` | the generated interface docs and the story-trace tests (#516) | `node module/tools/interface-docs-gate.mjs check`, `node module/tools/story-trace-gate.mjs tests` |
| `kit-version` | the published frontend kit's version moves whenever its content does, since a registry version is immutable once served | `node --test scripts/ci/kit-version.test.mjs`, `node scripts/ci/kit-version.mjs check` |
| `provider-shim` | provider setup scripts stay non-writing shims | `node --test scripts/setup/*.test.mjs` |
| `marketing` | the marketing runtime builds in isolation from the app, and the public config is current | `node module/tools/generate-public-config.mjs --check`, `node module/tools/marketing-extraction.mjs` |
| `sdk-boundary` | the root module's own tests, the Codefly SDK boundary, single-invocation protocol generation, and the exported API contract | `go test ./...` **in the root module only**, `go test codefly_sdk_boundary_test.go`, `codefly generate contracts saas-starter --check` |
| `module-package` | the package contract, protobuf compatibility, generator determinism, published conformance suites, and byte-identical archive builds | `go test ./...` **in `module/tools` only**, `go run ./cmd/module-package …`, `buf breaking`, `npm run test:published-plugin-contract` |

Two of those `go test ./...` invocations are worth reading carefully. This
repository holds **six independent Go modules** — root, `module/tools`, and one
per Go service — with no `go.work`, so `go test ./...` covers only the module it
is run in. The `sdk-boundary` invocation runs in the root module (the module
agent, the host, the generated reference composition) and the `module-package`
one runs in `module/tools`; neither compiles, let alone tests,
`services/accounts/code` or `services/auth-gateway/code`. Those are tested by
`codefly-quality` and `codefly-build` through their service plugins. Nothing in
this repository presents a root `go test ./...` as service coverage.

## Vulnerability policy and its one exemption

`codefly-supply-chain` runs the audit twice over, and the two runs have
deliberately different policies.

1. **Complete evidence, non-blocking.** The `audit` phase runs across the whole
   affected selection with `--fail-on-vuln=false` (and `--jobs=1`, because
   several published vendor-image agents predate Core's shared Trivy cache
   lock). This keeps every finding — including ones in vendor runtime images
   that have their own release cadence and that this repository cannot patch —
   in the Codefly evidence report rather than making the first unpatchable
   vendor CVE block the release.
2. **First-party enforcement, fail-closed.** A separate step then re-audits only
   what this repository owns and fails on any finding:

   ```sh
   codefly audit service accounts --outdated=false --fail-on-vuln
   codefly audit service auth-gateway --outdated=false --fail-on-vuln
   npm --prefix module/services/frontend/code audit --omit=dev --audit-level=high
   npm --prefix module/services/marketing/code audit --omit=dev --audit-level=high
   ```

   `--outdated=false` keeps this step about vulnerabilities, not staleness. The
   two npm audits are production-dependency-only at high severity.

So `--fail-on-vuln=false` narrows *what blocks*, never *what is looked at*: the
evidence report is the wider of the two, and the enforcement step is the
narrower. A finding in a first-party dependency is un-mergeable; a finding in a
vendor runtime image is recorded and triaged.

## Canonical manifest freshness

Phase 1 verifies that base files match `tools/base-manifest.json` — it trusts
the committed manifest as the source of truth. That protects consumers, but it
cannot catch the manifest itself drifting from the canonical tree it was
generated from: a base file edited without re-running
`node tools/base-integrity.mjs gen` ships a stale digest, and every consumer
sync then aborts on an unreconcilable source-path mismatch (v0.0.32).

Provider CI closes that gap with `base-integrity.mjs verify`, which re-derives
the manifest from the tree and fails on any changed, unrecorded, or removed base
file. It guards the canonical artifact that seeds every other consumer, so it
must run here rather than in a consumer copy — the same reason every job in
[Repository-specific gates](#repository-specific-gates) lives in provider YAML.

## Naming and confidentiality

This repository is **public**, and it sits below its consumers in the dependency
graph: it must carry no documentation-level or build-time knowledge of who
composes it. `AGENTS.md` §"Naming and confidentiality" has said so since the repo
was created, but nothing enforced it, and ~380 violating lines accumulated across
68 files — including a consumer's domain baked into a wire-format constant and a
design doc whose own filename named a private product.

`tools/naming-gate.mjs check` scans every tracked file's **contents and its
path** for real customer, product, and consumer names, and fails the build on a
hit. The forbidden terms live in `tools/naming-terms.json` as SHA-256 digests
rather than literals — a plaintext list would itself be the worst violation in
the tree. That is not secrecy (short digests are dictionary-attackable); it only
avoids stating the relationship.

The same rule binds the records around the tree — AGENTS.md names "issues, PRs,
… commit messages" — and those are the copies that cannot be taken back: GitHub
retains prior revisions of an edited body and serves them through its API, and a
commit message cannot be edited at all without rewriting history. So a second
step, `naming-gate.mjs records`, runs the same digests through the same matcher
over the pull request's **title**, its **body**, and every **commit message** in
the range, and fails the pull request before it can merge. It reports the
matching mode and the line, never the term: that log is public, and quoting the
match would republish exactly what the gate exists to keep out of it. It runs on
`pull_request` and on `merge_group`, where the title and body do not exist and
the commits alone are checked.

Prevention is the whole of the remedy here. Cleaning up a record that is already
published is a separate remediation and only a partial one, for the same two
reasons that make the check worth having.

Locally:

```sh
node module/tools/naming-gate.mjs check
node module/tools/naming-gate.mjs records <base>   # title and body from the environment, plus <base>..HEAD
node module/tools/naming-gate.mjs message <file>   # one commit message — what the hook runs
node module/tools/naming-gate.mjs hash <term>      # digest for a new terms entry
```

`scripts/hooks/commit-msg` runs the `message` check before the commit exists at
all. It is opt-in, because it takes over `core.hooksPath` for the repository:

```sh
git config core.hooksPath scripts/hooks
```

A genuine exception — a copyright holder, a CODEOWNERS handle — goes in
`tools/naming-allowlist.json` with a `reason` and a `ticket`. An entry missing
either is ignored, so an exemption cannot take effect without a reviewable
justification.

## Authorization coverage

The generated authorization catalog
(`services/accounts/generated/authz-methods.json`) is a complete, typed policy
for every RPC. The `Authorization coverage` job turns that catalog into
default-deny CI gates, so an under-specified or widened route is un-mergeable
rather than merely discouraged. `tools/authz-coverage-gate.mjs` runs, in order:

- **RBAC coverage** (`rbac`) — every RPC must declare a coherent gate: a known
  exposure (public / authenticated / internal), a known policy tier served on
  the matching exposure, and a platform-role requirement iff it is a
  platform-admin route. An unclassified route fails.
- **Audit coverage** (`audit`) — every mutating, caller-attributable RPC must
  emit audit. A mutation that records nothing fails.
- **Permission no-broadening** (`no-broadening`) — the catalog is diffed against
  `main`; any change that widens who may call a route (a relaxed exposure,
  tenant, platform-role, or MFA requirement, or a dropped permission/scope) fails
  unless the pull request carries the `authz-broadening-approved` label, which
  sets `AUTHZ_ALLOW_BROADENING` for the run.

Both coverage gates read ticketed exemptions from
`tools/authz-coverage-allowlist.json`; every entry needs a reason and a ticket,
and removing one re-arms the gate. The same job also runs the gateway
header-lockstep test (`TestUntrustedHeaders_SupersetOfStampedHeaders`), which
keeps the gateway's stamped identity headers a subset of the headers it strips;
the accounts-side companion (`TestUntrustedHeaders_SupersetOfTrustedHeaders`)
runs with the accounts service test suite.

## Published frontend kit version

A registry version is immutable, so the frontend kit's version has to move
whenever its content does. `publish-frontend-kit.mjs` enforces that at the
registry — it compares the built tarball's integrity against the version already
published and refuses to contradict it — but on its own it only reports the
problem at release time, after the tag is cut, which is where v0.0.58 stopped
with the kit's content several releases ahead of the version the registry serves
(#550). Meanwhile a consuming solution that installs the kit resolves the older
published bytes while the host serves its newer workspace copy, and the two
share one Module-Federation singleton slot keyed by version, so nothing shows
until an export disappears at runtime.

`kit-version` moves that verdict onto the pull request. It takes the newest
deploy-counter tag as the baseline of what the registry serves and fails when a
published kit package's content changed since that tag under an unchanged
version:

```sh
node scripts/ci/kit-version.mjs check
```

It reads git history rather than the registry on purpose — a registry read needs
a publish-capable token, which no branch build should hold. The registry
comparison in the publish step stays as the exact authority at release time.

The kit is co-versioned: `@codefly-dev/ui`, `@codefly-dev/saas-ui`, and
`CODEFLY_KIT_VERSION` in `services/frontend/code/src/solutions/SolutionOutlet.tsx`
bump together, which the `kit-shared-version` test pins.

## Evidence

Every run writes the schema-versioned report to `.codefly/ci/report.json` and
places SBOMs and other plugin-returned artifacts below the same directory. The
report records the affected-service plan, task graph, resolved plugin metadata,
phase and suite identities, timings, outcomes, blocking relationships, and
artifact hashes.

The report directory is machine-local output and is not committed. A CI
provider may retain it without interpreting or reconstructing its contents.

## Staying ahead of newly-published advisories

The first-party vulnerability gate (see [Vulnerability policy and its one
exemption](#vulnerability-policy-and-its-one-exemption)) fails closed on every
high-severity finding in the production dependency tree. Because
that check reads the live advisory database, a freshly published advisory on an
already-pinned transitive can redden an otherwise-clean release at tag time even
though the lockfile never changed (browserslist did exactly this before #400).

`.github/workflows/dep-audit.yml` keeps main ahead of that. On a daily schedule
(and on demand via `workflow_dispatch`) it runs `npm audit fix
--package-lock-only --omit=dev` across the frontend and marketing lockfiles,
rolls whatever it can safely remediate into a single standing pull request
(`chore/dep-audit-remediation`), explicitly dispatches `ci.yml` on that branch
after each push, and then re-runs the gate's own
`--audit-level=high` audit. If an advisory cannot be auto-fixed — it needs a
major bump or an explicit `overrides` pin — that final step fails the run so a
maintainer acts before the next tag. The job never weakens the gate: it moves
the same policy earlier so tags cut from an already-remediated tree.

The explicit dispatch is necessary because pushes and PRs created with
`GITHUB_TOKEN` do not trigger workflows. The token has `actions: write` to
dispatch CI, which reports the required named checks on the remediation head
SHA. A dispatch has no comparison base, so CI checks the full service graph;
publication remains restricted to release tags. A dispatch failure fails the
remediation run.

## Local use

Run the same release gate from the workspace root:

```sh
codefly ci run --all
```

For a focused reproduction, use `--phase`, `--suite`, or a base revision. These
are views of the same plugin-owned gate, not alternate test pipelines.

## Release cadence and ownership

`codefly sync module` pins an **immutable semver tag** in the consumer's
`base-source.json` lock. Consumers advance only when they deliberately re-pin,
so this repository's tag rhythm bounds every consumer's update rhythm.

Tags are cut by the saas-starter maintainers **on demand** — whenever
consumer-relevant base changes have landed on `main` and pass `codefly ci run`
plus `base-integrity.mjs verify`. There is no fixed calendar; a release is a
maintainer decision that the current base tree is a good pin, not a scheduled
event. Consumers that need to move faster than tags are cut should open an issue
rather than pin an untagged revision.

Two independent tag tracks share this repository, on two different version
axes. They are not interchangeable:

- **Deploy counter** — the `v0.0.x` tag series a downstream deployment
  repository and its per-environment deploy jobs adopt via `codefly sync module
  --to <tag>`. The tag itself is the
  counter; `agent.codefly.yaml`'s `version:` is the module agent's own version
  and may lag the tags (it is bumped when the agent changes, not on every tag).
- **Immutable module package** — `module-package/vX.Y.Z`, sourced from
  `module/module.package.codefly.yaml`'s `version:` (the module semver). Only
  this track triggers the immutable-package publication job (strict manifest
  validation, SBOM, provenance signing). The two axes are genuinely different;
  do not conflate them (that mismatch was [#405]).

To cut a deploy-counter tag:

1. If the module agent itself changed, bump `version:` in the root
   `agent.codefly.yaml`.
2. Commit it as `release: v0.0.N`.
3. Tag that commit with an annotated `v0.0.N` tag and push the tag.

To cut an immutable module-package release:

1. Bump `version:` in `module/module.package.codefly.yaml`.
2. Commit it as `release: module-package/vX.Y.Z`.
3. Tag that commit with an annotated `module-package/vX.Y.Z` tag and push it.

[#405]: https://github.com/codefly-dev/module-saas-starter/issues/405
