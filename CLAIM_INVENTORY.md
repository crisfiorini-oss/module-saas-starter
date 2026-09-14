# Claim inventory — root architecture documents

Audit finding A14 found that the root architecture documents assert things the
code no longer does, and in a few places things the code never did. This file is
the register that closes that loop: one row per load-bearing claim, naming the
executable evidence for it, what kind of claim it is, and who owns it.

It exists because the root documents are prose that nothing tests. Where a claim
*can* be machine-checked, the right answer is a gate rather than a row here — and
two of the rows below point at exactly that. Where a claim is about trust,
lifecycle, or failure semantics, no gate can carry it, and a reviewed row is the
best available evidence.

**Read the status column strictly.** In particular:

| Status | Means |
| --- | --- |
| **implemented** | shipped code, named below, with a test that fails if it regresses |
| **configured** | true of the shipped configuration; a deployment can set it otherwise |
| **operationally verified** | evidence exists from a running deployment, not only from tests |
| **planned** | designed and owned, not built |
| **historical** | was true; kept as a record of how something came to be, not as current state |
| **reviewed narrative** | a statement about trust, lifecycle, or failure semantics that no test can carry; its evidence is that a person reasoned about it and named the reasoning |
| **corrected** | the row records a claim this repository *used* to make and no longer does. Struck through, kept so a reader who remembers the old text can see it was retired deliberately rather than lost |
| **known drift, filed** | a claim that is wrong today, with an issue open against it. Do not rely on it |

Nothing here is marked **operationally verified**. Every row below is evidenced
by source, tests, or CI configuration in this repository, all of which run
against local fixtures and ephemeral containers. Live provider behaviour, cloud
failover, backup restoration, key-management operations under real rotation, and
any compliance posture are **not** established by anything in this repository and
must not be inferred from a row here. See
[Limits of this evidence](#limits-of-this-evidence).

## Authorization and database boundary

| Claim | Source | Executable evidence | Status | Owner |
| --- | --- | --- | --- | --- |
| Three orthogonal authorization layers (handler gate, RBAC, RLS) | MODULE.md § Three layers of authorization; AUTHZ.md | `pkg/adapters/auth.go`, `pkg/business/service.go:CheckPermission`, store RLS migrations | implemented | accounts |
| The layers are **complementary, not interchangeable** — none is a backstop for another's bug | MODULE.md § Three layers of authorization | none; this is a reviewed statement about what each layer can and cannot decide | reviewed narrative | this issue (#541) |
| ~~"A bug in any one layer is caught by the others"~~ | MODULE.md, before this change | contradicted by #530 (team member from a foreign org is a correctly-scoped row) and #533 | **corrected** | #541 |
| Scope transitions are `WithOrgTx` / `WithUserTx` / `WithControlPlane`; there is no application-settable RLS bypass | MODULE.md, AUTHZ.md, module/DATABASE_AUTHORITY.md | `pkg/infra/tenant_tx.go`; the `app.bypass` setting is gone | implemented | accounts |
| ~~`WithBypass` / `SET LOCAL ROLE NONE` back to the session superuser~~ | MODULE.md, AUTHZ.md, RLS_PLAN.md, before this change | no such symbol exists | **corrected** (RLS_PLAN.md marked historical) | #541 |
| User-scoped relations carry forced RLS and enter through `WithUserTx` | module/DATABASE_AUTHORITY.md § Scope and RLS inventory | `34_rls_user_scoped`, `35_rls_sessions`, successors; `relationsByScope` | implemented | accounts |
| ~~`users` / `mfa_devices` / `notifications` / `oauth_state` / `refresh_tokens` are outside RLS, protected by `WHERE user_id = $1`~~ | MODULE.md skip-list and AUTHZ.md skip-list, before this change | the first three carry forced RLS; the last two do not exist | **corrected** | #541 |
| The documented relation inventory matches the executable one | module/DATABASE_AUTHORITY.md § Scope and RLS inventory | `TestDatabaseAuthorityScopeInventoryMatchesCode` (`module/tools`) fails on drift in either direction | implemented | #541 |
| `GetServiceInfo`'s RLS catalog (`serviceRLSTables`) reports the current protected set | `pkg/business/introspection.go` | **stale**: 25 hand-maintained entries against 38 tenant + 13 user relations, sourced "store migrations through 60" | known drift, filed | #556 |
| Scope-node role grants and installation identity ship | PLATFORM_REFERENCE.md §1.2 | `98_layered_access`, `112_installations`, `pkg/business/installations.go` | implemented | accounts |
| RLS table→migration adoption table | AUTHZ.md § RLS coverage | names `audit_export_configs`, dropped by store migration 102 | historical (labelled) | #541 |

## Gateway hot path

| Claim | Source | Executable evidence | Status | Owner |
| --- | --- | --- | --- | --- |
| ~~"No network, no DB" on the hot path~~ | PRODUCTION_READY.md § Hot path, before this change | `checkJWT` performs a `jti` and a `sid` revocation read, and resolves its verifying key from a cached JWKS | **corrected** | #541 |
| Access-token validation is EdDSA-only with iss/aud/exp and 60s leeway | PRODUCTION_READY.md § Hot path | `ext_authz.go:checkJWT`, `ext_authz_unit_test.go` | implemented | auth-gateway |
| Verifying keys resolve by `kid` from a JWKS cached 5 min with a 10 min stale grace | PRODUCTION_READY.md § Hot path, § Security hardening | `access_keys.go`; `access_keys_test.go` | implemented (#532) | auth-gateway |
| Revocation answers are cached 3 s, bounded to 50 000 entries, and dropped for the presented `jti` on a logout route | PRODUCTION_READY.md § Hot path | `revocation.go`, `revocation_test.go` | implemented | auth-gateway |
| Revocation-store failure denies (503) unless explicitly configured fail-open | PRODUCTION_READY.md § Hot path | `revocationFailsOpen()` reads `SIDECAR_REVOCATION_FAIL_OPEN` from the `security` group; default false | configured | auth-gateway |
| Impersonation actor/subject semantics | PRODUCTION_READY.md, PLATFORM_REFERENCE.md §1.6 | `x-acting-as-user-id` is stamped from the `acting` claim; the actor/effective-subject model is under correction | planned | #533 |
| The historical `sidecar.go` file names and `LocalValidator` | SECURITY_REVIEW.md, PRODUCTION_READY.md before this change | renamed to `ext_authz.go` by #552; SECURITY_REVIEW.md keeps the old paths because it records findings as they were filed | historical | #541 (labelled, not rewritten) |

## Release gates

| Claim | Source | Executable evidence | Status | Owner |
| --- | --- | --- | --- | --- |
| `codefly ci run` is the canonical **service** gate and provider YAML reimplements none of it | RELEASE_GATES.md; AGENTS.md | `.github/workflows/ci.yml` `codefly-quality` / `codefly-supply-chain` / `codefly-build` | implemented | Codefly |
| ~~"GitHub Actions ... does not encode Go, Rust, Next.js, protobuf, dependency, container, or service-specific commands"~~ and ~~base integrity is "the one repository-specific gate"~~ | RELEASE_GATES.md, AGENTS.md, before this change | nine repository-specific jobs run `node --test`, `go test`, `buf breaking` and `npm` directly | **corrected** | #541 |
| The documented repository-specific gate list is the enforced one | RELEASE_GATES.md § Repository-specific gates; AGENTS.md | `release-gates.test.mjs` compares the table and both prose counts against `REQUIRED_GATES` | implemented | #541 |
| The complete audit runs `--fail-on-vuln=false`; a separate step enforces first-party findings fail-closed | RELEASE_GATES.md § Vulnerability policy | `.github/workflows/ci.yml` `codefly-supply-chain` | configured | Codefly + this repo |
| No artifact-writing job runs unless every mandatory gate actually succeeded | RELEASE_GATES.md § Publication gating | `scripts/ci/release-gates.mjs check` + `decide`, `release-gates.test.mjs` | implemented (#535) | this repo |
| Root `go test ./...` does not cover nested service modules | RELEASE_GATES.md, AGENTS.md | six independent `go.mod` files; there is no `go.work` | implemented (documented) | #541 |
| `main` here is the only default branch in the organization merging through a queue, and `secure-saas-platform` the only other requiring any check | RELEASE_GATES.md § The fleet beyond this repository | `scripts/ci/release-gates.mjs fleet` — operator-run: reading branch configuration needs `Administration: read`, which no workflow token can hold, so no gate can carry this | reviewed narrative | #617 |

## Public registry contract

| Claim | Source | Executable evidence | Status | Owner |
| --- | --- | --- | --- | --- |
| The public solutions `GET` carries only `{id, nav}` | AGENTS.md; `app/api/solutions/register/route.ts` | `route.test.ts` asserts the exact key set | implemented | #541 |
| ~~"nav-only … no upstreams", while the handler spread the whole manifest minus `dashboard`~~ | `route.ts` comment, before this change | the response carried `frontend.manifestUrl`, `exposedModule` and `backend` | **corrected** | #541 |
| Remote and backend detail is served only to a caller holding the cluster-internal token | `app/api/internal/solutions/route.ts` | `internal/solutions/__tests__/route.test.ts` | implemented | #541 |
| A freshly registered cross-origin remote loads with no rebuild | `src/proxy.ts` | `proxy-solution-csp.test.ts` — admitted origin, and self-only on an absent, malformed, unreachable, or token-rejected lookup | implemented | #541 |
| Solution registration is durable across replicas | `src/solutions/registry.ts` | **not implemented**: the registry is process-local | planned | #534 |
| The solution CSP depends on a reachable, token-gated loopback lookup | `src/proxy.ts`; `app/api/internal/solutions/route.ts` | `proxy-solution-csp.test.ts` covers all three degradations (secret unset, 401, unreachable), each to a self-only policy. The new route arrived under a documentation issue and has not been reviewed as a deployed surface — NetworkPolicy scope and the loopback shape are open | known drift, filed | #570 |

## Handbook and interface surfaces

Generated interface documentation and story tracing are **not** owned here.
[#516](https://github.com/codefly-dev/module-saas-starter/issues/516) owns the
handbook surface generation and the story-trace pipeline, and its gates
(`interface-docs-gate.mjs`, `story-trace-gate.mjs`) run in the `docs-sync` job.
This file deliberately adds no second pipeline and no second interface artifact;
it records engineering claims and their evidence, which is a different job from
projecting an interface.

## Naming and confidentiality

AGENTS.md § "Naming and confidentiality" forbids naming any real customer,
partner, employer, or downstream consumer anywhere in this repository, for
architectural reasons as much as legal ones: this module sits below its consumers
in the dependency graph and must carry no documentation-level knowledge of who
composes it.

A14 asked for a targeted cleanup of the prose covered by this change. What that
means concretely:

- Every document, comment and test this change touches was reviewed against the
  rule, and the two violations found in them — one in MODULE.md, one in
  RELEASE_GATES.md — were replaced with generic descriptions.
- **The repository-wide scrub was not done here.** Doing it inside this change
  would have buried the audit corrections in a rename, so it landed separately
  as #569, which added the gate and scrubbed the tree. The row below records the
  state now, not the state as of this change.

| Claim | Source | Executable evidence | Status | Owner |
| --- | --- | --- | --- | --- |
| No **text** file in the repository names a real customer, partner, employer, or downstream consumer | AGENTS.md § Naming and confidentiality | `node module/tools/naming-gate.mjs check` scans every file's contents *and* its path, holding its forbidden terms as digests rather than literals; `naming-gate.test.mjs` covers the matcher and asserts the shipped tree is clean. Both run in the `base-integrity` job | **implemented** | #569 |
| One checked-in **binary** descriptor still carries such a name | `packages/saas-sdk/generated/contract/contract.binpb` | **none — outside the gate's reach.** A compiled descriptor embeds its protos' comments, and the gate skips binaries, so nothing detects this | known drift, filed | #585 |
| No commit **added by a pull request** publishes an author or committer email outside GitHub's no-reply domains | AGENTS.md § Naming and confidentiality | `node module/tools/commit-identity-gate.mjs check <base>` allowlists `<id>+<login>@users.noreply.github.com` and `noreply@github.com` over both fields of every commit in the range; `commit-identity-gate.test.mjs` covers the matcher and asserts the rejected address never reaches the report. Runs in the `base-integrity` job on `pull_request`, from the *current* base tip to the head sha — never from `base.sha`, which is fixed at the last push and would drag already-published commits into the range once the base moves | **implemented** | #708 |
| 506 of the 865 commits already on `main` carry a consumer domain in their author or committer email | this repository's git history (and `cli`, `core`, `solution-runtime-go` likewise) | **none, and none possible without a history rewrite.** Both fields are part of the commit object, so changing one rewrites every descendant hash — breaking every clone, fork and open pull request — and GitHub serves the original objects until a Support request collects them. Rewriting is a disclosure decision weighed against that blast radius, and is **deliberately not taken**; the row above stops the count growing | accepted exposure, filed | #708 |

  The gate runs as a step of the `base-integrity` job rather than as a job of
  its own, so it is mandatory through that job and adds no row to
  § Repository-specific gates.

  Three limits on what the first row establishes, none of them closed here.
  It scans the working tree, so it does not un-publish the names already in
  this repository's git history or in its public issues. And it reads text: the
  accounts descriptor was regenerated with this change so that it matches its
  scrubbed proto, but the saas-sdk copy cannot be — `codefly generate client`
  refuses without `--force`, which also bumps the SDK toolchain, so it is
  #585's to regenerate rather than something to smuggle into a scrub. Until
  then that one file still spells a consumer's name in a public repository.
  What keeps this from recurring in the accounts descriptor is not the gate but
  the pair around it: the protos are scanned as text, and
  `codefly generate contracts --check` fails the build unless the descriptor
  matches them.
- No public denylist of real names is introduced by this file or by anything in
  this change, and no functional or operational identifier was renamed — a
  configuration key such as `SIDECAR_REVOCATION_FAIL_OPEN` keeps its name until a
  deliberate migration changes it, and is documented under the name it actually
  has.

## Limits of this evidence

- Everything above is evidenced by source, tests, or CI configuration **in this
  repository**. Tests run against local fixtures and ephemeral containers.
- No row establishes live provider behaviour (identity provider, email, billing,
  object storage), disaster recovery, backup restoration, high availability,
  failover, key-management operations under real rotation, or any compliance
  posture. Those need evidence from a running deployment, which this repository
  cannot produce.
- An open issue is not evidence of a capability, and closing one is not evidence
  that a capability was verified in a deployment.
- Rows marked **historical** describe documents kept as records. Do not read
  them as current state, and do not "fix" them into the present tense — that
  destroys the record.
