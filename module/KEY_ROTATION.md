# Key rotation

accounts holds exactly two keys, and they rotate differently enough that
conflating them is how a rotation takes authentication down:

- the **Ed25519 signing key**, the trust anchor for every credential the edge
  verifies locally — access tokens, Work Context capabilities, and
  composed-module registration tokens. Replacing it is a staged overlap, because
  credentials signed by the outgoing key must keep verifying until they expire.
- the **envelope key**, which seals every stored credential (source tokens, MFA
  seeds, WebAuthn credentials, webhook secrets) and computes the keyed hash
  behind every API key. Rotating it is invisible to users, because each
  ciphertext records the key version that sealed it — with one exception, the
  keyed hash, which cannot be re-keyed at all.

Which **service** holds them is a deployment decision, selected in the
`key-service` configuration group and never inferred. See "The key service"
below before either runbook: the backend changes who has custody, and for the
envelope key it changes what rotation even means.

## What each side does

**accounts** signs with one private key, loaded from Vault, and publishes the
matching public key plus every retained verification key at
`GET /v1/auth/.well-known/jwks.json`. Each key carries a deterministic `kid` —
the first eight bytes of SHA-256 over the public key — so two processes holding
the same key agree on its id with no coordination
(`services/accounts/code/pkg/auth/ed25519/minter.go`). Retained keys come from
the `internal-auth` configuration group:

| Key | Meaning |
| --- | --- |
| `JWT_PREVIOUS_PUBLIC_KEYS` | Comma-separated base64 Ed25519 **public** keys accounts keeps verifying and keeps publishing. Standard or raw-url base64; malformed entries are logged and ignored. |

**auth-gateway** reads that document and verifies by `kid`
(`services/auth-gateway/code/access_keys.go`). It holds the whole published set,
not one key, so both halves of an overlap verify — and it re-reads on its own,
so no gateway restart is part of a rotation.

Timing the runbook depends on:

| Bound | Value | Set in |
| --- | --- | --- |
| Access-token lifetime | 3 min (5 min while impersonating) | `Config.AccessTokenTTL` / `ImpersonationTokenTTL` |
| Clock-skew leeway | 60 s | `tokenClockSkewLeeway`, matched to accounts' `Config.ClockSkew` |
| Gateway key-set TTL | 5 min | `accessJWKSCacheTTL` |
| Gateway stale grace | 10 min | `accessJWKSStaleGrace` |
| Unknown-`kid` refetch spacing | 5 s | `jwksProbeInterval` |

A gateway picks up a newly published key within one TTL at worst, and usually on
the first token that names it: an unrecognised `kid` triggers a refetch, rate-
limited to one per 5 s across all key ids so untrusted token input cannot drive a
fetch per request. A key that stops being published stops verifying within one
TTL — or within TTL + grace if accounts is unreachable for the whole window.

## The key service

> **Where the cloud driver lives is a labelled stopgap.** accounts holds the GCP
> Cloud KMS driver itself — the endpoint, the metadata server, Google's
> resource-name grammar — because Codefly can express "this cell runs a Vault"
> (`kind: cell-vault`) but has no equivalent for "this cell has a key service",
> so there is no projection to read and no agent that owns the driver the way
> `service-vault` owns Vault's. Filed as codefly-dev/cli#924. Everything above
> the seam is already vendor-neutral, so when that kind exists the driver moves
> below it and nothing here changes. New managed providers use the owner runtime
> client described below; the legacy GCP implementation remains unchanged.

`KEY_SERVICE_MANAGED_BINDING` optionally carries the deployment-produced,
non-secret provider descriptor consumed by `service-vault/keyservice`. Accounts
depends on that client's generic encryption, MAC and wrapping operations; no
second cloud SDK or driver lives here. The existing `kms` / `kms-wrapped`
selections still apply. Mixing a descriptor with legacy KMS key names is refused.

The client owns provider ciphertexts, key-version checks and workload identity;
Accounts retains `cfs1` envelope framing, domain errors, tenant-key selection and
the `signing-key-wrap` purpose. The unwrapped value must still be a base64
Ed25519 seed. A provider outage never falls back to ephemeral signing, including
when a local caller otherwise permits a fixture key.

Build or reuse: the existing Host `Sealer`, `KeyFactory`, `Cipher` and wrapped-seed
path already define the required contracts. The owner client's provider driver
fills the missing implementation; no new Host crypto primitive, signing algorithm
or key store is introduced. Infrastructure allocation, exact workload grants,
recovery custody and live deployment remain separate qualification requirements.


Two backends, selected per key family in the `key-service` group
(`module/configurations/local/key-service.env` carries the full binding):

| | `vault` | `kms` |
| --- | --- | --- |
| What it is | a HashiCorp Vault the cell runs: KV v2 for the signing key, Transit for the envelope key and the keyed hash | the cell's cloud key-management service (GCP Cloud KMS first) |
| How accounts authenticates | an AppRole credential the `vault` secret group delivers | the workload's own cloud identity — on GCP the metadata server, against the service account bound to the pod |
| What the configuration carries | an address and a credential | key **names** only: no credential, no file |
| What the cell operates | a stateful store to run, unseal, back up and credential | nothing; keys are cloud resources |
| Can hold the signing key | yes | **wrapped, yes; natively, not yet** — see below |
| Can hold the envelope key | yes | yes |

`KEY_SERVICE_BACKEND` selects the backend that seals stored credentials and
computes the keyed hash. `KEY_SERVICE_SIGNING_BACKEND` selects the one holding
the signing key, and defaults to `KEY_SERVICE_BACKEND`.

**The two families are selected separately because they move separately.** An
envelope key is migrated by re-sealing, which is reversible and invisible to
users. Replacing the signing key either re-logs everyone in or needs both keys
published across the cutover. A deployment doing one of those this quarter and
the other next says so.

Outside the local environment an unselected backend **refuses to start, by
name**. The two shapes have opposite custody models, so inheriting either by
default would mean reaching a key service nobody chose.

### The same selection decides what is deployed

[ADR 0009](./docs/adr/0009-which-plane-decides-whether-a-vault-is-composed.md)
records why the inventory is decided in the manifest plane rather than read from
this group.

The group above is what the **process** reads. What is **deployed** is decided
earlier, by the environment's own `key-service` declaration in the composing
workspace's manifest (`module/deployment/README.md`, "The environment's key
service"). Both halves use the same two words:

| `key-service` on the environment | What this module composes | What the `key-service` group then selects |
| --- | --- | --- |
| `vault` | the `vault` service, or the cell's own through `managed-services.vault: {kind: cell-vault}` | `KEY_SERVICE_BACKEND=vault` |
| `kms` | **no Vault at all** | `KEY_SERVICE_BACKEND=kms` with `KEY_SERVICE_SIGNING_BACKEND=kms-wrapped` |

They are two declarations because they answer in two planes — a configuration
value is delivered to a running process, and an inventory is rendered before one
exists — and a module manifest cannot make the second a function of the first.
Until this existed they had nothing in common, and a cell whose keys were in
Cloud KMS still got a `vault` StatefulSet it never read: scheduled, refusing to
start without the auto-unseal seal such a cell is forbidden to hold, and
crash-looping. A contradiction between the two spellings — `kms` beside a
`cell-vault` handoff — is now refused by name rather than resolved by
precedence.

The `key-service` line itself is not writable yet (the environment block's
schema is the CLI's, and it has no extension seam), so a composition with no
Vault in any environment states that by leaving `vault` out of its `services:`
list — which the module agent reads as the same selection, and withdraws the
`vault` configuration group because of it: the group is how the vault backend is
reached, so it follows the backend an environment selected rather than the
presence of a workload. A cell whose Vault is the cell's own keeps the group
while this module renders no Vault at all. Neither route reaches a composition
that pins a published release of this module without an edit to that
composition's own files. Both routes,
and what the CLI still owes, are in `module/deployment/README.md`, "Composing no
Vault".

### The signing key's three homes

| `KEY_SERVICE_SIGNING_BACKEND` | Where the key is | Secrets store | Key material in process |
| --- | --- | --- | --- |
| `vault` | Vault KV v2, read at boot | yes — a Vault to run, unseal, back up, credential | yes |
| `kms-wrapped` | a ciphertext in `KEY_SERVICE_SIGNING_KEY_WRAPPED`, unwrapped at boot by a Cloud KMS key | **none** | yes |
| `kms` | inside Cloud KMS; every signature is a request | **none** | **no** |

`kms-wrapped` is what lets a hosted cell run with **no secrets store at all**
today — which is why `key-service: kms` on the environment composes no Vault
rather than keeping one for the signing key alone. The wrapped value is a
ciphertext carried as a configuration value, inert
without the Cloud KMS key named in `KEY_SERVICE_KMS_SIGNING_WRAP_KEY` and the
workload identity that reaches it — so nothing stored is a credential on its own,
and there is no store to operate. What it does not give you is non-exportability
*in use*: the unwrapped key lives in process memory, so it is non-exportable at
rest only. That is a weaker property than `kms`, which is why it is a backend of
its own rather than a fallback inside `kms` — an operator chooses it knowingly
instead of landing on it by default.

The wrapping key is deliberately **not** the envelope key: destroying an
envelope-key version would otherwise take away the host's ability to boot, and
the two rotate on unrelated schedules.

The wrapped value is the host's identity, so it must be identical across every
replica and every restart — the `kid` the gateway pinned moves if it changes.
Producing it is the cell's provisioning, from the cell's durable seed, exactly as
seeding Vault is on the `vault` backend; this module names no command of its own.
accounts refuses a value wrapped by a different key, of the wrong size, or not in
the envelope framing, each by name.

### Why `kms` cannot hold the signing key natively yet

A Cloud KMS key cannot be exported, and three consumers are handed the signing
key rather than signing through the key service:

| Consumer | Where |
| --- | --- |
| the Work Context signer | `github.com/codefly-dev/core/workcontext`, `Authority.Key` — core also accepts an injected `Authority.Signer`; this host still passes the material |
| the delegation minter | `github.com/codefly-dev/core`, `policy.MintEd25519` |
| the OAuth state signer's seed | `pkg/auth/oauth_state.go` |

This is a dependency-injection problem, not a cryptography one: each of those
constructors takes the key *material* where it should take an injected signer.
Once they accept a `crypto.Signer`, accounts hands them the key service and the
key never leaves Cloud KMS.

Until then `KEY_SERVICE_SIGNING_BACKEND=kms` is refused by name at startup,
rather than left to surface as a Work Context authority that answers every RPC
with a configuration error and a delegation minter that silently falls back to
its v1 HMAC. The refusal names `kms-wrapped` as the shape that runs with no
secrets store today.

## Custody of the signing key

accounts **reads** the keypair; it never **owns** it. On the `vault` backend —
the only one that can hold this key today — the private half lives in Vault KV
v2 at `secret/data/jwt-signing-key`, and putting it there is the platform's
identity-seeding command's job, not this module's:

| | |
| --- | --- |
| Where the key lives | Vault KV v2, `secret/data/jwt-signing-key`, as `{"private_key": "<base64 Ed25519 seed>", "public_key": "<base64 Ed25519 public key>"}` |
| Who writes it | the cell's identity-seeding command, from the cell's durable seed, create-only |
| Who reads it | accounts, once, at boot (`pkg/auth/ed25519/vault_key.go`) |
| If it is missing | accounts refuses to boot, naming the path and the custody contract. It does **not** generate one |

**This module never names that command.** A module names nothing above it, so
the exact verb belongs to the cell's own runbook. The composition puts it in the
operator's hands by setting `VAULT_KEY_CUSTODY` in the `vault` configuration
group to the command the cell uses: accounts quotes it verbatim in the refusal,
bounded and collapsed to one line, so whoever reads the crash loop sees the
command to run rather than a sentence about one.

**Outside the local environment it is required**, and accounts refuses to start
without it, by name — on the `vault` signing backend. A Cloud KMS key version is
provisioned as cloud resources and read by name, so there is no key for an
operator to write and nothing for this diagnostic to quote; insisting on it
there would be a configuration requirement nobody could satisfy. A diagnostic that exists only when somebody remembered to
configure it is missing exactly when the incident happens, so the check runs at
boot — while a deployment can still be fixed — rather than during a crash loop.
A local run has no cell and no seeding command, so it is optional there and the
refusal points at this section instead.

The incident this exists for: an operator met `load signing key from Vault:
ed25519minter: vault http 404` with nothing on the failure path saying where the
key was supposed to come from, generated a fresh keypair by hand, and invalidated
every live session — while the durable seed and Vault then disagreed.

**accounts never mints its own key outside the local environment.** A
self-minted key would have a different `kid` from the coordinate's seed, so
every session signed under the old key stops verifying the moment the gateway
converges, two replicas that each minted one would sign differently, and the
next deliberate re-seed would silently disagree with what Vault holds. Only the
dev/fixture identity provider — which is itself refused outside the local
environment — generates a key, so `codefly run service --fixture dev-admin`
works on a machine with no Vault.

That is why a re-seed must restore the **same** keypair: the seeding command is
idempotent against the durable seed precisely so the `kid` the gateway pinned
does not move and live sessions keep verifying. Generating a fresh keypair by
hand instead invalidates every session — it is a last resort, and after it the
durable seed and Vault disagree until one is reconciled.

In the local environment the composed `vault` service seeds this path itself on
first boot, and its store is in-memory: a restart mints a new key there, which
is why that shape is refused anywhere else.

**How accounts reaches the Vault that holds it.** Outside the local environment
the composition names the cell's Vault in the `vault` configuration group and
delivers an AppRole credential through the `vault` secret group; accounts logs
in for a short-lived token of its own. Nothing in that binding is a file — the
cell's Vault listens in-mesh without TLS of its own, because in-cluster
transport security is the mesh's, so there is no CA to pin and no token to
mount. The plaintext in-cluster address is admitted by the composition's
`internal-transport/mesh-protected=true` assertion and only for an in-cluster
Service address. See
[deployment/README.md](./deployment/README.md), "The cell's Vault".

## Rotating the signing key

Each step is safe to hold indefinitely; only move on once the previous step has
converged.

1. **Generate and stage.** Create the new keypair and store its private half in
   Vault beside the current one. Nothing changes yet. (The initial seed is not a
   rotation — see "Custody of the signing key" above.)
2. **Publish.** Append the **incoming public key** to `JWT_PREVIOUS_PUBLIC_KEYS`
   and restart accounts. The JWKS now lists both keys; accounts still signs with
   the old one. Wait one gateway key-set TTL (5 min) and confirm every gateway
   serves the new document — `GET /ready` on each gateway must be 200 and
   `auth_gateway.jwks.refresh{outcome="ok"}` must be advancing.
3. **Switch signing.** Point accounts' Vault signing key at the new key, and
   move the **outgoing public key** into `JWT_PREVIOUS_PUBLIC_KEYS` (dropping the
   incoming one, which is now the signing key and is published automatically).
   Restart accounts. Both keys stay published; new tokens are signed by the new
   key, in-flight tokens still verify under the old one.
4. **Overlap.** Hold for at least the longest access-token lifetime + clock
   skew + gateway key-set TTL — with the defaults (impersonation tokens being
   the longest at 5 min), **11 minutes**; use 30 to leave room for a rolling
   restart. Every token signed by the outgoing key has expired by the end of
   it.
5. **Retire.** Remove the outgoing public key from `JWT_PREVIOUS_PUBLIC_KEYS` and
   restart accounts. Gateways converge within one TTL and reject anything still
   signed by the retired key. Revoke the retired private key in Vault.

**Rollback.** Before step 5 the outgoing key is still published, so rolling back
is step 3 in reverse: point signing back at the old key, keep both public keys
listed, restart accounts. After step 5 the retired key is gone from the
published set, so rolling back to it means republishing it (step 2 with the old
key as the incoming one) before signing with it again.

Rotating the gateway and accounts in either order is safe at every step, because
the gateway never pins a key at boot: a gateway started mid-overlap loads the
whole published set and accepts both keys regardless of the order the document
lists them in.

## One key per purpose, delivered

The signing key above is one key with one purpose. Everything else this module
signs or authenticates with carries its own **delivered** key, in a group of its
own, so rotating one rotates one thing.

Two purposes were brought under that rule by the 2026-10-04 audit: the datasource
**content-ticket** key and the **account-link state** key. Both now come from
`datasource-keys` (`DATASOURCE_CONTENT_TICKET_KEY`,
`DATASOURCE_ACCOUNT_LINK_KEY`), a group only accounts declares, instead of being
derived from a shared credential.

An absent key leaves its purpose unavailable rather than falling back to a
derivation, because a fallback would make the property conditional on nobody
forgetting. **Rotating one of these is a flag day for the tokens it signed** — an
outstanding content ticket does not survive it — which is why each purpose has its
own, so the day is one purpose wide.

The sealing keys are a separate axis and are no longer one key: a stored value
names the service that sealed it and that service's own key, and the envelope key
is per organization. Rotating and moving those is the next two sections; this one
is about the keys a purpose is DELIVERED, which rotate on their own.

## Rotating the envelope key

Unlike the signing key, this is invisible to users and needs no overlap window:
**every stored value records the key version that sealed it**, so a rotated key
never makes an existing ciphertext unreadable. On `vault`, Transit's own
`vault:v<N>:` prefix carries the version; on `kms`, the stored payload names the
key version and the key.

Rotate the key in its own service and nothing else is required. Nothing in
accounts needs restarting, and old ciphertexts keep opening under the versions
that sealed them.

### The one thing that cannot be re-keyed: the API-key hash

`api_keys.key_hash` is a **keyed hash**, and the plaintext is gone the moment the
key is issued — so there is nothing to re-hash. Lookup is *by* hash, so a key
whose hash was computed under a different key simply is not found, which is
indistinguishable from revoked.

Two consequences:

- **Do not move the MAC key version.** `KEY_SERVICE_KMS_MAC_KEY` names a
  cryptoKey**Version**, not a key, precisely so this is a deliberate edit with a
  stated consequence rather than a side effect of rotating. Vault Transit has
  the same hazard and hides it better: `transit/hmac` follows the key's latest
  version, so rotating the Transit key breaks API-key lookup there too.
- **Across a backend cutover, keys issued under the outgoing backend keep
  working only while it stays bound.** accounts looks a presented key up under
  both hashes. Once the previous backend is withdrawn, those keys stop
  authenticating and must be re-issued — so either withdraw after the keys have
  expired, or re-issue them deliberately.

## Moving the envelope key to another key service

The cutover from one backend to another — `vault` to `kms`, or one Cloud KMS key
to another. Each step is safe to hold indefinitely.

1. **Bind both.** Set `KEY_SERVICE_BACKEND` to the incoming backend and
   `KEY_SERVICE_PREVIOUS_BACKEND` to the outgoing one, and restart accounts.
   Reads work immediately — every envelope names the backend that sealed it — and
   nothing new is sealed under the outgoing one. Naming the same backend twice is
   refused: the sweep would be a no-op while reading as progress.
2. **Re-seal.** The startup sweep rewrites every enveloped column under the
   incoming backend. It runs only while a previous backend is configured, is
   restart-safe and idempotent, and does its key-service calls outside the
   database transactions. An interrupted run resumes; two replicas cannot fight
   over a row.
3. **Confirm nothing references the outgoing backend.** The sweep logs
   `re-sealed stored credentials under the selected key service` with
   `still_referencing_another_backend`. While that is true it also logs a warning
   naming the exact columns and counts. **This is the only safe signal to act
   on** — a count of what the sweep changed cannot tell "finished" from "failed
   on the first row", which is why the remaining count is reported separately.
4. **Withdraw.** With nothing remaining, clear
   `KEY_SERVICE_PREVIOUS_BACKEND` and restart. Only now remove the outgoing
   service's binding — its address and credential, or its key grant.

**Withdrawing early is the failure this sequence exists to prevent.** A value
still sealed by a backend the deployment no longer binds is refused by name
rather than mis-read, so it fails closed; but the credential is unreadable until
the backend is bound again, and for a webhook signing secret that is
unrecoverable — the consumer shares it, so the host cannot regenerate it.

**Rollback.** Before step 4, swap the two keys back and restart: the sweep then
re-seals in the other direction. After step 4 the outgoing backend is no longer
bound, so rolling back means binding it again as the previous backend first.

**If a row cannot be moved**, the sweep counts it and continues rather than
aborting, so one unreadable value does not hide the state of every other column.
Investigate the named column before withdrawing; a row sealed by a *third*
backend nobody binds is reported as `unparseable` or under its own tag.

## Availability and security tradeoff

A gateway that cannot reach the JWKS keeps serving its last good key set for
`accessJWKSCacheTTL + accessJWKSStaleGrace` (15 min with the defaults) and then
fails closed with 503. This is deliberate:

- **Availability.** An accounts restart, deploy, or brief outage must not take
  authentication down with it, and must not leave a gateway permanently unable
  to verify JWTs. A gateway that has never loaded a key set is *not ready* — it
  answers 503 on `/ready` and is not routed traffic — and it recovers on its own
  as soon as accounts answers. No operator action, no restart. A gateway that
  *has* loaded keys stays ready even once they age past the grace: it refuses
  JWTs with 503 per request, but the routes that never carried a token (the
  billing and email webhooks, `/assets`, `/.well-known`) keep being served.
  Withdrawing the whole listener because the key set aged would turn a
  degraded-authentication incident into a total one. Alert on
  `auth_gateway.jwks.refresh{outcome="error"}`, not on readiness, to catch it.
- **Security.** The grace is bounded, so it also bounds retirement: a key
  withdrawn at accounts stops verifying everywhere within 15 minutes even if
  accounts never becomes reachable again. Nothing else is relaxed — an
  unrecognised `kid` selects no key at all rather than falling back to another,
  a token whose signature does not match the key its `kid` names is refused, and
  revocation, issuer, audience, expiry, and the alg lock apply identically under
  either key. Widening the verification set never widens authorization.
- **Emergency revocation.** Because of that bound, a compromised key is not
  retired by editing the JWKS alone. Retire it *and* kill the affected sessions
  through the revocation list, which is consulted per request and is not subject
  to the key cache.

The Work Context path deliberately does not take the grace: a presented
capability is an optional attenuation the caller can retry, so it fails closed
the moment its key set expires.

Accounts' own read-backs are narrower still. A capability presented with a
question (`CheckWorkContextRecordAccess`, `ListReadableSourceCollections`, the
module-parent reads) is read back through core's `Authority.ReadBack`, which
trusts only the authority's CURRENT key id. From the moment the Work Context key
rotates, a capability signed under the previous key is refused by those
read-backs — while a consumer whose JWKS still lists the old key accepts it —
until its holder mints a new one; the capability's own lifetime
bounds the window. See `services/accounts/AGENTS.md`.

## Observability

Two counters, both with a fixed label set and no credential-derived values:

| Metric | Labels | Use |
| --- | --- | --- |
| `auth_gateway.jwks.refresh` | `key_set` = `access_token` \| `work_context`, `outcome` = `ok` \| `error` | Refresh health. A sustained `error` streak means the gateway is running on cached keys and will fail closed when the grace expires. |
| `auth_gateway.jwt.rejection` | `reason` = `keys_unavailable` \| `unknown_key_id` \| `ambiguous_key_id` \| `invalid_token` \| `revoked` \| `session_revoked` \| `revocation_unavailable` | Why tokens are being refused. `unknown_key_id` rising during a rotation means a gateway has not converged on the published set; `keys_unavailable` means it holds none at all. |

During a rotation, watch `unknown_key_id` fall to zero after step 2 before
starting step 3, and `keys_unavailable` stay at zero throughout.
