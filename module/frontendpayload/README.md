# Host frontend bundles

Accounts and the gateway share this preparer. It reads the complete signed
`application/x-tar` payload, verifies its digest, uses Core's bounded archive
extractor and snapshots private bytes before exposing a file. An unavailable or
invalid source cannot replace an already prepared bundle.

`RegistrySource` reads blobs from one operator-selected OCI repository through
ORAS. Reader credentials are values. A redirect is followed only to the
repository's own host (Artifact Registry answers every blob read that way);
redirects elsewhere and foreign authentication realms are refused. HTTPS is explicit; plain HTTP requires the mesh Service assertion
or a loopback development source. No registry is selected by default.

The Azure SDK reader also follows ACR's dedicated data-download redirect to
`<same-registry>.<region>.data.azurecr.io` over HTTPS. Only credential-free GETs
reach that endpoint; authentication and token exchanges remain on the registry
login host. The cell must admit that registry's regional data endpoint as well.

`DirectorySource` reads Codefly's existing native artifact cache, whose files are
named by the SHA-256 hex digest. It never writes a cache and is refused when the
host reports that it runs in a Pod. Neither adapter is an artifact store:
production retention and reader access remain the configured repository's duty.

Run `GOWORK=off go test -race ./...` here. These tests cover preparation and
transport; they do not qualify host activation, a browser rollout or deployment.

The supported federation profile uses `publicPath: "auto"`, a named global
remote entry, no executable public-path override and no remote dependencies.
Preparation verifies all manifest-listed synchronous/asynchronous JavaScript and
CSS, the declared expose, and client surfaces under `/assets/<bundle-file>`.
Both wire and cumulative expanded bytes are limited to 64 MiB. This checks the
producer's declared inventory; it does not analyze arbitrary JavaScript imports.
The prepared identity includes the complete signed frontend declaration.

The source is selected from the render-owned `artifact-cache` group through
`Configure`, and is never inferred or created by the host. A native process
outside a Pod reads `ROOT`, the CLI's artifact cache. A deployed Pod reads
`REPOSITORY`, the one repository the CLI's deployed render publishes every
bundle to by digest, through `NewWorkloadRegistrySource`: HTTPS, read as the
Pod's own workload identity (a labelled vendor stopgap, `workload.go`), with
no stored credential. The two values never coexist. An absent group is no
source: delivery stays pending and never falls back to a backend's mutable
asset directory. Reader access to that repository is granted to the host's
workloads by the cell's operator; retention is the repository's. A failed read
names its class (the registry's status, a missing blob, a refused redirect, or
the reader identity's refusal) and never the token or the transport's text. A
live cell read has not been qualified yet.
