package keyservice

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"

	codefly "github.com/codefly-dev/sdk-go"
	managed "github.com/codefly-dev/service-vault/keyservice"

	"accounts/pkg/vaultconnection"
)

// ConfigurationGroup is the workspace group that selects the key service.
const ConfigurationGroup = "key-service"

// The keys the group carries. Values only: a key NAME is not a secret, and the
// point of the `kms` backend is that there is no credential to deliver.
const (
	// BackendKey selects the backend that seals stored credentials and computes
	// the keyed hash. Required outside the local environment.
	BackendKey = "KEY_SERVICE_BACKEND"
	// PreviousBackendKey names the backend a cutover is migrating away from. It
	// is accepted on READ only — nothing new is sealed under it — and is
	// withdrawn once no stored value references it.
	PreviousBackendKey = "KEY_SERVICE_PREVIOUS_BACKEND"
	// SigningBackendKey selects the backend that holds the access-token signing
	// key. It defaults to BackendKey.
	//
	// The two families are selected separately because they move separately: an
	// envelope key is migrated by re-sealing, which is reversible and invisible
	// to users, while replacing the signing key either re-logs everyone in or
	// needs both keys published across the cutover. A deployment that has to do
	// one of those today and the other next quarter can say so.
	SigningBackendKey = "KEY_SERVICE_SIGNING_BACKEND"

	KMSEnvelopeKeyKey = "KEY_SERVICE_KMS_ENVELOPE_KEY"
	KMSMACKeyKey      = "KEY_SERVICE_KMS_MAC_KEY"
	// KMSSigningWrapKeyKey names the symmetric key that unwraps the signing key
	// on the `kms-wrapped` signing backend.
	KMSSigningWrapKeyKey = "KEY_SERVICE_KMS_SIGNING_WRAP_KEY"
	// SigningKeyWrappedKey carries the wrapped signing key itself, as a VALUE.
	// It is a ciphertext, inert without the Cloud KMS key above and the workload
	// identity that reaches it, so it is not a credential delivered to the pod —
	// which is the whole point: no secrets store, and nothing stored that is a
	// secret on its own.
	SigningKeyWrappedKey = "KEY_SERVICE_SIGNING_KEY_WRAPPED"
)

// Binding is the key service this deployment resolved: the cipher every
// stored-credential caller is wired to, and enough of the selection to build
// the signing family and to register a health probe for a backend that needs
// one.
type Binding struct {
	// Backend seals; Previous is accepted on read during a cutover, or "".
	Backend, Previous Backend
	// SigningBackend holds the access-token signing key.
	SigningBackend Backend
	Cipher         *Cipher

	// Vault is the Vault connection this binding opened, or nil when no family
	// selected Vault. A deployment on `kms` for both families has none: no
	// address, no AppRole credential, and no Vault health probe to register.
	Vault *vaultconnection.Connection
	// VaultHealth probes the Vault that holds the envelope key, or nil.
	VaultHealth func(ctx context.Context) error

	kms     KMSConfig
	managed managed.Client
	// wrappedSigningKey is the configured ciphertext, read once at selection so
	// a missing one refuses with every other configuration problem rather than
	// after a key service has already been reached.
	wrappedSigningKey string
}

// Selected is what the `key-service` group says, with nothing bound yet.
type Selected struct {
	Backend, Previous, SigningBackend Backend
}

// Selection reads and validates the selection without reaching any key service.
//
// It is separate from Load so the boot gate can run it before the process has
// acquired anything at all: a deployment that named no backend, or named one
// twice, is told so while it can still be fixed rather than after a database
// pool, a cache and a job runtime are already up.
func Selection(ctx context.Context, local bool) (Selected, error) {
	backend, err := selectedBackend(ctx, BackendKey, local)
	if err != nil {
		return Selected{}, err
	}
	selection := Selected{Backend: backend, SigningBackend: backend}
	if named := groupValue(ctx, SigningBackendKey); named != "" {
		if selection.SigningBackend, err = ParseBackend(named); err != nil {
			return Selected{}, fmt.Errorf("%s: %w", SigningBackendKey, err)
		}
	}
	if selection.SigningBackend == BackendKMS {
		// Named here rather than discovered at the first request. Three
		// consumers are handed the signing key and sign on their own: the Work
		// Context authority (core's workcontext.Authority, which can take an
		// injected crypto.Signer but is handed the key by this host), the
		// delegation minter (core's policy.MintEd25519, which takes an
		// ed25519.PrivateKey) and the OAuth state signer's seed. A key that
		// cannot be exported leaves the Work Context authority answering every
		// RPC with a configuration error and the delegation minter silently
		// falling back to its v1 HMAC. Refusing the selection is the honest
		// answer until each of the three is given a signer to call.
		return Selected{}, fmt.Errorf("%s=%s is not supported yet: a Cloud KMS key cannot be exported, and three consumers are HANDED the signing key rather than given a signer to call: the Work Context authority (github.com/codefly-dev/core workcontext.Authority accepts an injected crypto.Signer, but this host does not wire one yet), the delegation minter (github.com/codefly-dev/core policy.MintEd25519) and the OAuth state signer. Use %s=%s to run with no secrets store today — the key is wrapped by a Cloud KMS key and unwrapped at boot, which is non-exportable at rest rather than in use — or %s=%s to keep it in Vault",
			SigningBackendKey, BackendKMS, SigningBackendKey, BackendKMSWrapped, SigningBackendKey, BackendVault)
	}
	if named := groupValue(ctx, PreviousBackendKey); named != "" {
		if selection.Previous, err = ParseBackend(named); err != nil {
			return Selected{}, fmt.Errorf("%s: %w", PreviousBackendKey, err)
		}
		if selection.Previous == backend {
			return Selected{}, fmt.Errorf("%s and %s are both %q: a cutover has two backends, and naming one twice would make the sweep that re-seals every stored credential a no-op while reading as progress", BackendKey, PreviousBackendKey, backend)
		}
	}
	return selection, nil
}

// Load resolves the key service from the `key-service` configuration group.
//
// Every refusal names the key that is missing or wrong, and every one of them
// happens here — before the process acquires anything — so a deployment that
// cannot work is rejected while it can still be fixed rather than discovered
// from a crash loop or, worse, from the first MFA enrolment that fails.
func Load(ctx context.Context) (*Binding, error) {
	selection, err := Selection(ctx, codefly.IsLocal())
	if err != nil {
		return nil, err
	}
	backend, previous, signing := selection.Backend, selection.Previous, selection.SigningBackend

	binding := &Binding{
		Backend: backend, Previous: previous, SigningBackend: signing,
		wrappedSigningKey: groupValue(ctx, SigningKeyWrappedKey),
	}
	descriptor := groupValue(ctx, ManagedBindingKey)
	usesManaged := backend == BackendKMS || previous == BackendKMS || signing == BackendKMSWrapped
	if descriptor != "" {
		if !usesManaged {
			return nil, errors.New("managed key-service binding requires a kms consumer")
		}
		for _, key := range []string{KMSEnvelopeKeyKey, KMSMACKeyKey, KMSSigningWrapKeyKey} {
			if groupValue(ctx, key) != "" {
				return nil, errors.New("managed key-service binding cannot be combined with legacy KMS key names")
			}
		}
		if signing == BackendKMSWrapped && binding.wrappedSigningKey == "" {
			return nil, fmt.Errorf("%s is required for wrapped signing", SigningKeyWrappedKey)
		}
		if binding.managed, err = managed.New(ctx, descriptor); err != nil {
			return nil, err
		}
	} else if usesManaged {
		if binding.kms, err = kmsConfig(ctx, backend, previous, signing); err != nil {
			return nil, err
		}
	}

	seal, err := binding.sealer(ctx, backend)
	if err != nil {
		return nil, err
	}
	var previousSealer Sealer
	if previous != "" {
		if previousSealer, err = binding.sealer(ctx, previous); err != nil {
			return nil, fmt.Errorf("bind the previous key-service backend %q: %w", previous, err)
		}
	}
	if binding.Cipher, err = NewCipher(seal, previousSealer); err != nil {
		return nil, err
	}
	return binding, nil
}

// sealer binds one backend, reusing the Vault connection across families so a
// deployment that selected Vault twice logs in once.
func (b *Binding) sealer(ctx context.Context, backend Backend) (Sealer, error) {
	switch backend {
	case BackendVault:
		connection, err := b.vaultConnection(ctx)
		if err != nil {
			return nil, err
		}
		sealer := &VaultSealer{address: connection.Address, connection: connection, client: connection.Client}
		if b.VaultHealth == nil {
			b.VaultHealth = sealer.Health
		}
		return sealer, nil
	case BackendKMS:
		if b.managed != nil {
			return managedSealer{b.managed}, nil
		}
		return NewKMSSealer(ctx, b.kms)
	default:
		return nil, fmt.Errorf("unsupported key-service backend %q", backend)
	}
}

func (b *Binding) vaultConnection(ctx context.Context) (*vaultconnection.Connection, error) {
	if b.Vault != nil {
		return b.Vault, nil
	}
	connection, err := vaultconnection.Load(ctx)
	if err != nil {
		return nil, err
	}
	b.Vault = connection
	return connection, nil
}

// SigningKey returns the Ed25519 signing key from the backend selected for it.
//
// The key service owns this key's CUSTODY — which service holds it, and the
// refusal when that service cannot answer — but not the signing. The material
// stays in this process because three consumers are handed the key and sign on
// their own; ReadVaultSigningKey says which, and Selection refuses a backend
// that cannot export rather than letting them fail one at a time.
//
// ephemeral is set only for the dev/fixture identity provider in a local run,
// where a freshly generated key lets `codefly run service --fixture dev-admin`
// work on a machine with no Vault. Everywhere else a signing key that cannot be
// loaded is a refusal: an ephemeral one would make each replica sign
// differently, break every existing session, and desynchronise the `kid` the
// gateway pinned.
func (b *Binding) SigningKey(ctx context.Context, ephemeral bool) (ed25519.PrivateKey, error) {
	if b.SigningBackend == BackendKMSWrapped {
		if b.managed != nil {
			return managedSigningKey(ctx, b.managed, b.wrappedSigningKey)
		}
		wrap, err := NewKMSKeyWrap(ctx, b.kms)
		if err != nil {
			return nil, err
		}
		// No ephemeral fallback here even locally: the wrapped key and the key
		// that unwraps it are both configuration, so a failure is a
		// configuration answer the operator can act on, not an absent dependency
		// a developer machine might legitimately lack.
		return wrap.UnwrapSigningKey(ctx, b.wrappedSigningKey)
	}
	if b.SigningBackend != BackendVault {
		return nil, fmt.Errorf("unsupported key-service signing backend %q", b.SigningBackend)
	}
	connection, err := b.vaultConnection(ctx)
	if err != nil {
		if ephemeral {
			return nil, fmt.Errorf("%w: no usable Vault binding: %w", ErrNoSigningKey, err)
		}
		return nil, fmt.Errorf("load signing key: no usable Vault binding for secret/data/jwt-signing-key: %w", err)
	}
	private, err := ReadVaultSigningKey(ctx, connection)
	if err == nil {
		return private, nil
	}
	if ephemeral {
		// The cause travels with the sentinel: a local developer whose Vault is
		// misconfigured has to be told WHY it did not answer, or the fallback
		// is diagnosed by guessing.
		return nil, fmt.Errorf("%w: %w", ErrNoSigningKey, err)
	}
	return nil, fmt.Errorf("load signing key from Vault at secret/data/jwt-signing-key: %w", err)
}

// ErrNoSigningKey reports that no key was loaded and the caller was allowed to
// generate one. It wraps the underlying cause, and is returned only where a
// local run already asked for that, so a caller that mints a key on it cannot be
// reached from a deployment.
var ErrNoSigningKey = errors.New("key service: no signing key is bound")

// GenerateSigningKey mints a keypair for the local dev fixture.
func GenerateSigningKey() (ed25519.PrivateKey, error) {
	_, private, err := ed25519.GenerateKey(nil)
	return private, err
}

func selectedBackend(ctx context.Context, key string, local bool) (Backend, error) {
	named := groupValue(ctx, key)
	if named == "" {
		if !local {
			return "", fmt.Errorf("%s is required outside the local environment: select %s in the `%s` configuration group. The two backends have opposite custody models — `vault` runs a stateful secrets store the cell credentials and unseals, `kms` uses the cell's cloud key service with non-exportable keys and the workload's own identity — so an unstated one is refused rather than defaulted into either", key, joinBackends(), ConfigurationGroup)
		}
		return BackendVault, nil
	}
	backend, err := ParseBackend(named)
	if err != nil {
		return "", fmt.Errorf("%s: %w", key, err)
	}
	return backend, nil
}

func kmsConfig(ctx context.Context, backend, previous, signing Backend) (KMSConfig, error) {
	config := KMSConfig{
		EnvelopeKey:    groupValue(ctx, KMSEnvelopeKeyKey),
		MACKey:         groupValue(ctx, KMSMACKeyKey),
		SigningWrapKey: groupValue(ctx, KMSSigningWrapKeyKey),
	}
	var missing []string
	if signing == BackendKMSWrapped {
		if config.SigningWrapKey == "" {
			missing = append(missing, KMSSigningWrapKeyKey)
		}
		if strings.TrimSpace(groupValue(ctx, SigningKeyWrappedKey)) == "" {
			missing = append(missing, SigningKeyWrappedKey)
		}
	}
	if (backend == BackendKMS || previous == BackendKMS) && config.EnvelopeKey == "" {
		missing = append(missing, KMSEnvelopeKeyKey)
	}
	if (backend == BackendKMS || previous == BackendKMS) && config.MACKey == "" {
		missing = append(missing, KMSMACKeyKey)
	}
	if len(missing) > 0 {
		return KMSConfig{}, fmt.Errorf("the `kms` key-service backend requires %s in the `%s` configuration group: it reads key names and nothing else, so a missing name is the whole binding rather than a default to fall back on", strings.Join(missing, " and "), ConfigurationGroup)
	}
	return config, nil
}

// groupValue reads one key of the `key-service` group, falling back to a plain
// process variable exactly as the rest of accounts' workspace reads do.
func groupValue(ctx context.Context, key string) string {
	value, err := codefly.For(ctx).WorkspaceValue(ConfigurationGroup, key)
	if err != nil || value == "" {
		value = os.Getenv(key)
	}
	return strings.TrimSpace(value)
}
