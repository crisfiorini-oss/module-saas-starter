package keyservice

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	managed "github.com/codefly-dev/service-vault/keyservice"
	"github.com/stretchr/testify/require"

	"accounts/pkg/business"
)

// Only Host's adaptation is controlled here. Provider cryptography and retained
// key behavior are qualified by the runtime client's own SDK transport suite.
type projectedClient struct {
	managed.Client
	sealer  testSealer
	seed    string
	err     error
	purpose string
}

func (c *projectedClient) Tag() string      { return c.sealer.Tag() }
func (c *projectedClient) Identity() string { return c.sealer.Identity() }
func (c *projectedClient) Accepts(payload string) bool {
	return c.sealer.Accepts(Envelope{Backend: c.Tag(), Payload: payload})
}
func (c *projectedClient) Seal(ctx context.Context, purpose, value string) (string, error) {
	return c.sealer.Seal(ctx, purpose, value)
}
func (c *projectedClient) Open(ctx context.Context, purpose, value string) (string, error) {
	if c.err != nil {
		return "", c.err
	}
	return c.sealer.Open(ctx, purpose, value)
}
func (c *projectedClient) MAC(ctx context.Context, value string) (string, error) {
	return c.sealer.MAC(ctx, value)
}
func (c *projectedClient) Unwrap(_ context.Context, purpose, _ string) (string, error) {
	c.purpose = purpose
	return c.seed, c.err
}
func (c *projectedClient) ForKey(_ context.Context, key string) (managed.Client, error) {
	return &projectedClient{sealer: testSealer{tag: c.Tag(), key: key}}, nil
}

func TestManagedSealerRetainsHostFramingAndErrorSemantics(t *testing.T) {
	client := &projectedClient{sealer: testSealer{tag: "managed-test", key: "deployment"}}
	sealer := managedSealer{client}
	cipher, err := NewCipher(sealer, nil)
	require.NoError(t, err)
	stored, err := cipher.EncryptSecret(t.Context(), "row", "credential")
	require.NoError(t, err)
	require.True(t, IsEnvelopeFraming(stored))
	parsed, err := ParseEnvelope(stored)
	require.NoError(t, err)
	require.Equal(t, "managed-test", parsed.Backend)
	opened, err := cipher.DecryptSecret(t.Context(), "row", stored)
	require.NoError(t, err)
	require.Equal(t, "credential", opened)
	hash, err := sealer.MAC(t.Context(), "api-key")
	require.NoError(t, err)
	require.Equal(t, "cfs1:managed-test:deployment:api-key", hash)
	org, err := sealer.SealerFor(t.Context(), "organization")
	require.NoError(t, err)
	require.NotEqual(t, sealer.Identity(), org.Identity())
	client.err = managed.ErrInvalidCiphertext
	_, err = cipher.DecryptSecret(t.Context(), "row", stored)
	require.ErrorIs(t, err, business.ErrInvalidSecretEnvelope)
	client.err = errors.New("provider unavailable")
	_, err = cipher.DecryptSecret(t.Context(), "row", stored)
	require.ErrorIs(t, err, client.err)
	require.NotErrorIs(t, err, business.ErrInvalidSecretEnvelope)
}

func TestManagedWrappedSigningPreservesExistingEd25519Contract(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 19
	client := &projectedClient{sealer: testSealer{tag: "managed-test"}, seed: base64.StdEncoding.EncodeToString(seed)}
	binding := &Binding{SigningBackend: BackendKMSWrapped, managed: client, wrappedSigningKey: "cfs1:managed-test:opaque"}
	key, err := binding.SigningKey(t.Context(), false)
	require.NoError(t, err)
	require.Equal(t, ed25519.NewKeyFromSeed(seed), key)
	require.Equal(t, signingKeyWrapPurpose, client.purpose)
	again, err := binding.SigningKey(t.Context(), false)
	require.NoError(t, err)
	require.Equal(t, key, again)
	client.err = errors.New("access revoked")
	_, err = binding.SigningKey(t.Context(), true)
	require.ErrorIs(t, err, client.err)
	require.NotErrorIs(t, err, ErrNoSigningKey, "managed custody must never permit ephemeral fallback")
	client.err = nil
	client.seed = base64.StdEncoding.EncodeToString([]byte("short"))
	_, err = binding.SigningKey(t.Context(), false)
	require.Error(t, err)
	binding.wrappedSigningKey = "cfs1:other:opaque"
	_, err = binding.SigningKey(t.Context(), false)
	require.Error(t, err)
}

func TestManagedSelectionRefusesMixedBindingsBeforeProviderAccess(t *testing.T) {
	t.Setenv(BackendKey, "kms")
	t.Setenv(SigningBackendKey, "kms-wrapped")
	t.Setenv(ManagedBindingKey, `{"provider":"unreachable"}`)
	t.Setenv(KMSEnvelopeKeyKey, "legacy-key")
	_, err := Load(t.Context())
	require.ErrorContains(t, err, "legacy KMS")
	t.Setenv(KMSEnvelopeKeyKey, "")
	t.Setenv(SigningKeyWrappedKey, "")
	_, err = Load(t.Context())
	require.ErrorContains(t, err, SigningKeyWrappedKey)
}
