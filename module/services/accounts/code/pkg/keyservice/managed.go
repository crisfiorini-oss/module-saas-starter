package keyservice

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	managed "github.com/codefly-dev/service-vault/keyservice"

	"accounts/pkg/business"
)

// ManagedBindingKey is the non-secret installation projected by the key-service
// owner. Provider drivers live in that owner's runtime client, never in Host.
const ManagedBindingKey = "KEY_SERVICE_MANAGED_BINDING"

type managedSealer struct{ managed.Client }

func (s managedSealer) Accepts(e Envelope) bool {
	return e.Backend == s.Tag() && s.Client.Accepts(e.Payload)
}

func (s managedSealer) Open(ctx context.Context, purpose, payload string) (string, error) {
	value, err := s.Client.Open(ctx, purpose, payload)
	if errors.Is(err, managed.ErrInvalidCiphertext) {
		return "", fmt.Errorf("%w: %w", business.ErrInvalidSecretEnvelope, err)
	}
	return value, err
}

func (s managedSealer) MAC(ctx context.Context, value string) (string, error) {
	hash, err := s.Client.MAC(ctx, value)
	if err != nil {
		return "", err
	}
	return (Envelope{Backend: s.Tag(), Payload: hash}).String(), nil
}

func (s managedSealer) SealerFor(ctx context.Context, key string) (Sealer, error) {
	client, err := s.Client.ForKey(ctx, key)
	if err != nil {
		return nil, err
	}
	return managedSealer{client}, nil
}

func managedSigningKey(ctx context.Context, client managed.Client, value string) (ed25519.PrivateKey, error) {
	envelope, err := ParseEnvelope(value)
	if err != nil {
		return nil, err
	}
	if envelope.Backend != client.Tag() {
		return nil, errors.New("wrapped signing key belongs to another key service")
	}
	encoded, err := client.Unwrap(ctx, signingKeyWrapPurpose, envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("unwrap managed signing key: %w", err)
	}
	seed, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("managed signing key must unwrap to a base64 Ed25519 seed")
	}
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}

var _ Sealer = managedSealer{}
var _ KeyFactory = managedSealer{}
