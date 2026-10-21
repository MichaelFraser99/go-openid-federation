package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwk"
)

func realJWK(t *testing.T, curve elliptic.Curve, useRSA bool) map[string]any {
	t.Helper()
	if useRSA {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		published, err := jwk.PublicJwk(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		return *published
	}
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	published, err := jwk.PublicJwk(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return *published
}

func TestValidateJWKShape(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		key       map[string]any
		expectErr string
	}{
		{name: "a real P-256 key", reference: "RFC 7518 6.2.1.1", key: realJWK(t, elliptic.P256(), false)},
		{name: "a real P-384 key", reference: "RFC 7518 6.2.1.1", key: realJWK(t, elliptic.P384(), false)},
		{name: "a real RSA key", reference: "RFC 7518 6.3.1", key: realJWK(t, nil, true)},
		{name: "kty that is a number", reference: "RFC 7517 4.1", key: map[string]any{"kty": 7}, expectErr: "'kty' member"},
		{name: "kty that is an object", reference: "RFC 7517 4.1", key: map[string]any{"kty": map[string]any{}}, expectErr: "'kty' member"},
		{name: "kty that is absent", reference: "RFC 7517 4.1", key: map[string]any{"kid": "a"}, expectErr: "'kty' member"},
		{name: "kty that is empty", reference: "RFC 7517 4.1", key: map[string]any{"kty": ""}, expectErr: "'kty' member"},
		{name: "an EC key with no crv", reference: "RFC 7518 6.2.1.1", key: map[string]any{"kty": "EC"}, expectErr: "'crv' member"},
		{name: "an EC key with a numeric crv", reference: "RFC 7518 6.2.1.1", key: map[string]any{"kty": "EC", "crv": 7}, expectErr: "'crv' member"},
		{name: "an EC key with an empty crv", reference: "RFC 7518 6.2.1.1", key: map[string]any{"kty": "EC", "crv": ""}, expectErr: "'crv' member"},
		{name: "a non-EC key with a numeric crv is ignored", reference: "RFC 7517 4", key: map[string]any{"kty": "OKP", "crv": 7}},
		{name: "an RSA key with a null crv is ignored", reference: "RFC 7517 4", key: map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB", "crv": nil}},
		{name: "an RSA key with no crv is fine", reference: "RFC 7518 6.3.1", key: map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB"}},
		{name: "an OKP key with a string crv is fine", reference: "RFC 8037 2", key: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AQAB"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateJWKShape(tc.key)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the key shape to be accepted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected an error naming %s, got an accepted key", tc.reference, tc.expectErr)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error naming %s, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}
