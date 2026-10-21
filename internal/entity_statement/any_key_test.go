package entity_statement

import (
	"crypto"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
)

func anyKeySign(t *testing.T, signer crypto.Signer, kid string) string {
	t.Helper()
	token, err := jwt.New(signer, map[string]any{"kid": kid, "typ": "entity-statement+jwt", "alg": "RS256"}, map[string]any{"iss": "https://leaf.example.com"}, jwt.Opts{Algorithm: josemodel.RS256})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	return *token
}

func TestVerifyAgainstAnyKey(t *testing.T) {
	key := selectorKey(t)
	other := selectorKey(t)
	token := anyKeySign(t, key, "leaf")

	labelled := func(kid string) map[string]any { return selectorJwk(t, key.Public(), kid) }

	tests := []struct {
		name      string
		reference string
		keys      []map[string]any
		expectErr string
	}{
		{
			name:      "the signing key under the kid the header names",
			reference: "10.2",
			keys:      []map[string]any{labelled("leaf")},
		},
		{
			name:      "the signing key under a label of the operator's own",
			reference: "RFC 7517 4.5",
			keys:      []map[string]any{labelled("operator-local-label")},
		},
		{
			name:      "the signing key with no kid at all",
			reference: "RFC 7517 4.5",
			keys: []map[string]any{func() map[string]any {
				published := labelled("leaf")
				delete(published, "kid")
				return published
			}()},
		},
		{
			name:      "the signing key held after another entity's key",
			reference: "10.2",
			keys:      []map[string]any{selectorJwk(t, other.Public(), "first"), labelled("second")},
		},
		{
			name:      "the signing key held after a key with no kid",
			reference: "RFC 7517 5",
			keys:      []map[string]any{{"kty": "RSA", "n": "AQAB", "e": "AQAB"}, labelled("leaf")},
		},
		{
			name:      "the signing key held after a key of a type this library cannot use",
			reference: "RFC 7517 5",
			keys:      []map[string]any{{"kid": "pq", "kty": "ML-DSA-44", "pk": "AQAB"}, labelled("leaf")},
		},
		{
			name:      "only another entity's key",
			reference: "10.2",
			keys:      []map[string]any{selectorJwk(t, other.Public(), "other")},
			expectErr: "no key in the key set verifies the signature",
		},
		{
			name:      "only keys this library cannot use",
			reference: "RFC 7517 5",
			keys:      []map[string]any{{"kid": "pq", "kty": "ML-DSA-44", "pk": "AQAB"}, {"kid": "broken"}},
			expectErr: "no key in the key set can verify a signature made with this token's 'alg'",
		},
		{
			name:      "the signing key held after a key whose kty is not a string",
			reference: "RFC 7517 4.1",
			keys:      []map[string]any{{"kid": "folded", "kty": map[string]any{"RSA": true}}, labelled("leaf")},
		},
		{
			name:      "the signing key held after a key whose kty is a number",
			reference: "RFC 7517 4.1",
			keys:      []map[string]any{{"kid": "numeric", "kty": 1}, labelled("leaf")},
		},
		{
			name:      "only a key whose kty is not a string",
			reference: "RFC 7517 4.1",
			keys:      []map[string]any{{"kid": "folded", "kty": []any{"RSA"}}},
			expectErr: "no key in the key set can verify a signature made with this token's 'alg'",
		},
		{
			name:      "an empty key set",
			reference: "RFC 7517 5",
			keys:      nil,
			expectErr: "no key in the key set can verify a signature made with this token's 'alg'",
		},
		{
			name:      "only the signing key published for another algorithm",
			reference: "RFC 7517 4.4",
			keys: []map[string]any{func() map[string]any {
				published := labelled("leaf")
				published["alg"] = "PS256"
				return published
			}()},
			expectErr: "no key in the key set can verify a signature made with this token's 'alg'",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("[%s] a key this library cannot judge must not panic: %v", tc.reference, recovered)
				}
			}()
			err := VerifyAgainstAnyKey(token, josemodel.Jwks{Keys: tc.keys})
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the signature to verify against a key in the set, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the signature to be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}
