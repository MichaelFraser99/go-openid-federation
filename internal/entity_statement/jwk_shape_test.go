package entity_statement

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwk"
	josemodel "github.com/MichaelFraser99/go-jose/model"
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
		{name: "kty that is a number", reference: "RFC 7517 4.1", key: map[string]any{"kty": 7}, expectErr: "'kty' claim"},
		{name: "kty that is an object", reference: "RFC 7517 4.1", key: map[string]any{"kty": map[string]any{}}, expectErr: "'kty' claim"},
		{name: "kty that is absent", reference: "RFC 7517 4.1", key: map[string]any{"kid": "a"}, expectErr: "'kty' claim"},
		{name: "kty that is empty", reference: "RFC 7517 4.1", key: map[string]any{"kty": ""}, expectErr: "'kty' claim"},
		{name: "an EC key with no crv", reference: "RFC 7518 6.2.1.1", key: map[string]any{"kty": "EC"}, expectErr: "'crv' claim"},
		{name: "an EC key with a numeric crv", reference: "RFC 7518 6.2.1.1", key: map[string]any{"kty": "EC", "crv": 7}, expectErr: "'crv' claim"},
		{name: "an EC key with an empty crv", reference: "RFC 7518 6.2.1.1", key: map[string]any{"kty": "EC", "crv": ""}, expectErr: "'crv' claim"},
		{name: "a non-EC key with a numeric crv", reference: "RFC 7517 4.1", key: map[string]any{"kty": "OKP", "crv": 7}, expectErr: "'crv' claim"},
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

func TestSelectKey_RefusesAMalformedKeyShapeWithoutPanicking(t *testing.T) {
	tests := []struct {
		name string
		key  map[string]any
	}{
		{name: "kty that is a number", key: map[string]any{"kid": "a", "kty": 7}},
		{name: "kty that is an object", key: map[string]any{"kid": "a", "kty": map[string]any{}}},
		{name: "an EC key with no crv", key: map[string]any{"kid": "a", "kty": "EC", "x": "AQAB", "y": "AQAB"}},
		{name: "an EC key with a numeric crv", key: map[string]any{"kid": "a", "kty": "EC", "crv": 7, "x": "AQAB", "y": "AQAB"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("a peer supplied key shape panicked key selection: %v", r)
				}
			}()
			selected, err := SelectKey(josemodel.Jwks{Keys: []map[string]any{tc.key}}, "a")
			if err == nil {
				t.Fatalf("expected a malformed key shape to be refused, got %v", selected)
			}
			if !strings.Contains(err.Error(), "the selected key in the included 'jwks'") {
				t.Fatalf("expected the error to name the selected key, got %v", err)
			}
		})
	}
}

func TestSelectKey_AcceptsRealKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  map[string]any
	}{
		{name: "a real P-256 key", key: realJWK(t, elliptic.P256(), false)},
		{name: "a real RSA key", key: realJWK(t, nil, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := tc.key
			key["kid"] = "a"
			if _, err := SelectKey(josemodel.Jwks{Keys: []map[string]any{key}}, "a"); err != nil {
				t.Fatalf("expected a real published key to be selected, got %v", err)
			}
		})
	}
}

func TestExtractDetails_RefusesNonStringClaims(t *testing.T) {
	tests := []struct {
		name      string
		head      map[string]any
		body      map[string]any
		expectErr string
	}{
		{
			name:      "a conforming statement",
			head:      map[string]any{"kid": "a"},
			body:      map[string]any{"iss": "https://leaf.example.com", "sub": "https://leaf.example.com"},
			expectErr: "",
		},
		{name: "kid that is a number", head: map[string]any{"kid": 1}, body: map[string]any{"iss": "https://a.example.com", "sub": "https://a.example.com"}, expectErr: "'kid' claim"},
		{name: "sub that is a number", head: map[string]any{"kid": "a"}, body: map[string]any{"iss": "https://a.example.com", "sub": 1}, expectErr: "'sub' claim"},
		{name: "sub that is an array", head: map[string]any{"kid": "a"}, body: map[string]any{"iss": "https://a.example.com", "sub": []any{"https://a.example.com"}}, expectErr: "'sub' claim"},
		{name: "iss that is an object", head: map[string]any{"kid": "a"}, body: map[string]any{"iss": map[string]any{}, "sub": "https://a.example.com"}, expectErr: "'iss' claim"},
		{name: "kid that is absent", head: map[string]any{}, body: map[string]any{"iss": "https://a.example.com", "sub": "https://a.example.com"}, expectErr: "'kid' claim"},
		{name: "iss that is absent", head: map[string]any{"kid": "a"}, body: map[string]any{"sub": "https://a.example.com"}, expectErr: "'iss' claim"},
		{name: "sub that is absent", head: map[string]any{"kid": "a"}, body: map[string]any{"iss": "https://a.example.com"}, expectErr: "'sub' claim"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("a non-string claim panicked detail extraction: %v", r)
				}
			}()

			kid, subject, issuer, err := ExtractDetails(unsignedToken(t, tc.head, tc.body))

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("expected the statement to be read, got %v", err)
				}
				if *kid != "a" || *subject != "https://leaf.example.com" || *issuer != "https://leaf.example.com" {
					t.Errorf("expected the claims to be returned, got kid %q sub %q iss %q", *kid, *subject, *issuer)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error naming %s, got kid %v", tc.expectErr, kid)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("expected an error naming %s, got %v", tc.expectErr, err)
			}
		})
	}
}
