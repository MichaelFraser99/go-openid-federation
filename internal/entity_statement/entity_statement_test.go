package entity_statement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
)

func selectorKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

func selectorJwk(t *testing.T, pub crypto.PublicKey, kid any) map[string]any {
	t.Helper()
	publicJWK, err := jwk.PublicJwk(pub)
	if err != nil {
		t.Fatalf("failed to build public jwk: %v", err)
	}
	if kid == nil {
		delete(*publicJWK, "kid")
	} else {
		(*publicJWK)["kid"] = kid
	}
	(*publicJWK)["alg"] = "RS256"
	return *publicJWK
}

func TestSelectKey(t *testing.T) {
	key := selectorKey(t)
	other := selectorKey(t)

	tests := []struct {
		name      string
		keys      []map[string]any
		kid       string
		expectErr string
	}{
		{
			name: "a matching kid selects the key",
			keys: []map[string]any{selectorJwk(t, key.Public(), "a")},
			kid:  "a",
		},
		{
			name:      "an empty kid is refused",
			keys:      []map[string]any{selectorJwk(t, key.Public(), "")},
			kid:       "",
			expectErr: "non-empty string",
		},
		{
			name:      "an entry without a kid is refused",
			keys:      []map[string]any{selectorJwk(t, key.Public(), nil)},
			kid:       "a",
			expectErr: "missing the mandatory 'kid' claim",
		},
		{
			name:      "an entry with a non-string kid is refused",
			keys:      []map[string]any{selectorJwk(t, key.Public(), 7)},
			kid:       "a",
			expectErr: "malformed 'kid' claim",
		},
		{
			name: "duplicate kid values are refused",
			keys: []map[string]any{
				selectorJwk(t, key.Public(), "a"),
				selectorJwk(t, other.Public(), "a"),
			},
			kid:       "a",
			expectErr: "unique 'kid' values",
		},
		{
			name:      "an empty key set is refused",
			keys:      []map[string]any{},
			kid:       "a",
			expectErr: "contains no usable keys",
		},
		{
			name:      "a kid absent from the set is refused",
			keys:      []map[string]any{selectorJwk(t, key.Public(), "a")},
			kid:       "b",
			expectErr: "no usable key with that 'kid'",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			selected, err := SelectKey(josemodel.Jwks{Keys: tc.keys}, tc.kid)
			if tc.expectErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got key %v", tc.expectErr, selected)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("expected an error containing %q, got %v", tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if selected["kid"] != tc.kid {
				t.Errorf("expected the key with kid %q, got %v", tc.kid, selected["kid"])
			}
		})
	}
}

func TestVerifyAgainstJwks(t *testing.T) {
	key := selectorKey(t)
	attacker := selectorKey(t)

	published := josemodel.Jwks{Keys: []map[string]any{selectorJwk(t, key.Public(), "a")}}
	body := map[string]any{"iss": "https://leaf.example.com", "sub": "https://leaf.example.com"}

	sign := func(t *testing.T, signer crypto.Signer, head map[string]any) string {
		t.Helper()
		token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: jwa.RS256})
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}
		return *token
	}

	tests := []struct {
		name      string
		head      map[string]any
		signer    crypto.Signer
		kid       string
		expectErr bool
	}{
		{
			name:   "a signature by the published key verifies",
			head:   map[string]any{"kid": "a", "alg": "RS256"},
			signer: key,
			kid:    "a",
		},
		{
			name:      "a signature by another key is refused",
			head:      map[string]any{"kid": "a", "alg": "RS256"},
			signer:    attacker,
			kid:       "a",
			expectErr: true,
		},
		{
			name:      "a key supplied in the jwk header is not trusted",
			head:      map[string]any{"kid": "a", "alg": "RS256", "jwk": selectorJwk(t, attacker.Public(), "a")},
			signer:    attacker,
			kid:       "a",
			expectErr: true,
		},
		{
			name:      "a kid absent from the published set is refused",
			head:      map[string]any{"kid": "b", "alg": "RS256"},
			signer:    key,
			kid:       "b",
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyAgainstJwks(sign(t, tc.signer, tc.head), tc.kid, published)
			if tc.expectErr && err == nil {
				t.Fatal("expected verification to fail")
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("expected verification to succeed, got %v", err)
			}
		})
	}
}

func TestVerifyAgainstJwks_HonoursTheAlgorithmThePublishedKeyIsFor(t *testing.T) {
	key := selectorKey(t)
	body := map[string]any{"iss": "https://leaf.example.com", "sub": "https://leaf.example.com"}

	tests := []struct {
		name      string
		reference string
		keyAlg    any
		expectErr string
	}{
		{name: "a key published for the algorithm that signed", reference: "RFC 7517 4.4", keyAlg: "RS256"},
		{name: "a key published for no algorithm is unconstrained", reference: "RFC 7517 4.4", keyAlg: nil},
		{name: "a key published for another algorithm", reference: "RFC 7517 4.4", keyAlg: "PS256", expectErr: "does not match the 'alg' the selected key"},
		{name: "a key whose alg is not a string", reference: "RFC 7517 4.4", keyAlg: 7, expectErr: "malformed 'alg' member"},
		{name: "a key whose alg is empty", reference: "RFC 7517 4.4", keyAlg: "", expectErr: "malformed 'alg' member"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			publishedKey := selectorJwk(t, key.Public(), "a")
			if tc.keyAlg == nil {
				delete(publishedKey, "alg")
			} else {
				publishedKey["alg"] = tc.keyAlg
			}

			token, err := jwt.New(key, map[string]any{"kid": "a", "alg": "RS256"}, body, jwt.Opts{Algorithm: jwa.RS256})
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			err = VerifyAgainstJwks(*token, "a", josemodel.Jwks{Keys: []map[string]any{publishedKey}})
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected verification to succeed, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected verification to be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error naming %s, got %v", tc.reference, tc.expectErr, err)
			}
			if strings.Contains(err.Error(), "failed to verify JWT signature") {
				t.Errorf("[%s] a key published for another algorithm must not read as a bad signature, got %v", tc.reference, err)
			}
		})
	}
}

func TestVerifyAgainstJwks_TheKeyAlgorithmIsComparedExactly(t *testing.T) {
	key := selectorKey(t)
	body := map[string]any{"iss": "https://leaf.example.com", "sub": "https://leaf.example.com"}

	for _, keyAlg := range []string{"rs256", "Rs256", " RS256", "RS256 "} {
		t.Run(keyAlg, func(t *testing.T) {
			publishedKey := selectorJwk(t, key.Public(), "a")
			publishedKey["alg"] = keyAlg
			token, err := jwt.New(key, map[string]any{"kid": "a", "alg": "RS256"}, body, jwt.Opts{Algorithm: jwa.RS256})
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			err = VerifyAgainstJwks(*token, "a", josemodel.Jwks{Keys: []map[string]any{publishedKey}})
			if err == nil {
				t.Fatalf("[RFC 7517 4.4] an 'alg' is a case-sensitive ASCII string, so a key published for %q must not verify an RS256 signature", keyAlg)
			}
			if !strings.Contains(err.Error(), "does not match the 'alg' the selected key") {
				t.Fatalf("expected the mismatch to be named, got %v", err)
			}
		})
	}
}

func TestVerifyAgainstJwks_ANullKeyAlgorithmLeavesTheKeyUnconstrained(t *testing.T) {
	key := selectorKey(t)
	publishedKey := selectorJwk(t, key.Public(), "a")
	publishedKey["alg"] = nil
	token, err := jwt.New(key, map[string]any{"kid": "a", "alg": "RS256"}, map[string]any{"iss": "https://leaf.example.com"}, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	if err := VerifyAgainstJwks(*token, "a", josemodel.Jwks{Keys: []map[string]any{publishedKey}}); err != nil {
		t.Fatalf("[RFC 7517 4.4] use of 'alg' is optional, so a null value must leave the key unconstrained, got %v", err)
	}
}

func TestVerifyAgainstJwks_AMissingHeaderAlgorithmIsNotReportedAsASignatureFailure(t *testing.T) {
	key := selectorKey(t)
	publishedKey := selectorJwk(t, key.Public(), "a")
	encode := base64.RawURLEncoding.EncodeToString
	token := encode([]byte(`{"kid":"a"}`)) + "." + encode([]byte(`{"iss":"https://leaf.example.com"}`)) + "." + encode([]byte("sig"))

	err := VerifyAgainstJwks(token, "a", josemodel.Jwks{Keys: []map[string]any{publishedKey}})
	if err == nil {
		t.Fatal("[3.2 step 3] a statement with no 'alg' header must be refused")
	}
	if !strings.Contains(err.Error(), "missing or malformed header claim 'alg'") {
		t.Errorf("expected the missing header to be named rather than read as a bad signature, got %v", err)
	}
}
