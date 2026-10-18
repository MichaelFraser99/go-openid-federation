package entity_statement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

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
			name:      "a kid absent from the set is refused",
			keys:      []map[string]any{selectorJwk(t, key.Public(), "a")},
			kid:       "b",
			expectErr: "no matching key found",
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
		token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: josemodel.RS256})
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
