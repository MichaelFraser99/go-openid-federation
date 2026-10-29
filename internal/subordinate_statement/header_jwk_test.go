package subordinate_statement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

func testPublicJwk(t *testing.T, pub crypto.PublicKey, kid string) map[string]any {
	t.Helper()
	publicJWK, err := jwk.PublicJwk(pub)
	if err != nil {
		t.Fatalf("failed to build public jwk: %v", err)
	}
	(*publicJWK)["kid"] = kid
	(*publicJWK)["alg"] = "RS256"
	return *publicJWK
}

func testIssuerStatement(t *testing.T, iss model.EntityIdentifier, keys ...map[string]any) model.EntityStatement {
	t.Helper()
	return model.EntityStatement{
		Iss:  iss,
		Sub:  iss,
		Iat:  time.Now().UTC().Unix(),
		Exp:  time.Now().Add(time.Hour).UTC().Unix(),
		JWKs: josemodel.Jwks{Keys: keys},
	}
}

func testSign(t *testing.T, signer crypto.Signer, head, body map[string]any) string {
	t.Helper()
	if key, ok := signer.(*rsa.PrivateKey); ok {
		return rawRSAToken(t, key, head, body)
	}
	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to sign statement: %v", err)
	}
	return *token
}

func TestValidate_RejectsSignaturesNotMadeByTheIssuersPublishedKey(t *testing.T) {
	const (
		trustAnchor = model.EntityIdentifier("https://ta.example.com")
		leaf        = model.EntityIdentifier("https://leaf.example.com")
	)

	issuerKey := testKey(t)
	attackerKey := testKey(t)
	subjectKey := testKey(t)

	issuerJwk := testPublicJwk(t, issuerKey.Public(), "ta")
	attackerJwk := testPublicJwk(t, attackerKey.Public(), "ta")
	subjectJwk := testPublicJwk(t, subjectKey.Public(), "leaf")

	body := func() map[string]any {
		return map[string]any{
			"iss":  string(trustAnchor),
			"sub":  string(leaf),
			"iat":  time.Now().UTC().Unix(),
			"exp":  time.Now().Add(time.Hour).UTC().Unix(),
			"jwks": map[string]any{"keys": []any{subjectJwk}},
		}
	}

	emptyKidJwk := testPublicJwk(t, issuerKey.Public(), "")

	tests := []struct {
		name          string
		head          map[string]any
		signer        crypto.Signer
		publishedKeys []map[string]any
		expectErr     bool
	}{
		{
			name:      "statement signed by the issuer's published key is accepted",
			head:      map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"},
			signer:    issuerKey,
			expectErr: false,
		},
		{
			name:      "attacker key carried in the jwk header is not trusted",
			head:      map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256", "jwk": attackerJwk},
			signer:    attackerKey,
			expectErr: true,
		},
		{
			name:      "attacker key without a jwk header is rejected",
			head:      map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"},
			signer:    attackerKey,
			expectErr: true,
		},
		{
			name:          "empty kid matching an empty published kid is rejected",
			head:          map[string]any{"kid": "", "typ": "entity-statement+jwt", "alg": "RS256"},
			signer:        issuerKey,
			publishedKeys: []map[string]any{emptyKidJwk},
			expectErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			publishedKeys := tc.publishedKeys
			if publishedKeys == nil {
				publishedKeys = []map[string]any{issuerJwk}
			}
			issuer := testIssuerStatement(t, trustAnchor, publishedKeys...)
			statement := testSign(t, tc.signer, tc.head, body())

			result, err := Validate(t.Context(), model.Configuration{}, issuer, statement)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected statement to be rejected, got accepted result for sub %q", result.Sub)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected statement to be accepted, got error: %v", err)
			}
			if result.Sub != leaf {
				t.Fatalf("expected sub %q, got %q", leaf, result.Sub)
			}
		})
	}
}
