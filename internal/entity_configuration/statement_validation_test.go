package entity_configuration

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func signStatementWithKey(t *testing.T, signer crypto.Signer, head, body map[string]any) string {
	t.Helper()
	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: josemodel.RS256})
	if err != nil {
		t.Fatalf("failed to sign statement: %v", err)
	}
	return *token
}

// jwt.New inserts a typ of JWT when the header omits one, so a statement with
// no typ header at all has to be assembled directly.
func signStatementWithoutTyp(t *testing.T, key *rsa.PrivateKey, head, body map[string]any) string {
	t.Helper()
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("failed to encode: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := encode(head) + "." + encode(body)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("failed to sign statement: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestValidate_EntityConfigurationStatementRules(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")

	key := headerJwkKey(t)
	published := headerJwkPublicJwk(t, key.Public(), "leaf")

	body := func(extra map[string]any) map[string]any {
		claims := map[string]any{
			"iss":      string(leaf),
			"sub":      string(leaf),
			"iat":      time.Now().Add(-time.Minute).UTC().Unix(),
			"exp":      time.Now().Add(time.Hour).UTC().Unix(),
			"jwks":     map[string]any{"keys": []any{published}},
			"metadata": map[string]any{},
		}
		for k, v := range extra {
			claims[k] = v
		}
		return claims
	}

	tests := []struct {
		name      string
		step      string
		head      map[string]any
		extra     map[string]any
		expectErr string
	}{
		{
			name: "a conforming entity configuration is accepted",
			step: "3.2",
			head: map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"},
		},
		{
			name:      "typ of JWT",
			step:      "3.2 step 2",
			head:      map[string]any{"kid": "leaf", "typ": "JWT", "alg": "RS256"},
			expectErr: "must set the 'typ' header to 'entity-statement+jwt'",
		},
		{
			name:      "typ of trust-mark+jwt",
			step:      "3.2 step 2",
			head:      map[string]any{"kid": "leaf", "typ": "trust-mark+jwt", "alg": "RS256"},
			expectErr: "must set the 'typ' header to 'entity-statement+jwt'",
		},
		{
			name: "the media type form of typ is accepted",
			step: "RFC 7515 4.1.9",
			head: map[string]any{"kid": "leaf", "typ": "application/entity-statement+jwt", "alg": "RS256"},
		},
		{
			name:      "an unknown critical header",
			step:      "RFC 7515 4.1.11",
			head:      map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256", "crit": []any{"x-unknown"}},
			expectErr: "does not understand",
		},
		{
			name:      "an empty crit header",
			step:      "RFC 7515 4.1.11",
			head:      map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256", "crit": []any{}},
			expectErr: "must not be the empty array",
		},
		{
			name:      "metadata_policy is not permitted",
			step:      "3.2 step 17",
			head:      map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"},
			extra:     map[string]any{"metadata_policy": map[string]any{"federation_entity": map[string]any{}}},
			expectErr: `"metadata_policy" claim is permitted only in subordinate statements`,
		},
		{
			name:      "metadata_policy_crit is not permitted",
			step:      "3.2 step 18",
			head:      map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"},
			extra:     map[string]any{"metadata_policy_crit": []any{"regexp"}},
			expectErr: `"metadata_policy_crit" claim is permitted only in subordinate statements`,
		},
		{
			name:      "constraints is not permitted",
			step:      "3.2 step 19",
			head:      map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"},
			extra:     map[string]any{"constraints": map[string]any{"max_path_length": 1}},
			expectErr: `"constraints" claim is permitted only in subordinate statements`,
		},
		{
			name:      "source_endpoint is not permitted",
			step:      "3.2 step 23",
			head:      map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"},
			extra:     map[string]any{"source_endpoint": "https://ta.example.com/fetch"},
			expectErr: `"source_endpoint" claim is permitted only in subordinate statements`,
		},
		{
			name:      "a parse failure is not reported as a metadata problem",
			step:      "diagnostics",
			head:      map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"},
			extra:     map[string]any{"iss": 7},
			expectErr: "invalid entity statement",
		},
	}

	t.Run("no typ header at all", func(t *testing.T) {
		token := signStatementWithoutTyp(t, key, map[string]any{"kid": "leaf", "alg": "RS256"}, body(nil))
		_, err := Validate(context.Background(), model.Configuration{}, leaf, token)
		if err == nil {
			t.Fatal("[3.2 step 2] expected a statement with no typ header to be rejected")
		}
		if !strings.Contains(err.Error(), "missing required header claim 'typ'") {
			t.Fatalf("[3.2 step 2] expected the missing typ header to be reported, got %v", err)
		}
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := signStatementWithKey(t, key, tc.head, body(tc.extra))

			result, err := Validate(context.Background(), model.Configuration{}, leaf, token)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the configuration to be accepted, got %v", tc.step, err)
				}
				if result.Sub != leaf {
					t.Errorf("expected sub %q, got %q", leaf, result.Sub)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected an error containing %q, got an accepted configuration", tc.step, tc.expectErr)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error containing %q, got %v", tc.step, tc.expectErr, err)
			}
		})
	}
}
