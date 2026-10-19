package subordinate_statement

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_SubordinateStatementRules(t *testing.T) {
	const (
		trustAnchor = model.EntityIdentifier("https://ta.example.com")
		leaf        = model.EntityIdentifier("https://leaf.example.com")
	)

	issuerKey := testKey(t)
	subjectKey := testKey(t)
	issuerJwk := testPublicJwk(t, issuerKey.Public(), "ta")
	subjectJwk := testPublicJwk(t, subjectKey.Public(), "leaf")

	body := func(extra map[string]any) map[string]any {
		claims := map[string]any{
			"iss":  string(trustAnchor),
			"sub":  string(leaf),
			"iat":  time.Now().Add(-time.Minute).UTC().Unix(),
			"exp":  time.Now().Add(time.Hour).UTC().Unix(),
			"jwks": map[string]any{"keys": []any{subjectJwk}},
		}
		for k, v := range extra {
			claims[k] = v
		}
		return claims
	}

	validMark := trustMarkForType(t, "https://tm.example.com/a")

	tests := []struct {
		name      string
		step      string
		head      map[string]any
		extra     map[string]any
		expectErr string
	}{
		{
			name: "a conforming subordinate statement is accepted",
			step: "3.2",
			head: map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"},
		},
		{
			name:      "typ of JWT",
			step:      "3.2 step 2",
			head:      map[string]any{"kid": "ta", "typ": "JWT", "alg": "RS256"},
			expectErr: "must set the 'typ' header to 'entity-statement+jwt'",
		},
		{
			name:      "an unknown critical header",
			step:      "RFC 7515 4.1.11",
			head:      map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256", "crit": []any{"x-unknown"}},
			expectErr: "does not understand",
		},
		{
			name:      "authority_hints is not permitted",
			step:      "3.2 step 14",
			head:      map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"},
			extra:     map[string]any{"authority_hints": []any{"https://other-ta.example.com"}},
			expectErr: `"authority_hints" claim is permitted only in entity configurations`,
		},
		{
			name:      "trust_anchor_hints is not permitted",
			step:      "3.2 step 15",
			head:      map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"},
			extra:     map[string]any{"trust_anchor_hints": []any{"https://other-ta.example.com"}},
			expectErr: `"trust_anchor_hints" claim is permitted only in entity configurations`,
		},
		{
			name:      "trust_marks is not permitted",
			step:      "3.2 step 20",
			head:      map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"},
			extra:     map[string]any{"trust_marks": []any{map[string]any{"trust_mark_type": "https://tm.example.com/a", "trust_mark": validMark}}},
			expectErr: `"trust_marks" claim is permitted only in entity configurations`,
		},
		{
			name:      "trust_mark_issuers is not permitted",
			step:      "3.2 step 21",
			head:      map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"},
			extra:     map[string]any{"trust_mark_issuers": map[string]any{"https://tm.example.com/a": []any{}}},
			expectErr: `"trust_mark_issuers" claim is permitted only in entity configurations`,
		},
		{
			name:  "trust_mark_owners is not permitted",
			step:  "3.2 step 22",
			head:  map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"},
			extra: map[string]any{"trust_mark_owners": map[string]any{"https://tm.example.com/a": map[string]any{"sub": "https://o.example.com", "jwks": map[string]any{"keys": []any{}}}}},

			expectErr: `"trust_mark_owners" claim is permitted only in entity configurations`,
		},
		{
			name:      "a parse failure is not reported as a metadata problem",
			step:      "diagnostics",
			head:      map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"},
			extra:     map[string]any{"exp": time.Now().Add(-time.Hour).UTC().Unix()},
			expectErr: "invalid entity statement",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuer := testIssuerStatement(t, trustAnchor, issuerJwk)
			statement := testSign(t, issuerKey, tc.head, body(tc.extra))

			result, err := Validate(model.Configuration{}, issuer, statement)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the statement to be accepted, got %v", tc.step, err)
				}
				if result.Sub != leaf {
					t.Errorf("expected sub %q, got %q", leaf, result.Sub)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected an error containing %q, got an accepted statement", tc.step, tc.expectErr)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error containing %q, got %v", tc.step, tc.expectErr, err)
			}
		})
	}
}

func trustMarkForType(t *testing.T, trustMarkType string) string {
	t.Helper()
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("failed to encode: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	head := encode(map[string]any{"typ": "trust-mark+jwt", "alg": "RS256", "kid": "k"})
	body := encode(map[string]any{
		"iss":             "https://tm.example.com",
		"sub":             "https://leaf.example.com",
		"trust_mark_type": trustMarkType,
		"iat":             time.Now().UTC().Unix(),
	})
	return head + "." + body + ".signature"
}
