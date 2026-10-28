package subordinate_statement

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_AStatementHoldingTooManyValuesIsRefusedBeforeItsSignatureIsChecked(t *testing.T) {
	const (
		issuer  = model.EntityIdentifier("https://issuer.example.com")
		subject = model.EntityIdentifier("https://subject.example.com")
	)
	key := testKey(t)
	issuerStatement := testIssuerStatement(t, issuer, testPublicJwk(t, key.Public(), "issuer"))

	padding := func(values int) []any {
		p := make([]any, values)
		for i := range p {
			p[i] = 0
		}
		return p
	}
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	markHolding := func(values int) map[string]any {
		token := encode(map[string]any{"alg": "RS256"}) + "." + encode(map[string]any{"trust_mark_type": "t", "pad": padding(values - 5)}) + "." + encode("sig")
		return map[string]any{"trust_mark_type": "t", "trust_mark": token}
	}

	tests := map[string]struct {
		cfg        model.Configuration
		head       map[string]any
		body       map[string]any
		expectPart string
		limit      int
	}{
		"a padded header past the default": {
			head:       map[string]any{"pad": padding(model.DefaultMaxStatementValues)},
			expectPart: "the JWT header holds more than", limit: model.DefaultMaxStatementValues,
		},
		"a padded body past the default": {
			body:       map[string]any{"pad": padding(model.DefaultMaxStatementValues)},
			expectPart: "the JWT body holds more than", limit: model.DefaultMaxStatementValues,
		},
		"a padded header past a configured limit": {
			cfg:        model.Configuration{MaxStatementValues: 100},
			head:       map[string]any{"pad": padding(100)},
			expectPart: "the JWT header holds more than", limit: 100,
		},
		"a padded body past a configured limit": {
			cfg:        model.Configuration{MaxStatementValues: 100},
			body:       map[string]any{"pad": padding(100)},
			expectPart: "the JWT body holds more than", limit: 100,
		},
		"trust marks that together pass a configured limit": {
			cfg:        model.Configuration{MaxStatementValues: 100},
			body:       map[string]any{"trust_marks": []any{markHolding(60), markHolding(60)}},
			expectPart: "the JWT body carries trust marks holding more than", limit: 100,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			head := map[string]any{"kid": "issuer", "typ": "entity-statement+jwt", "alg": "RS256"}
			for k, v := range tc.head {
				head[k] = v
			}
			body := map[string]any{
				"iss": string(issuer),
				"sub": string(subject),
				"iat": time.Now().Add(-time.Minute).UTC().Unix(),
				"exp": time.Now().Add(time.Hour).UTC().Unix(),
			}
			for k, v := range tc.body {
				body[k] = v
			}
			token := encode(head) + "." + encode(body) + "." + base64.RawURLEncoding.EncodeToString([]byte("not a signature"))
			_, err := Validate(context.Background(), tc.cfg, issuerStatement, token)
			expected := fmt.Sprintf("%s the %d JSON values", tc.expectPart, tc.limit)
			if err == nil || !strings.Contains(err.Error(), expected) {
				t.Fatalf("expected a refusal containing %q, got %v", expected, err)
			}
		})
	}
}
