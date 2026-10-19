package model

import (
	"encoding/json"
	"strings"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

func TestTrustMarkOwner_MarshalJSON(t *testing.T) {
	keys := josemodel.Jwks{Keys: []map[string]any{{"kid": "a", "kty": "EC"}}}

	tests := []struct {
		name       string
		owner      TrustMarkOwner
		expectErr  string
		expectSub  string
		expectKeep []string
	}{
		{
			name:       "extra members are carried",
			owner:      TrustMarkOwner{Sub: "https://owner.example.com", JWKs: keys, AdditionalClaims: map[string]any{"other": "allowed"}},
			expectSub:  "https://owner.example.com",
			expectKeep: []string{`"other":"allowed"`},
		},
		{
			name:      "an extra member cannot shadow sub",
			owner:     TrustMarkOwner{Sub: "https://owner.example.com", JWKs: keys, AdditionalClaims: map[string]any{"sub": "https://evil.example.com"}},
			expectSub: "https://owner.example.com",
		},
		{
			name:      "an extra member cannot shadow jwks",
			owner:     TrustMarkOwner{Sub: "https://owner.example.com", JWKs: keys, AdditionalClaims: map[string]any{"jwks": "not a key set"}},
			expectSub: "https://owner.example.com",
			expectKeep: []string{
				`"jwks":{`,
			},
		},
		{
			name:      "an unserialisable extra member is reported",
			owner:     TrustMarkOwner{Sub: "https://owner.example.com", JWKs: keys, AdditionalClaims: map[string]any{"bad": func() {}}},
			expectErr: "unsupported type",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.owner)
			if tc.expectErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got %s", tc.expectErr, raw)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("expected an error containing %q, got %v", tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			var decoded struct {
				Sub string `json:"sub"`
			}
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("failed to decode the marshalled owner: %v", err)
			}
			if decoded.Sub != tc.expectSub {
				t.Errorf("expected sub %q, got %q (an extra member must not shadow it)", tc.expectSub, decoded.Sub)
			}
			for _, want := range tc.expectKeep {
				if !strings.Contains(string(raw), want) {
					t.Errorf("expected the output to contain %s, got %s", want, raw)
				}
			}
		})
	}
}
