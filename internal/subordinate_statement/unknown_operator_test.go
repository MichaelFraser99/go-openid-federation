package subordinate_statement

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_RefusesToPublishAPolicyItCannotUnderstand(t *testing.T) {
	tests := map[string]struct {
		policy    string
		expectErr string
	}{
		"a policy of known operators": {policy: `{"federation_entity":{"contacts":{"add":["ops@ta.example.com"]}}}`},
		"an unknown operator beside a known one": {
			policy:    `{"federation_entity":{"contacts":{"add":["ops@ta.example.com"],"regexp":".*"}}}`,
			expectErr: "holds operators this library does not understand, so it cannot publish them: federation_entity.contacts.regexp",
		},
		"only an unknown operator": {
			policy:    `{"openid_relying_party":{"scope":{"pattern":"x"}}}`,
			expectErr: "openid_relying_party.scope.pattern",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var policy model.MetadataPolicy
			if err := json.Unmarshal([]byte(tc.policy), &policy); err != nil {
				t.Fatalf("failed to load the configured policy: %v", err)
			}
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatal(err)
			}
			retriever := func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
				return &model.SubordinateConfiguration{
					JWKs:     josemodel.Jwks{Keys: []map[string]any{{"kid": "leaf", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}}},
					Policies: policy,
				}, &model.SignerConfiguration{Signer: signer, KeyID: "ta", Algorithm: "ES256"}, nil
			}
			cfg := model.ServerConfiguration{
				EntityIdentifier:          "https://ta.example.com",
				IntermediateConfiguration: &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
			}

			token, err := New(t.Context(), "https://leaf.example.com", retriever, cfg)
			if tc.expectErr == "" {
				if err != nil || token == nil {
					t.Fatalf("expected the statement to be issued, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("expected publication to be refused naming the operator with %q, got %v", tc.expectErr, err)
			}
		})
	}
}
