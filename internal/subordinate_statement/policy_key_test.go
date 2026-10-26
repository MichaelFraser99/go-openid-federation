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

func TestNew_RefusesToPublishAPolicyOperandCarryingPrivateMembers(t *testing.T) {
	private := map[string]any{"kid": "policy", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "d": "SECRETEXPONENT"}
	public := map[string]any{"kid": "policy", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}

	tests := []struct {
		name      string
		reference string
		operator  string
		key       map[string]any
		expectErr bool
	}{
		{name: "a value operand carrying only public material", reference: "6.1.2", operator: "value", key: public},
		{name: "a value operand carrying a private exponent", reference: "RFC 7518 6.2.2", operator: "value", key: private, expectErr: true},
		{name: "a default operand carrying a private exponent", reference: "RFC 7518 6.2.2", operator: "default", key: private, expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"openid_relying_party": map[string]any{
					"jwks": map[string]any{tc.operator: map[string]any{"keys": []any{tc.key}}},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			var policy model.MetadataPolicy
			if err := json.Unmarshal(raw, &policy); err != nil {
				t.Fatalf("failed to parse the fixture policy: %v", err)
			}

			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatal(err)
			}
			good := map[string]any{"kid": "good", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}
			retriever := func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
				return &model.SubordinateConfiguration{
					JWKs:     josemodel.Jwks{Keys: []map[string]any{good}},
					Policies: policy,
				}, &model.SignerConfiguration{Signer: signer, KeyID: "ta", Algorithm: "ES256"}, nil
			}

			cfg := model.ServerConfiguration{
				EntityIdentifier:          "https://ta.example.com",
				IntermediateConfiguration: &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
			}

			token, err := New(t.Context(), "https://leaf.example.com", retriever, cfg)
			if !tc.expectErr {
				if err != nil {
					t.Fatalf("[%s] expected a policy pinning a public key to be published, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] a policy operand is the authority's own configuration and is served from /fetch, so it must be held to the same rule: %s", tc.reference, publishedPayload(t, *token))
			}
			if !strings.Contains(err.Error(), "private key members") {
				t.Errorf("[%s] expected the refusal to name the private members, got %v", tc.reference, err)
			}
			if token != nil && strings.Contains(publishedPayload(t, *token), "SECRETEXPONENT") {
				t.Errorf("[%s] the private exponent reached the published statement", tc.reference)
			}
		})
	}
}
