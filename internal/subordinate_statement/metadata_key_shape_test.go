package subordinate_statement

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_RefusesARecordWhoseMetadataJwksHoldsAPrivateKeyInAnyShape(t *testing.T) {
	private := map[string]any{"kid": "leaked", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "d": "SECRETEXPONENT"}
	public := map[string]any{"kid": "registered", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}

	tests := []struct {
		name      string
		reference string
		jwks      any
		expectErr bool
	}{
		{name: "a bare public JWK", reference: "RFC 7517 4", jwks: public},
		{name: "a bare private JWK", reference: "RFC 7518 6.2.2", jwks: private, expectErr: true},
		{name: "an array holding a private JWK", reference: "RFC 7518 6.2.2", jwks: []any{public, private}, expectErr: true},
		{name: "a keys member that is an object holding a private JWK", reference: "RFC 7518 6.2.2", jwks: map[string]any{"keys": map[string]any{"0": private}}, expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"x_custom": map[string]any{"jwks": tc.jwks}})
			if err != nil {
				t.Fatal(err)
			}
			var metadata model.Metadata
			if err := json.Unmarshal(raw, &metadata); err != nil {
				t.Fatalf("failed to parse the fixture metadata: %v", err)
			}
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatal(err)
			}
			retriever := func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
				return &model.SubordinateConfiguration{
					JWKs:     josemodel.Jwks{Keys: []map[string]any{public}},
					Metadata: &metadata,
				}, &model.SignerConfiguration{Signer: signer, KeyID: "ta", Algorithm: "ES256"}, nil
			}
			cfg := model.ServerConfiguration{
				EntityIdentifier:          "https://ta.example.com",
				IntermediateConfiguration: &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
			}

			token, err := New(t.Context(), "https://leaf.example.com", retriever, cfg)
			if !tc.expectErr {
				if err != nil {
					t.Fatalf("[%s] expected a public key to be published, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] a private key inside a metadata jwks is published in the signed statement, got %s", tc.reference, publishedPayload(t, *token))
			}
			if !errors.Is(err, ErrUnusableRecord) {
				t.Errorf("[%s] expected the refusal to be the record's alone, got %v", tc.reference, err)
			}
			if !strings.Contains(err.Error(), "metadata.x_custom.jwks") {
				t.Errorf("[%s] expected the refusal to name the key set, got %v", tc.reference, err)
			}
			if strings.Contains(err.Error(), "SECRETEXPONENT") {
				t.Errorf("[%s] the refusal carries the private value: %v", tc.reference, err)
			}
		})
	}
}
