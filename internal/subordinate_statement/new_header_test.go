package subordinate_statement

import (
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_RefusesAHeaderItsOwnReadPathRejects(t *testing.T) {
	tests := []struct {
		name      string
		step      string
		algorithm string
		ecSigner  bool
		expectErr string
	}{
		{name: "an alg of none", step: "3.2 step 3", algorithm: "none", expectErr: "refusing to publish"},
		{name: "an empty alg", step: "3.2 step 3", algorithm: "", expectErr: "refusing to publish"},
		{name: "an alg in the wrong case", step: "3.2 step 3", algorithm: "rs256", expectErr: "refusing to publish"},
		{name: "an unknown alg", step: "3.2 step 3", algorithm: "banana", expectErr: "refusing to publish"},
		{name: "an alg that does not match the key", step: "3.2 step 12", algorithm: "RS256", ecSigner: true, expectErr: "refusing to publish"},
		{name: "a conforming alg is published", step: "3.2 step 3", algorithm: "RS256"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			subjectKey := testKey(t)
			signerKey := testKey(t)
			var signer crypto.Signer = signerKey
			if tc.ecSigner {
				ec, err := jws.GetSigner(josemodel.ES256, nil)
				if err != nil {
					t.Fatalf("failed to build an EC signer: %v", err)
				}
				signer = ec
			}

			simple := func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
				return &model.SubordinateConfiguration{
					JWKs: josemodel.Jwks{Keys: []map[string]any{testPublicJwk(t, subjectKey.Public(), "leaf")}},
				}, &model.SignerConfiguration{
					Signer:    signer,
					KeyID:     "ta",
					Algorithm: tc.algorithm,
				}, nil
			}

			cfg := model.ServerConfiguration{
				EntityIdentifier: "https://ta.example.com",
				IntermediateConfiguration: &model.IntermediateConfiguration{
					SubordinateStatementLifetime: time.Hour,
				},
			}

			token, err := New(t.Context(), "https://leaf.example.com", simple, cfg)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the statement to be issued, got %v", tc.step, err)
				}
				if token == nil {
					t.Fatalf("[%s] expected a signed statement", tc.step)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected issuance to be refused, got a signed statement this library would reject", tc.step)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error containing %q, got %v", tc.step, tc.expectErr, err)
			}
		})
	}
}
