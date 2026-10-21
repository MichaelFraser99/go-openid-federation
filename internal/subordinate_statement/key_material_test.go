package subordinate_statement

import (
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func registrantRetriever(t *testing.T, registered map[string]any) func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
	t.Helper()
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build signer: %v", err)
	}
	return func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
		return &model.SubordinateConfiguration{
			JWKs: josemodel.Jwks{Keys: []map[string]any{registered}},
		}, &model.SignerConfiguration{Signer: signer, KeyID: "ta", Algorithm: "ES256"}, nil
	}
}

func TestNew_RefusesToRelayARegisteredKeyCarryingPrivateMembers(t *testing.T) {
	tests := []struct {
		name       string
		reference  string
		registered map[string]any
		expectErr  string
	}{
		{
			name:       "a registered public EC key",
			reference:  "RFC 7518 6.2.1",
			registered: map[string]any{"kid": "leaf", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"},
		},
		{
			name:       "a registered EC key carrying its private exponent",
			reference:  "RFC 7518 6.2.2",
			registered: map[string]any{"kid": "leaf", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "d": "AQAB"},
			expectErr:  "private key members",
		},
		{
			name:       "a registered RSA key carrying its primes",
			reference:  "RFC 7518 6.3.2",
			registered: map[string]any{"kid": "leaf", "kty": "RSA", "n": "AQAB", "e": "AQAB", "p": "AQAB", "q": "AQAB"},
			expectErr:  "private key members",
		},
		{
			name:       "a registered symmetric key",
			reference:  "RFC 7518 6.4.1",
			registered: map[string]any{"kid": "leaf", "kty": "oct", "k": "AQAB"},
			expectErr:  "private key members",
		},
	}

	cfg := model.ServerConfiguration{
		EntityIdentifier: "https://ta.example.com",
		IntermediateConfiguration: &model.IntermediateConfiguration{
			SubordinateStatementLifetime: time.Hour,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, err := New(t.Context(), "https://leaf.example.com", registrantRetriever(t, tc.registered), cfg)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the registered public key to be relayed, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected issuance to be refused, got a signed statement", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
			for _, member := range model.PrivateJWKMembers(tc.registered) {
				if value, ok := tc.registered[member].(string); ok && token != nil && strings.Contains(*token, value) {
					t.Errorf("[%s] the private member %q reached the signed statement", tc.reference, member)
				}
			}
		})
	}
}
