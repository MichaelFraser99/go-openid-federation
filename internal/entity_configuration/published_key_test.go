package entity_configuration

import (
	"crypto"
	"strings"
	"testing"
)

func TestPublishedKeyUsableForSigning_KeyShape(t *testing.T) {
	signerConfiguration, publicJWK := issuanceSigner(t)
	signerPublic := signerConfiguration.Signer.Public()

	tests := []struct {
		name      string
		reference string
		existing  map[string]any
		expectErr string
	}{
		{
			name:      "the published key matches the signer",
			reference: "RFC 7517 4.1",
			existing:  publicJWK,
		},
		{
			name:      "a kty that is a number",
			reference: "RFC 7517 4.1",
			existing:  map[string]any{"kid": "a", "kty": 7},
			expectErr: "'kty' member",
		},
		{
			name:      "a kty that is absent",
			reference: "RFC 7517 4.1",
			existing:  map[string]any{"kid": "a"},
			expectErr: "'kty' member",
		},
		{
			name:      "an EC key with no crv",
			reference: "RFC 7518 6.2.1.1",
			existing:  map[string]any{"kid": "a", "kty": "EC", "x": "AQAB", "y": "AQAB"},
			expectErr: "'crv' member",
		},
		{
			name:      "an EC key with a numeric crv",
			reference: "RFC 7518 6.2.1.1",
			existing:  map[string]any{"kid": "a", "kty": "EC", "crv": 7, "x": "AQAB", "y": "AQAB"},
			expectErr: "'crv' member",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[%s] a malformed published key panicked: %v", tc.reference, r)
				}
			}()

			err := publishedKeyUsableForSigning(tc.existing, publicJWK, signerPublic)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the published key to be usable, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected an error naming %s", tc.reference, tc.expectErr)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error naming %s, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}

	_ = crypto.SHA256
}
