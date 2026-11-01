package model

import (
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
)

func TestVerifyIssuanceAlgorithm(t *testing.T) {
	for _, algorithm := range DefaultSigningAlgorithms() {
		if algorithm == jwa.EdDSA {
			continue
		}
		t.Run(algorithm.String(), func(t *testing.T) {
			if err := VerifyIssuanceAlgorithm(algorithm.String()); err != nil {
				t.Errorf("[3.2 step 3] expected %s to be an algorithm this library signs with, got %v", algorithm, err)
			}
		})
	}

	tests := map[string]struct {
		name      string
		expectErr string
	}{
		"EdDSA, which is accepted only for verification": {name: "EdDSA", expectErr: "sign with Ed25519"},
		"HS256":                     {name: "HS256", expectErr: "a symmetric key would not be secret"},
		"HS384":                     {name: "HS384", expectErr: "a symmetric key would not be secret"},
		"HS512":                     {name: "HS512", expectErr: "a symmetric key would not be secret"},
		"none":                      {name: "none", expectErr: `"none" is not a supported signing algorithm`},
		"empty":                     {name: "", expectErr: `"" is not a supported signing algorithm`},
		"another case":              {name: "es256", expectErr: `"es256" is not a supported signing algorithm`},
		"a trailing space":          {name: "ES256 ", expectErr: `"ES256 " is not a supported signing algorithm`},
		"an encryption algorithm":   {name: "RSA-OAEP", expectErr: `"RSA-OAEP" is not a supported signing algorithm`},
		"a name long enough to cut": {name: strings.Repeat("A", 4096), expectErr: "is not a supported signing algorithm"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := VerifyIssuanceAlgorithm(tc.name)
			if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[3.2 step 3] expected a refusal naming %q, got %v", tc.expectErr, err)
			}
			if len(err.Error()) > MaxErrorDescriptionBytes+128 {
				t.Errorf("the refusal must bound the name it quotes, got %d bytes", len(err.Error()))
			}
		})
	}
}
