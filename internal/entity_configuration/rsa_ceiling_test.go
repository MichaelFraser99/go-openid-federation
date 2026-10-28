package entity_configuration

import (
	"context"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func allOnesModulus(bits int) string {
	modulus := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	return base64.RawURLEncoding.EncodeToString(modulus.Bytes())
}

func TestValidate_APeersOversizedRSAKeyIsRefusedBeforeItIsUsed(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")

	tests := map[string]struct {
		bits      int
		alg       string
		expectErr string
	}{
		"a one megabit key under RS256":        {bits: 1 << 20, alg: "RS256", expectErr: "1048576 bit RSA modulus, more than the 8192 bits"},
		"a one megabit key under PS512":        {bits: 1 << 20, alg: "PS512", expectErr: "1048576 bit RSA modulus, more than the 8192 bits"},
		"a key one bit past the ceiling":       {bits: 8193, alg: "RS256", expectErr: "8193 bit RSA modulus, more than the 8192 bits"},
		"a one megabit key under an EC header": {bits: 1 << 20, alg: "ES256"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key := map[string]any{"kty": "RSA", "kid": "big", "n": allOnesModulus(tc.bits), "e": "AQAB"}
			signature := base64.RawURLEncoding.EncodeToString([]byte{2})
			token := strings.TrimSuffix(unsignedStatement(t, map[string]any{"kid": "big", "typ": "entity-statement+jwt", "alg": tc.alg}, map[string]any{
				"iss":  string(leaf),
				"sub":  string(leaf),
				"iat":  time.Now().Add(-time.Minute).UTC().Unix(),
				"exp":  time.Now().Add(time.Hour).UTC().Unix(),
				"jwks": map[string]any{"keys": []any{key}},
			}), base64.RawURLEncoding.EncodeToString([]byte("not a signature"))) + signature

			started := time.Now()
			_, err := Validate(context.Background(), model.Configuration{}, leaf, token)
			elapsed := time.Since(started)
			if err == nil {
				t.Fatalf("expected the statement to be refused")
			}
			if tc.expectErr != "" && !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("expected the refusal to name the ceiling with %q, got %v", tc.expectErr, err)
			}
			if elapsed > time.Second {
				t.Errorf("refusing the statement took %v, so the key was used before it was refused", elapsed)
			}
		})
	}
}
