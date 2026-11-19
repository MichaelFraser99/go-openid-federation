package model_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func modulusOfBits(bits int) string {
	raw := make([]byte, (bits+7)/8)
	for i := range raw {
		raw[i] = 0xff
	}
	if spare := len(raw)*8 - bits; spare > 0 {
		raw[0] >>= spare
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestVerifyKeyStrengthForAnySignatureAlgorithm_FiltersAKeySetAsAConsumerWould(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		key       map[string]any
		expectErr string
	}{
		{name: "a 2048 bit RSA key", reference: "RFC 7518 3.3", key: map[string]any{"kty": "RSA", "n": modulusOfBits(2048), "e": "AQAB"}},
		{name: "a 2047 bit RSA key", reference: "RFC 7518 3.3", key: map[string]any{"kty": "RSA", "n": modulusOfBits(2047), "e": "AQAB"}, expectErr: "2047 bit RSA modulus"},
		{name: "a 2048 bit RSA key written with a leading zero octet", reference: "RFC 7518 6.3.1.1", key: map[string]any{"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(append([]byte{0}, func() []byte { raw, _ := base64.RawURLEncoding.DecodeString(modulusOfBits(2048)); return raw }()...)), "e": "AQAB"}},
		{name: "an RSA key above this library's maximum", reference: "RFC 7517 4.4", key: map[string]any{"kty": "RSA", "n": modulusOfBits(16384), "e": "AQAB"}},
		{name: "a 1024 bit RSA key published for signing", reference: "RFC 7518 3.3", key: map[string]any{"kty": "RSA", "use": "sig", "n": modulusOfBits(1024), "e": "AQAB"}, expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit RSA key whose key_ops list verify", reference: "RFC 7518 3.3", key: map[string]any{"kty": "RSA", "key_ops": []any{"verify"}, "n": modulusOfBits(1024), "e": "AQAB"}, expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit RSA key published for encryption", reference: "RFC 7517 4.2", key: map[string]any{"kty": "RSA", "use": "enc", "n": modulusOfBits(1024), "e": "AQAB"}},
		{name: "a 1024 bit RSA key whose key_ops exclude verify", reference: "RFC 7517 4.3", key: map[string]any{"kty": "RSA", "key_ops": []any{"encrypt"}, "n": modulusOfBits(1024), "e": "AQAB"}},
		{name: "a 1024 bit RSA key whose use is malformed, which no resolver selects", reference: "RFC 7517 4.2", key: map[string]any{"kty": "RSA", "use": 1, "n": modulusOfBits(1024), "e": "AQAB"}},
		{name: "a 1024 bit RSA key whose use is null, which counts as absent", reference: "RFC 7517 4.2", key: map[string]any{"kty": "RSA", "use": nil, "n": modulusOfBits(1024), "e": "AQAB"}, expectErr: "1024 bit RSA modulus"},
		{name: "an EC key", reference: "RFC 7518 6.2", key: map[string]any{"kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}},
		{name: "an RSA key with no modulus is left to the shape check", reference: "RFC 7518 6.3.1.1", key: map[string]any{"kty": "RSA", "e": "AQAB"}},
		{name: "an RSA key whose modulus is not base64url is left to the parser", reference: "RFC 7518 6.3.1.1", key: map[string]any{"kty": "RSA", "n": "not base64!", "e": "AQAB"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := model.VerifyKeyStrengthForAnySignatureAlgorithm(tc.key)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the key to pass, got %v", tc.reference, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected a refusal naming %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func TestVerifyKeyStrengthForAnySignatureAlgorithm_LeavesOnlyKeysAResolverCanVerifyWith(t *testing.T) {
	published := []map[string]any{
		{"kid": "strong", "kty": "RSA", "n": modulusOfBits(2048), "e": "AQAB"},
		{"kid": "weak", "kty": "RSA", "n": modulusOfBits(1024), "e": "AQAB"},
		{"kid": "weak-enc", "kty": "RSA", "use": "enc", "n": modulusOfBits(1024), "e": "AQAB"},
		{"kid": "ec", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"},
	}

	var kept []string
	for _, key := range published {
		if model.VerifyKeyStrengthForAnySignatureAlgorithm(key) == nil {
			kept = append(kept, key["kid"].(string))
		}
	}

	if strings.Join(kept, ",") != "strong,weak-enc,ec" {
		t.Errorf("[RFC 7518 3.3] expected only the 1024 bit key a resolver could select to verify to be filtered out, got %v", kept)
	}
}
