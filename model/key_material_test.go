package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwk"
)

func privateMemberKey(t *testing.T, kty string) map[string]any {
	t.Helper()
	switch kty {
	case "RSA":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		published, err := jwk.PrivateJwk(key)
		if err != nil {
			t.Fatal(err)
		}
		return *published
	case "EC":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		published, err := jwk.PrivateJwk(key)
		if err != nil {
			t.Fatal(err)
		}
		return *published
	}
	t.Fatalf("unsupported kty %q", kty)
	return nil
}

func rsaJWKOfBits(t *testing.T, bits int) map[string]any {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"kty": "RSA",
		"kid": "sized",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func TestPrivateJWKMembers(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		key       map[string]any
		expect    []string
	}{
		{
			name:      "a public RSA key carries none",
			reference: "RFC 7518 6.3.1",
			key:       realJWK(t, nil, true),
		},
		{
			name:      "a public EC key carries none",
			reference: "RFC 7518 6.2.1",
			key:       realJWK(t, elliptic.P256(), false),
		},
		{
			name:      "an RSA private key names every private member it carries",
			reference: "RFC 7518 6.3.2",
			key:       privateMemberKey(t, "RSA"),
			expect:    []string{"d", "p", "q", "dp", "dq", "qi"},
		},
		{
			name:      "an EC private key names its private exponent",
			reference: "RFC 7518 6.2.2",
			key:       privateMemberKey(t, "EC"),
			expect:    []string{"d"},
		},
		{
			name:      "an OKP private key names its private exponent",
			reference: "RFC 8037 2",
			key:       map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AQAB", "d": "AQAB"},
			expect:    []string{"d"},
		},
		{
			name:      "a symmetric key is private in its entirety",
			reference: "RFC 7518 6.4.1",
			key:       map[string]any{"kty": "oct", "k": "AQAB"},
			expect:    []string{"k"},
		},
		{
			name:      "other primes info is private",
			reference: "RFC 7518 6.3.2.7",
			key:       map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB", "oth": []any{}},
			expect:    []string{"oth"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			members := PrivateJWKMembers(tc.key)
			for _, want := range tc.expect {
				if !slices.Contains(members, want) {
					t.Errorf("[%s] expected %q among the private members found, got %v", tc.reference, want, members)
				}
			}
			if len(tc.expect) == 0 && len(members) != 0 {
				t.Errorf("[%s] expected a public key to carry no private members, got %v", tc.reference, members)
			}
			err := VerifyPublishableJWK(tc.key)
			if len(tc.expect) == 0 {
				if err != nil {
					t.Errorf("[%s] expected a public key to be publishable, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected a key carrying %v to be refused for publication", tc.reference, tc.expect)
			}
			for _, want := range tc.expect {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("[%s] expected the refusal to name %q, got %v", tc.reference, want, err)
				}
			}
		})
	}
}

func TestVerifyKeyStrength(t *testing.T) {
	weak := rsaJWKOfBits(t, 1024)
	strong := rsaJWKOfBits(t, 2048)

	tests := []struct {
		name      string
		reference string
		key       map[string]any
		alg       string
		expectErr string
	}{
		{name: "a 2048 bit modulus with RS256", reference: "RFC 7518 3.3", key: strong, alg: "RS256"},
		{name: "a 1024 bit modulus with RS256", reference: "RFC 7518 3.3", key: weak, alg: "RS256", expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit modulus with RS512", reference: "RFC 7518 3.3", key: weak, alg: "RS512", expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit modulus with PS256", reference: "RFC 7518 3.5", key: weak, alg: "PS256", expectErr: "1024 bit RSA modulus"},
		{name: "a weak modulus used with an algorithm the rule does not cover", reference: "RFC 7518 3.3", key: weak, alg: "RSA-OAEP"},
		{name: "an EC key has no modulus rule", reference: "RFC 7518 3.4", key: realJWK(t, elliptic.P256(), false), alg: "ES256"},
		{name: "an RSA key with no modulus is left to the shape check", reference: "RFC 7517 5", key: map[string]any{"kty": "RSA", "e": "AQAB"}, alg: "RS256"},
		{name: "an RSA key with a modulus that is not base64url is left to the shape check", reference: "RFC 7517 5", key: map[string]any{"kty": "RSA", "n": "!!!", "e": "AQAB"}, alg: "RS256"},
		{name: "a key of an unsupported type is not refused", reference: "RFC 7517 5", key: map[string]any{"kty": "Kyber768", "pk": "AQAB"}, alg: "RS256"},
		{name: "a key with no kty is not refused", reference: "RFC 7517 5", key: map[string]any{"n": "AQAB"}, alg: "RS256"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyKeyStrength(tc.key, tc.alg)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the key to be accepted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the key to be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}
