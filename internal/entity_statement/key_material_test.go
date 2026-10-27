package entity_statement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
)

func keyMaterialKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

func keyMaterialJwk(t *testing.T, pub crypto.PublicKey, kid string) map[string]any {
	t.Helper()
	published, err := jwk.PublicJwk(pub)
	if err != nil {
		t.Fatalf("failed to build public jwk: %v", err)
	}
	(*published)["kid"] = kid
	return *published
}

func keyMaterialSign(t *testing.T, signer crypto.Signer, kid string, alg jwa.Algorithm) string {
	t.Helper()
	token, err := jwt.New(signer, map[string]any{"kid": kid, "typ": "entity-statement+jwt", "alg": alg.String()}, map[string]any{"iss": "https://leaf.example.com"}, jwt.Opts{Algorithm: alg})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	return *token
}

func TestVerifyAgainstJwks_HonoursWhatTheSelectedKeySaysAboutItsUse(t *testing.T) {
	key := keyMaterialKey(t, 2048)
	token := keyMaterialSign(t, key, "leaf", jwa.RS256)

	tests := []struct {
		name      string
		reference string
		use       any
		expectErr string
	}{
		{name: "no use leaves the key unconstrained", reference: "RFC 7517 4.2", use: nil},
		{name: "a use of sig", reference: "RFC 7517 4.2", use: "sig"},
		{name: "a use of enc", reference: "RFC 7517 4.2", use: "enc", expectErr: "declares a 'use' of \"enc\""},
		{name: "a use this library does not know", reference: "RFC 7517 4.2", use: "deriveBits", expectErr: "declares a 'use' of \"deriveBits\""},
		{name: "a use that is not a string", reference: "RFC 7517 4.2", use: 1, expectErr: "malformed 'use' member"},
		{name: "a use that is the empty string", reference: "RFC 7517 4.2", use: "", expectErr: "malformed 'use' member"},
		{name: "a use of SIG, which RFC 7517 compares case-sensitively", reference: "RFC 7517 4.2", use: "SIG", expectErr: "declares a 'use' of \"SIG\""},
		{name: "a use of Sig", reference: "RFC 7517 4.2", use: "Sig", expectErr: "declares a 'use' of \"Sig\""},
		{name: "a use of sig with a trailing space", reference: "RFC 7517 4.2", use: "sig ", expectErr: "declares a 'use' of \"sig \""},
		{name: "a use that merely begins with sig", reference: "RFC 7517 4.2", use: "signature", expectErr: "declares a 'use' of \"signature\""},
		{name: "a use that is an array holding sig", reference: "RFC 7517 4.2", use: []any{"sig"}, expectErr: "malformed 'use' member"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			published := keyMaterialJwk(t, key.Public(), "leaf")
			if tc.use != nil {
				published["use"] = tc.use
			}

			err := VerifyAgainstJwks(token, "leaf", josemodel.Jwks{Keys: []map[string]any{published}})
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the signature to verify, got %v", tc.reference, err)
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

func TestVerifyAgainstJwks_RefusesAnRSAKeyBelowTheAlgorithmsMinimumSize(t *testing.T) {
	weak := keyMaterialKey(t, 1024)
	strong := keyMaterialKey(t, 2048)

	tests := []struct {
		name      string
		reference string
		signer    *rsa.PrivateKey
		alg       jwa.Algorithm
		expectErr string
	}{
		{name: "a 2048 bit key with RS256", reference: "RFC 7518 3.3", signer: strong, alg: jwa.RS256},
		{name: "a 1024 bit key with RS256", reference: "RFC 7518 3.3", signer: weak, alg: jwa.RS256, expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit key with PS256", reference: "RFC 7518 3.5", signer: weak, alg: jwa.PS256, expectErr: "1024 bit RSA modulus"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := keyMaterialSign(t, tc.signer, "leaf", tc.alg)
			published := keyMaterialJwk(t, tc.signer.Public(), "leaf")

			err := VerifyAgainstJwks(token, "leaf", josemodel.Jwks{Keys: []map[string]any{published}})
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the signature to verify, got %v", tc.reference, err)
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

func TestVerifyAgainstJwks_AKeyThisLibraryCannotJudgeDoesNotBlockTheSigningKey(t *testing.T) {
	key := keyMaterialKey(t, 2048)
	token := keyMaterialSign(t, key, "leaf", jwa.RS256)
	signing := keyMaterialJwk(t, key.Public(), "leaf")

	oversized := keyMaterialKey(t, 2048)
	oversizedJwk := keyMaterialJwk(t, oversized.Public(), "retired")

	tests := []struct {
		name      string
		reference string
		spare     map[string]any
	}{
		{
			name:      "a key of an unknown type",
			reference: "RFC 7517 5",
			spare:     map[string]any{"kid": "pq", "kty": "ML-DSA-44", "pk": "AQAB"},
		},
		{
			name:      "a key of an unknown type declaring an enc use",
			reference: "RFC 7517 4.2",
			spare:     map[string]any{"kid": "pq", "kty": "ML-KEM-768", "pk": "AQAB", "use": "enc"},
		},
		{
			name:      "a key with no kty at all",
			reference: "RFC 7517 4.1",
			spare:     map[string]any{"kid": "retired", "x5c": []any{"AQAB"}},
		},
		{
			name:      "a weak RSA key held alongside the signing key",
			reference: "RFC 7518 3.3",
			spare: func() map[string]any {
				weak := keyMaterialKey(t, 1024)
				return map[string]any{
					"kid": "weak",
					"kty": "RSA",
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(weak.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(weak.E)).Bytes()),
				}
			}(),
		},
		{
			name:      "a retired key carrying private members",
			reference: "RFC 7518 6.3.2",
			spare: func() map[string]any {
				published := oversizedJwk
				published["d"] = "AQAB"
				return published
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, order := range []struct {
				name string
				keys []map[string]any
			}{
				{name: "spare first", keys: []map[string]any{tc.spare, signing}},
				{name: "spare last", keys: []map[string]any{signing, tc.spare}},
			} {
				t.Run(order.name, func(t *testing.T) {
					if err := VerifyAgainstJwks(token, "leaf", josemodel.Jwks{Keys: order.keys}); err != nil {
						t.Fatalf("[%s] a key this library cannot judge must not stop the signing key verifying, got %v", tc.reference, err)
					}
				})
			}
		})
	}
}

func TestVerifyAgainstJwks_ASelectedKeyThisLibraryCannotUseIsRefusedWithoutPanicking(t *testing.T) {
	key := keyMaterialKey(t, 2048)
	token := keyMaterialSign(t, key, "leaf", jwa.RS256)

	tests := []struct {
		name      string
		reference string
		key       map[string]any
	}{
		{name: "a post-quantum key type", reference: "RFC 7517 4.1", key: map[string]any{"kid": "leaf", "kty": "ML-DSA-44", "pk": "AQAB"}},
		{name: "a key type that is not a string", reference: "RFC 7517 4.1", key: map[string]any{"kid": "leaf", "kty": 1}},
		{name: "an EC key naming a curve this library does not hold", reference: "RFC 7518 6.2.1.1", key: map[string]any{"kid": "leaf", "kty": "EC", "crv": "P-192", "x": "AQAB", "y": "AQAB"}},
		{name: "an OKP key", reference: "RFC 8037 2", key: map[string]any{"kid": "leaf", "kty": "OKP", "crv": "Ed25519", "x": "AQAB"}},
		{name: "an RSA key with no modulus", reference: "RFC 7518 6.3.1.1", key: map[string]any{"kid": "leaf", "kty": "RSA", "e": "AQAB"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("[%s] verifying against a key this library cannot use panicked: %v", tc.reference, recovered)
				}
			}()
			if err := VerifyAgainstJwks(token, "leaf", josemodel.Jwks{Keys: []map[string]any{tc.key}}); err == nil {
				t.Fatalf("[%s] expected a key this library cannot use to be refused", tc.reference)
			}
		})
	}
}
