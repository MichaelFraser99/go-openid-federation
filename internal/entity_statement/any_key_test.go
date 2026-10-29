package entity_statement

import (
	"crypto"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
)

func anyKeySign(t *testing.T, signer crypto.Signer, kid string) string {
	t.Helper()
	token, err := jwt.New(signer, map[string]any{"kid": kid, "typ": "entity-statement+jwt", "alg": "RS256"}, map[string]any{"iss": "https://leaf.example.com"}, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	return *token
}

func TestVerifyAgainstAnyKey(t *testing.T) {
	key := selectorKey(t)
	other := selectorKey(t)
	token := anyKeySign(t, key, "leaf")

	labelled := func(kid string) map[string]any { return selectorJwk(t, key.Public(), kid) }

	tests := []struct {
		name      string
		reference string
		keys      []map[string]any
		expectErr string
	}{
		{
			name:      "the signing key under the kid the header names",
			reference: "10.2",
			keys:      []map[string]any{labelled("leaf")},
		},
		{
			name:      "the signing key under a label of the operator's own",
			reference: "RFC 7517 4.5",
			keys:      []map[string]any{labelled("operator-local-label")},
		},
		{
			name:      "the signing key with no kid at all",
			reference: "RFC 7517 4.5",
			keys: []map[string]any{func() map[string]any {
				published := labelled("leaf")
				delete(published, "kid")
				return published
			}()},
		},
		{
			name:      "the signing key held after another entity's key",
			reference: "10.2",
			keys:      []map[string]any{selectorJwk(t, other.Public(), "first"), labelled("second")},
		},
		{
			name:      "the signing key held after a key with no kid",
			reference: "RFC 7517 5",
			keys:      []map[string]any{{"kty": "RSA", "n": "AQAB", "e": "AQAB"}, labelled("leaf")},
		},
		{
			name:      "the signing key held after a key of a type this library cannot use",
			reference: "RFC 7517 5",
			keys:      []map[string]any{{"kid": "pq", "kty": "ML-DSA-44", "pk": "AQAB"}, labelled("leaf")},
		},
		{
			name:      "only another entity's key",
			reference: "10.2",
			keys:      []map[string]any{selectorJwk(t, other.Public(), "other")},
			expectErr: "no key in the key set verifies the signature",
		},
		{
			name:      "only keys this library cannot use",
			reference: "RFC 7517 5",
			keys:      []map[string]any{{"kid": "pq", "kty": "ML-DSA-44", "pk": "AQAB"}, {"kid": "broken"}},
			expectErr: "no key in the key set can verify a signature made with this token's 'alg'",
		},
		{
			name:      "the signing key held after a key whose kty is not a string",
			reference: "RFC 7517 4.1",
			keys:      []map[string]any{{"kid": "folded", "kty": map[string]any{"RSA": true}}, labelled("leaf")},
		},
		{
			name:      "the signing key held after a key whose kty is a number",
			reference: "RFC 7517 4.1",
			keys:      []map[string]any{{"kid": "numeric", "kty": 1}, labelled("leaf")},
		},
		{
			name:      "only a key whose kty is not a string",
			reference: "RFC 7517 4.1",
			keys:      []map[string]any{{"kid": "folded", "kty": []any{"RSA"}}},
			expectErr: "no key in the key set can verify a signature made with this token's 'alg'",
		},
		{
			name:      "an empty key set",
			reference: "RFC 7517 5",
			keys:      nil,
			expectErr: "no key in the key set can verify a signature made with this token's 'alg'",
		},
		{
			name:      "only the signing key published for another algorithm",
			reference: "RFC 7517 4.4",
			keys: []map[string]any{func() map[string]any {
				published := labelled("leaf")
				published["alg"] = "PS256"
				return published
			}()},
			expectErr: "no key in the key set can verify a signature made with this token's 'alg'",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("[%s] a key this library cannot judge must not panic: %v", tc.reference, recovered)
				}
			}()
			err := VerifyAgainstAnyKey(t.Context(), token, josemodel.Jwks{Keys: tc.keys})
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the signature to verify against a key in the set, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the signature to be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func sizedRSAKey(bits int, alg any) map[string]any {
	modulus := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	key := map[string]any{"kid": "sized", "kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(modulus.Bytes()), "e": "AQAB"}
	if alg != nil {
		key["alg"] = alg
	}
	return key
}

func TestKeyCanVerify_HonoursWhatTheKeySaysAboutItself(t *testing.T) {
	rsaKey := selectorKey(t)
	ecSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	ecPub, err := jwk.PublicJwk(ecSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	(*ecPub)["kid"] = "ec"

	withAlg := func(alg any) map[string]any {
		key := selectorJwk(t, rsaKey.Public(), "ta")
		if alg == nil {
			delete(key, "alg")
			return key
		}
		key["alg"] = alg
		return key
	}

	tests := []struct {
		name      string
		reference string
		key       map[string]any
		usable    bool
	}{
		{name: "an RSA key published for RS256", reference: "RFC 7517 4.4", key: withAlg("RS256"), usable: true},
		{name: "an RSA key published for PS512", reference: "RFC 7517 4.4", key: withAlg("PS512"), usable: true},
		{name: "an RSA key with no published algorithm", reference: "RFC 7517 4.4", key: withAlg(nil), usable: true},
		{name: "an EC key, which the signing library verifies ES256 with", reference: "RFC 7518 3.4", key: *ecPub, usable: true},
		{name: "an RSA key published for EdDSA", reference: "RFC 8037 3.1", key: withAlg("EdDSA")},
		{name: "an RSA key published for ES256", reference: "RFC 7518 3.4", key: withAlg("ES256")},
		{name: "an RSA key published for HS256", reference: "RFC 7518 3.2", key: withAlg("HS256")},
		{name: "an RSA key whose algorithm is not a string", reference: "RFC 7517 4.4", key: withAlg(5)},
		{name: "an RSA key whose algorithm is the empty string", reference: "RFC 7517 4.4", key: withAlg("")},
		{name: "a key of a type the signing library cannot use", reference: "RFC 7517 5", key: map[string]any{"kid": "ed", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},
		{name: "a symmetric key", reference: "RFC 7518 6.4.1", key: map[string]any{"kid": "oct", "kty": "oct", "k": "AQAB"}},
		{name: "a key with no kty", reference: "RFC 7517 4.1", key: map[string]any{"kid": "broken"}},
		{name: "an 8192 bit RSA key published for RS256", reference: "#214", key: sizedRSAKey(8192, "RS256"), usable: true},
		{name: "an 8193 bit RSA key published for RS256", reference: "#214", key: sizedRSAKey(8193, "RS256")},
		{name: "an 8193 bit RSA key with no published algorithm", reference: "#214", key: sizedRSAKey(8193, nil)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := KeyCanVerify(tc.key); got != tc.usable {
				t.Errorf("[%s] expected usable %v, got %v: a key this deployment can never verify with must be refused before a walk, not after one", tc.reference, tc.usable, got)
			}
		})
	}
}

func TestVerifyAgainstAnyKey_TheSigningKeyNeedNotBeLast(t *testing.T) {
	signer := selectorKey(t)
	other := selectorKey(t)
	token := anyKeySign(t, signer, "leaf")

	tests := []struct {
		name      string
		reference string
		keys      []map[string]any
	}{
		{
			name:      "the signing key held before a rotation key",
			reference: "10.2",
			keys:      []map[string]any{selectorJwk(t, signer.Public(), "current"), selectorJwk(t, other.Public(), "next")},
		},
		{
			name:      "the signing key held after a retired key",
			reference: "10.2",
			keys:      []map[string]any{selectorJwk(t, other.Public(), "retired"), selectorJwk(t, signer.Public(), "current")},
		},
		{
			name:      "the signing key held between two others",
			reference: "10.2",
			keys:      []map[string]any{selectorJwk(t, other.Public(), "retired"), selectorJwk(t, signer.Public(), "current"), selectorJwk(t, other.Public(), "next")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyAgainstAnyKey(t.Context(), token, josemodel.Jwks{Keys: tc.keys}); err != nil {
				t.Errorf("[%s] every key in the set is tried, so position must not matter, got %v", tc.reference, err)
			}
		})
	}
}

func TestVerifyAgainstAnyKey_AKeyTheTokenCarriesIsNeverTrusted(t *testing.T) {
	attacker := selectorKey(t)
	configured := selectorKey(t)

	attackerJwk := selectorJwk(t, attacker.Public(), "x")

	token, err := jwt.New(attacker, map[string]any{
		"kid": "x", "typ": "entity-statement+jwt", "alg": "RS256", "jwk": attackerJwk,
	}, map[string]any{"iss": "https://ta.example.com"}, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		reference string
		keys      []map[string]any
		expectErr bool
	}{
		{
			name:      "a configured set that does not hold the key the token carries",
			reference: "10.2",
			keys:      []map[string]any{selectorJwk(t, configured.Public(), "ta")},
			expectErr: true,
		},
		{
			name:      "a configured set that does hold it",
			reference: "10.2",
			keys:      []map[string]any{attackerJwk},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyAgainstAnyKey(t.Context(), *token, josemodel.Jwks{Keys: tc.keys})
			if tc.expectErr {
				if err == nil {
					t.Fatalf("[%s] a key the token carries in its own header must never be trusted", tc.reference)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected the configured key to verify, got %v", tc.reference, err)
			}
		})
	}
}
