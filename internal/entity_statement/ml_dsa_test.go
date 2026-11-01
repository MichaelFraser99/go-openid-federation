package entity_statement

import (
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

var mlDSAAlgorithms = []jwa.Algorithm{jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87}

func mlDSAKey(t *testing.T, alg jwa.Algorithm, kid string) (josemodel.Signer, map[string]any) {
	t.Helper()
	signer, err := jws.GetSigner(alg, nil)
	if err != nil {
		t.Fatalf("failed to build the %s signer: %v", alg, err)
	}
	published, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to build the %s jwk: %v", alg, err)
	}
	(*published)["kid"] = kid
	return signer, *published
}

func noPanic(t *testing.T, check func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a key this library cannot use panicked: %v", r)
		}
	}()
	check()
}

func TestVerifyAgainstJwks_VerifiesEachMLDSAParameterSet(t *testing.T) {
	for _, alg := range mlDSAAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			signer, published := mlDSAKey(t, alg, "k")
			token := signedAs(t, signer, alg)
			set := josemodel.Jwks{Keys: []map[string]any{published}}

			if err := VerifyAgainstJwks(t.Context(), token, "k", set, model.DefaultSigningAlgorithms()); err != nil {
				t.Errorf("[RFC 9964] expected a %s signature to verify by kid, got %v", alg, err)
			}
			if err := VerifyAgainstAnyKey(t.Context(), token, set, model.DefaultSigningAlgorithms()); err != nil {
				t.Errorf("[RFC 9964] expected a %s signature to verify against the set, got %v", alg, err)
			}
			if !KeyCanVerify(published, model.DefaultSigningAlgorithms()) {
				t.Errorf("[RFC 9964] expected a %s key to be usable", alg)
			}
			if err := VerifyAgainstJwks(t.Context(), token, "k", set, []jwa.Algorithm{jwa.ES256}); err == nil || !strings.Contains(err.Error(), "does not accept") {
				t.Errorf("[RFC 8725 3.1] a list without %s must refuse it, got %v", alg, err)
			}
		})
	}
}

func TestVerifyAgainstJwks_AnMLDSAKeyIsBoundToItsParameterSet(t *testing.T) {
	signer65, _ := mlDSAKey(t, jwa.MLDSA65, "k")
	_, published44 := mlDSAKey(t, jwa.MLDSA44, "k")
	token := signedAs(t, signer65, jwa.MLDSA65)

	noPanic(t, func() {
		err := VerifyAgainstJwks(t.Context(), token, "k", josemodel.Jwks{Keys: []map[string]any{published44}}, model.DefaultSigningAlgorithms())
		if err == nil {
			t.Fatal("[RFC 8725 3.1] an ML-DSA-65 signature must not verify against an ML-DSA-44 key")
		}
	})
}

func TestKeyCanVerify_RefusesAnAKPKeyGoJoseCannotRead(t *testing.T) {
	_, published := mlDSAKey(t, jwa.MLDSA65, "k")
	tests := map[string]map[string]any{
		"no alg, which RFC 9964 makes mandatory": withMember(published, "alg", nil),
		"a pub of the wrong length":              withMember(published, "pub", "AQAB"),
		"a pub that is not base64url":            withMember(published, "pub", "not base64!"),
		"a pub that is not a string":             withMember(published, "pub", 1),
		"an alg naming another key type":         withMember(published, "alg", "ES256"),
	}

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			if key["alg"] == nil {
				delete(key, "alg")
			}
			noPanic(t, func() {
				if KeyCanVerify(key, model.DefaultSigningAlgorithms()) {
					t.Errorf("expected the key to be unusable")
				}
				if VerifyAgainstAnyKey(t.Context(), "a.b.c", josemodel.Jwks{Keys: []map[string]any{key}}, model.DefaultSigningAlgorithms()) == nil {
					t.Errorf("expected nothing to verify against the key")
				}
			})
		})
	}
}

func TestVerifyAgainstAnyKey_AMixedSetVerifiesEitherAlgorithm(t *testing.T) {
	ecSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	ecPublished, err := jwk.PublicJwk(ecSigner.Public())
	if err != nil {
		t.Fatalf("failed to build the jwk: %v", err)
	}
	(*ecPublished)["kid"] = "k"
	mlSigner, mlPublished := mlDSAKey(t, jwa.MLDSA65, "k")
	tokens := map[string]string{"ES256": signedAs(t, ecSigner, jwa.ES256), "ML-DSA-65": signedAs(t, mlSigner, jwa.MLDSA65)}

	for order, set := range map[string][]map[string]any{
		"the classical key first": {*ecPublished, mlPublished},
		"the ML-DSA key first":    {mlPublished, *ecPublished},
	} {
		for alg, token := range tokens {
			t.Run(order+", "+alg, func(t *testing.T) {
				if err := VerifyAgainstAnyKey(t.Context(), token, josemodel.Jwks{Keys: set}, model.DefaultSigningAlgorithms()); err != nil {
					t.Errorf("[3] a key set holding classical and ML-DSA keys side by side must verify a %s signature, got %v", alg, err)
				}
			})
		}
	}
}
