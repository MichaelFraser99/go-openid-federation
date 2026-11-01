package trust_marks

import (
	"crypto"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func mlDSAJwk(t *testing.T, alg jwa.Algorithm, kid string) (crypto.Signer, map[string]any) {
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

func signWith(t *testing.T, signer crypto.Signer, alg jwa.Algorithm, head, body map[string]any) string {
	t.Helper()
	head["alg"] = alg.String()
	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: alg})
	if err != nil {
		t.Fatalf("failed to sign with %s: %v", alg, err)
	}
	return *token
}

func TestValidate_ATrustMarkSignedWithMLDSAValidates(t *testing.T) {
	f := newRvFed(t, map[string]string{})
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("ta"))}})
	signer, published := mlDSAJwk(t, jwa.MLDSA44, "ml-key")
	ta.JWKs.Keys = append(ta.JWKs.Keys, published)

	tm := signWith(t, signer, jwa.MLDSA44, map[string]any{"kid": "ml-key", "typ": "trust-mark+jwt"}, map[string]any{
		"iss":             f.id("ta"),
		"sub":             rvSub,
		"trust_mark_type": rvType,
		"iat":             time.Now().UTC().Unix(),
		"exp":             time.Now().Add(time.Hour).UTC().Unix(),
	})
	_, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, tm, ValidateOptions{
		ExpectedType:             rvType,
		ExpectedSubject:          rvSub,
		AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(f.id("ta"))},
		TrustAnchor:              ta.Sub,
		TrustAnchorConfiguration: ta,
	}, nil)
	if err != nil {
		t.Fatalf("[RFC 9964] a trust mark signed with ML-DSA-44 must validate, got %v", err)
	}
}

func TestValidate_ADelegationSignedWithMLDSAValidates(t *testing.T) {
	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("member")
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
	signer, published := mlDSAJwk(t, jwa.MLDSA65, "owner-key")
	ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: {Sub: dlgOwner, JWKs: josemodel.Jwks{Keys: []map[string]any{published}}}}

	delegation := signWith(t, signer, jwa.MLDSA65, dlgHead("owner-key"), dlgBody(dlgOwner, issuer, rvType))
	tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)
	_, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, tm, ValidateOptions{
		ExpectedType:             rvType,
		ExpectedSubject:          rvSub,
		AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(issuer)},
		TrustAnchor:              ta.Sub,
		TrustAnchorConfiguration: ta,
	}, nil)
	if err != nil {
		t.Fatalf("[RFC 9964] a delegation signed with ML-DSA-65 must validate, got %v", err)
	}
}
