package trust_marks

import (
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_HoldsATrustMarkToTheConfiguredAlgorithms(t *testing.T) {
	f := newRvFed(t, map[string]string{})
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("ta"))}})
	for _, key := range ta.JWKs.Keys {
		delete(key, "alg")
	}
	tm := rawRSAToken(t, f.ecKey["ta"], map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "PS256"}, map[string]any{
		"iss":             f.id("ta"),
		"sub":             rvSub,
		"trust_mark_type": rvType,
		"iat":             time.Now().UTC().Unix(),
		"exp":             time.Now().Add(time.Hour).UTC().Unix(),
	})
	validate := func(algorithms []jwa.Algorithm) error {
		_, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client(), SigningAlgorithms: algorithms}, tm, ValidateOptions{
			ExpectedType:             rvType,
			ExpectedSubject:          rvSub,
			AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(f.id("ta"))},
			TrustAnchor:              ta.Sub,
			TrustAnchorConfiguration: ta,
		}, nil)
		return err
	}

	if err := validate([]jwa.Algorithm{jwa.RS256, jwa.PS256}); err != nil {
		t.Fatalf("the fixture is wrong: a list naming PS256 must accept the trust mark, got %v", err)
	}
	err := validate([]jwa.Algorithm{jwa.RS256})
	if err == nil || !strings.Contains(err.Error(), "does not accept") {
		t.Fatalf("[7.3] a trust mark signed with an algorithm the deployment does not accept is refused, got %v", err)
	}
}

func TestValidate_HoldsADelegationToTheConfiguredAlgorithms(t *testing.T) {
	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("member")
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
	ownerKey := rvKey(t)
	ownerJwk := federationPublicJwk(t, ownerKey.Public(), "owner-key")
	delete(ownerJwk, "alg")
	ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: {Sub: dlgOwner, JWKs: josemodel.Jwks{Keys: []map[string]any{ownerJwk}}}}

	head := dlgHead("owner-key")
	head["alg"] = "PS256"
	delegation := dlgSign(t, ownerKey, head, dlgBody(dlgOwner, issuer, rvType))
	tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)
	validate := func(algorithms []jwa.Algorithm) error {
		_, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client(), SigningAlgorithms: algorithms}, tm, ValidateOptions{
			ExpectedType:             rvType,
			ExpectedSubject:          rvSub,
			AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(issuer)},
			TrustAnchor:              ta.Sub,
			TrustAnchorConfiguration: ta,
		}, nil)
		return err
	}

	if err := validate([]jwa.Algorithm{jwa.RS256, jwa.PS256}); err != nil {
		t.Fatalf("the fixture is wrong: a list naming PS256 must accept the delegation, got %v", err)
	}
	err := validate([]jwa.Algorithm{jwa.RS256})
	if err == nil || !strings.Contains(err.Error(), "delegation") {
		t.Fatalf("[7.2.2] a delegation signed with an algorithm the deployment does not accept is refused, got %v", err)
	}
}
