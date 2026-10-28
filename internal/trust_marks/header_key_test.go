package trust_marks

import (
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_AKeyCarriedInTheTrustMarkIsNotTrusted(t *testing.T) {
	tests := map[string]struct {
		reference string
		header    func(t *testing.T, attacker any) map[string]any
	}{
		"the attacker's key in the jwk header under the issuer's kid": {
			reference: "7.3 step 7",
			header: func(t *testing.T, attacker any) map[string]any {
				return map[string]any{"jwk": federationPublicJwk(t, attacker, "test-key")}
			},
		},
		"the attacker's key in the jwk header under no kid": {
			reference: "7.3 step 7",
			header: func(t *testing.T, attacker any) map[string]any {
				key := federationPublicJwk(t, attacker, "test-key")
				delete(key, "kid")
				return map[string]any{"jwk": key}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			attacker := rvKey(t)

			head := map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256"}
			for member, value := range tc.header(t, attacker.Public()) {
				head[member] = value
			}
			mark := dlgSignRaw(t, attacker, head, map[string]any{
				"iss": issuer, "sub": rvSub, "trust_mark_type": rvType,
				"iat": time.Now().UTC().Unix(), "exp": time.Now().Add(time.Hour).UTC().Unix(),
			})

			validated, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, mark, ValidateOptions{
				ExpectedType:             rvType,
				ExpectedSubject:          rvSub,
				AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(issuer)},
				TrustAnchor:              ta.Sub,
				TrustAnchorConfiguration: ta,
			}, nil)
			if err == nil {
				t.Fatalf("[%s] the signature must validate using the issuer's published key, so a mark signed by a key it carries itself must be refused, got %+v", tc.reference, validated)
			}
		})
	}
}
