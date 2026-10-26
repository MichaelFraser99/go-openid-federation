package trust_marks

import (
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func shapedMark(t *testing.T, f *rvFed, issuer, trustMarkType string, delegation any) string {
	t.Helper()
	body := map[string]any{
		"iss": issuer, "sub": rvSub, "trust_mark_type": trustMarkType,
		"iat": time.Now().UTC().Unix(), "exp": time.Now().Add(time.Hour).UTC().Unix(),
		"delegation": delegation,
	}
	token, err := jwt.New(f.ecKey["member"], map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256"}, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to sign the trust mark: %v", err)
	}
	return *token
}

func TestValidate_ADelegationThatIsNotAJWTNamesItsOwnFault(t *testing.T) {
	shapes := map[string]any{
		"a null delegation":            nil,
		"a numeric delegation":         42,
		"a boolean delegation":         true,
		"an object delegation":         map[string]any{"jwt": "x"},
		"an array delegation":          []any{"x"},
		"an empty string delegation":   "",
		"a whitespace-only delegation": "   ",
	}

	for _, owned := range []bool{true, false} {
		for name, shape := range shapes {
			label := name + " on an unowned type"
			if owned {
				label = name + " on an owned type"
			}
			t.Run(label, func(t *testing.T) {
				f := newRvFed(t, map[string]string{"member": "ta"})
				issuer := f.id("member")
				ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
				if owned {
					ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, rvKey(t), "owner-key")}
				}

				_, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, shapedMark(t, f, issuer, rvType, shape), ValidateOptions{
					ExpectedType:             rvType,
					ExpectedSubject:          rvSub,
					AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(issuer)},
					TrustAnchor:              ta.Sub,
					TrustAnchorConfiguration: ta,
				}, nil)
				if err == nil {
					t.Fatalf("[7.2.1] a 'delegation' claim that is not a signed JWT must be refused")
				}
				if !strings.Contains(err.Error(), "not a signed JWT") {
					t.Errorf("[7.2.1] the refusal must name the delegation's own shape rather than the trust anchor's owner list, got %q", err.Error())
				}
			})
		}
	}
}
