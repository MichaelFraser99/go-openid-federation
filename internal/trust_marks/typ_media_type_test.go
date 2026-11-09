package trust_marks

import (
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestFilterByTrusted_AMarkAndItsDelegationAreTypedByOneASCIIMediaTypeRule(t *testing.T) {
	spellings := func(jwtType string) map[string]bool {
		return map[string]bool{
			jwtType:                  true,
			"application/" + jwtType: true,
			strings.ToUpper(jwtType): true,
			"Application/" + strings.ToUpper(jwtType):  true,
			strings.Replace(jwtType, "s", "\u017f", 1): false,
			strings.Replace(jwtType, "k", "\u212a", 1): false,
			"application/application/" + jwtType:       false,
			"/" + jwtType:                              false,
			"text/" + jwtType:                          false,
			jwtType + " ":                              false,
			jwtType[:len(jwtType)-1]:                   false,
			"jwt":                                      false,
			"":                                         false,
		}
	}

	for _, delegated := range []bool{false, true} {
		jwtType := "trust-mark+jwt"
		if delegated {
			jwtType = delegationJWTType
		}
		for typ, accepted := range spellings(jwtType) {
			t.Run(jwtType+" spelled "+typ, func(t *testing.T) {
				d := dlgSetup(t)
				delegationHead := dlgHead("owner-key")
				markHead := map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256"}
				if delegated {
					delegationHead["typ"] = typ
				} else {
					markHead["typ"] = typ
				}
				body := map[string]any{
					"iss": d.issuer, "sub": rvSub, "trust_mark_type": rvType,
					"iat": time.Now().UTC().Unix(), "exp": time.Now().Add(time.Hour).UTC().Unix(),
					"delegation": dlgSignRaw(t, d.ownerKey, delegationHead, dlgBody(dlgOwner, d.issuer, rvType)),
				}
				mark := dlgSign(t, d.fed.ecKey["member"], markHead, body)

				kept := len(d.fed.filter(t, d.anchor, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: mark}))
				if accepted && kept != 1 {
					t.Errorf("[RFC 7515 4.1.9] %q names the media type application/%s, so the mark must be kept, got %d", typ, jwtType, kept)
				}
				if !accepted && kept != 0 {
					t.Errorf("[7, 7.2.1] %q is not the media type application/%s compared with ASCII case folding, so the mark must be dropped, got %d", typ, jwtType, kept)
				}
			})
		}
	}
}
