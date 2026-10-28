package trust_marks

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_ACriticalHeaderOnAMarkOrDelegationIsRefusedNotPanicked(t *testing.T) {
	type shape struct {
		crit   any
		reason string
	}
	shapes := map[string]shape{
		"an object entry":             {crit: []any{map[string]any{}}, reason: "must be an array of strings"},
		"an array entry":              {crit: []any{[]any{}}, reason: "must be an array of strings"},
		"a numeric entry":             {crit: []any{1}, reason: "must be an array of strings"},
		"an empty list":               {crit: []any{}, reason: "must not be the empty array"},
		"a string rather than a list": {crit: "exp", reason: "must be an array of strings"},
		"a registered claim name":     {crit: []any{"exp"}, reason: "lists [exp], which this implementation does not understand"},
		"an extension name":           {crit: []any{"https://example.com/ext"}, reason: "which this implementation does not understand"},
	}

	for _, delegation := range []bool{false, true} {
		for name, tc := range shapes {
			label := "a trust mark with " + name
			if delegation {
				label = "a delegation with " + name
			}
			t.Run(label, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("[RFC 7515 4.1.11] a malformed 'crit' header panicked: %v", r)
					}
				}()
				f := newRvFed(t, map[string]string{"member": "ta"})
				issuer := f.id("member")
				ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
				ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, rvKey(t), "owner-key")}

				head := map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256", "crit": tc.crit}
				body := map[string]any{
					"iss": issuer, "sub": rvSub, "trust_mark_type": rvType,
					"iat": time.Now().UTC().Unix(), "exp": time.Now().Add(time.Hour).UTC().Unix(),
				}
				token := paddedToken(t, head, body)
				expected := "the trust mark's JWT header is refused"
				if delegation {
					head["typ"] = "trust-mark-delegation+jwt"
					head["kid"] = "owner-key"
					body["iss"] = string(dlgOwner)
					body["sub"] = issuer
					token = shapedMark(t, f, issuer, rvType, paddedToken(t, head, body))
					expected = "the trust mark's delegation header is refused"
				}

				_, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, token, ValidateOptions{
					ExpectedType:             rvType,
					ExpectedSubject:          rvSub,
					AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(issuer)},
					TrustAnchor:              ta.Sub,
					TrustAnchorConfiguration: ta,
				}, nil)
				if err == nil || !strings.Contains(err.Error(), expected) || !strings.Contains(err.Error(), tc.reason) {
					t.Fatalf("[RFC 7515 4.1.11] expected a refusal saying %q, got %v", tc.reason, err)
				}
			})
		}
	}
}

func TestFilterByTrusted_AMarkWithACriticalHeaderIsDroppedAndTheResolveSucceeds(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a malformed 'crit' header panicked: %v", r)
		}
	}()
	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("member")
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
	head := map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256", "crit": []any{map[string]any{}}}
	body := map[string]any{
		"iss": issuer, "sub": rvSub, "trust_mark_type": rvType,
		"iat": time.Now().UTC().Unix(), "exp": time.Now().Add(time.Hour).UTC().Unix(),
	}
	resolved := &model.ResolveResponse{
		Sub:        rvSub,
		Exp:        time.Now().Add(time.Hour).UTC().Unix(),
		TrustMarks: []model.TrustMarkHolder{{TrustMarkType: rvType, TrustMark: paddedToken(t, head, body)}},
	}

	if err := FilterByTrusted(t.Context(), model.Configuration{HttpClient: f.server.Client()}, resolved, ta, nil); err != nil {
		t.Fatalf("[8.3] a mark that fails validation is dropped rather than refusing the resolve, got %v", err)
	}
	if len(resolved.TrustMarks) != 0 {
		t.Fatalf("[8.3] expected the mark to be dropped, %s", fmt.Sprint(len(resolved.TrustMarks)))
	}
}
