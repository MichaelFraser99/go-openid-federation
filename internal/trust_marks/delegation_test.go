package trust_marks

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const dlgOwner = "https://owner.example.com"

func dlgSign(t *testing.T, signer crypto.Signer, head, body map[string]any) string {
	t.Helper()
	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: josemodel.RS256})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	return *token
}

func dlgHead(kid string) map[string]any {
	return map[string]any{"kid": kid, "typ": "trust-mark-delegation+jwt", "alg": "RS256"}
}

func dlgBody(owner, issuer, trustMarkType string) map[string]any {
	return map[string]any{
		"iss":             owner,
		"sub":             issuer,
		"trust_mark_type": trustMarkType,
		"iat":             time.Now().Add(-time.Minute).UTC().Unix(),
	}
}

func dlgMark(t *testing.T, signer crypto.Signer, kid, iss, trustMarkType, sub string, delegation *string) string {
	t.Helper()
	body := map[string]any{
		"iss": iss, "sub": sub, "trust_mark_type": trustMarkType,
		"iat": time.Now().UTC().Unix(), "exp": time.Now().Add(time.Hour).UTC().Unix(),
	}
	if delegation != nil {
		body["delegation"] = *delegation
	}
	return dlgSign(t, signer, map[string]any{"kid": kid, "typ": "trust-mark+jwt", "alg": "RS256"}, body)
}

func dlgOwnerEntry(t *testing.T, owner string, key *rsa.PrivateKey, kid string, extraKeys ...map[string]any) model.TrustMarkOwner {
	t.Helper()
	keys := []map[string]any{federationPublicJwk(t, key.Public(), kid)}
	keys = append(keys, extraKeys...)
	return model.TrustMarkOwner{Sub: model.EntityIdentifier(owner), JWKs: josemodel.Jwks{Keys: keys}}
}

func TestFilterByTrusted_AnOwnedTypeRequiresADelegation(t *testing.T) {
	tests := map[string]struct {
		reference string
		issuers   func(issuer model.EntityIdentifier) []model.EntityIdentifier
	}{
		"with the issuer listed":    {reference: "7.3 step 8", issuers: func(i model.EntityIdentifier) []model.EntityIdentifier { return []model.EntityIdentifier{i} }},
		"with an unrestricted list": {reference: "7.3 step 8", issuers: func(model.EntityIdentifier) []model.EntityIdentifier { return []model.EntityIdentifier{} }},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := model.EntityIdentifier(f.id("member"))
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: tc.issuers(issuer)})
			ownerKey := rvKey(t)
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")}

			tm := dlgMark(t, f.ecKey["member"], "test-key", string(issuer), rvType, rvSub, nil)
			if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 0 {
				t.Errorf("[%s] the trust anchor names an owner for this type, so a trust mark with no delegation must be dropped", tc.reference)
			}
		})
	}
}

func TestFilterByTrusted_AValidDelegationIsKept(t *testing.T) {
	tests := map[string]struct {
		reference string
		body      func(owner, issuer string) map[string]any
	}{
		"with no expiry, which does not expire": {
			reference: "7.2.1",
			body:      func(owner, issuer string) map[string]any { return dlgBody(owner, issuer, rvType) },
		},
		"with an expiry still ahead": {
			reference: "7.2.2 step 7",
			body: func(owner, issuer string) map[string]any {
				body := dlgBody(owner, issuer, rvType)
				body["exp"] = time.Now().Add(time.Hour).UTC().Unix()
				return body
			},
		},
		"with a ref claim it does not read": {
			reference: "7.2.1",
			body: func(owner, issuer string) map[string]any {
				body := dlgBody(owner, issuer, rvType)
				body["ref"] = "https://owner.example.com/about"
				return body
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			ownerKey := rvKey(t)
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")}

			delegation := dlgSign(t, ownerKey, dlgHead("owner-key"), tc.body(dlgOwner, issuer))
			tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)
			if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 1 {
				t.Errorf("[%s] a delegation that meets every step of 7.2.2 must be accepted, got %d trust marks", tc.reference, len(got))
			}
		})
	}
}

func TestFilterByTrusted_ADelegationThatFailsAStepIsDropped(t *testing.T) {
	tests := map[string]struct {
		reference string
		head      func(kid string) map[string]any
		body      func(owner, issuer string) map[string]any
		signWith  func(t *testing.T, ownerKey *rsa.PrivateKey) crypto.Signer
		raw       *string
	}{
		"not a signed JWT": {
			reference: "7.2.2 step 1",
			raw:       func() *string { s := "not-a-jwt"; return &s }(),
		},
		"three parts that are not base64url": {
			reference: "7.2.2 step 1",
			raw:       func() *string { s := "aaa.bbb.ccc"; return &s }(),
		},
		"an empty delegation": {
			reference: "7.2.2 step 1",
			raw:       func() *string { s := ""; return &s }(),
		},
		"no typ header": {
			reference: "7.2.2 step 2",
			head:      func(kid string) map[string]any { return map[string]any{"kid": kid, "alg": "RS256"} },
		},
		"a typ header of JWT": {
			reference: "7.2.2 step 2",
			head:      func(kid string) map[string]any { return map[string]any{"kid": kid, "typ": "JWT", "alg": "RS256"} },
		},
		"a typ header of trust-mark+jwt": {
			reference: "7.2.2 step 2",
			head: func(kid string) map[string]any {
				return map[string]any{"kid": kid, "typ": "trust-mark+jwt", "alg": "RS256"}
			},
		},
		"no kid header": {
			reference: "7.2.1",
			head:      func(string) map[string]any { return map[string]any{"typ": "trust-mark-delegation+jwt", "alg": "RS256"} },
		},
		"a kid the owner does not publish": {
			reference: "7.2.2 step 9",
			head:      func(string) map[string]any { return dlgHead("some-other-key") },
		},
		"a sub that is not the trust mark issuer": {
			reference: "7.2.2 step 4",
			body: func(owner, issuer string) map[string]any {
				return dlgBody(owner, "https://someone-else.example.com", rvType)
			},
		},
		"no sub claim": {
			reference: "7.2.2 step 4",
			body: func(owner, issuer string) map[string]any {
				body := dlgBody(owner, issuer, rvType)
				delete(body, "sub")
				return body
			},
		},
		"an iss that is not the owner the anchor names": {
			reference: "7.2.2 step 5",
			body: func(owner, issuer string) map[string]any {
				return dlgBody("https://not-the-owner.example.com", issuer, rvType)
			},
		},
		"no iss claim": {
			reference: "7.2.2 step 5",
			body: func(owner, issuer string) map[string]any {
				body := dlgBody(owner, issuer, rvType)
				delete(body, "iss")
				return body
			},
		},
		"a trust_mark_type that is not the trust mark's": {
			reference: "7.2.2 step 8",
			body: func(owner, issuer string) map[string]any {
				return dlgBody(owner, issuer, "https://tm.example.com/something-else")
			},
		},
		"no trust_mark_type claim": {
			reference: "7.2.2 step 8",
			body: func(owner, issuer string) map[string]any {
				body := dlgBody(owner, issuer, rvType)
				delete(body, "trust_mark_type")
				return body
			},
		},
		"no iat claim": {
			reference: "7.2.2 step 6",
			body: func(owner, issuer string) map[string]any {
				body := dlgBody(owner, issuer, rvType)
				delete(body, "iat")
				return body
			},
		},
		"an iat in the future": {
			reference: "7.2.2 step 6",
			body: func(owner, issuer string) map[string]any {
				body := dlgBody(owner, issuer, rvType)
				body["iat"] = time.Now().Add(time.Hour).UTC().Unix()
				return body
			},
		},
		"an exp in the past": {
			reference: "7.2.2 step 7",
			body: func(owner, issuer string) map[string]any {
				body := dlgBody(owner, issuer, rvType)
				body["exp"] = time.Now().Add(-time.Hour).UTC().Unix()
				return body
			},
		},
		"signed by a key the owner does not hold": {
			reference: "7.2.2 step 9",
			signWith:  func(t *testing.T, _ *rsa.PrivateKey) crypto.Signer { return rvKey(t) },
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			ownerKey := rvKey(t)
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")}

			delegation := ""
			if tc.raw != nil {
				delegation = *tc.raw
			} else {
				head := dlgHead("owner-key")
				if tc.head != nil {
					head = tc.head("owner-key")
				}
				body := dlgBody(dlgOwner, issuer, rvType)
				if tc.body != nil {
					body = tc.body(dlgOwner, issuer)
				}
				var signer crypto.Signer = ownerKey
				if tc.signWith != nil {
					signer = tc.signWith(t, ownerKey)
				}
				delegation = dlgSign(t, signer, head, body)
			}

			tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)
			if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 0 {
				t.Errorf("[%s] a delegation that fails a validation step makes the whole validation fail, so the trust mark must be dropped", tc.reference)
			}
		})
	}
}

func TestFilterByTrusted_ADelegationForATypeWithNoOwnerIsDropped(t *testing.T) {
	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("member")
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
	ownerKey := rvKey(t)

	delegation := dlgSign(t, ownerKey, dlgHead("owner-key"), dlgBody(dlgOwner, issuer, rvType))
	tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)
	if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 0 {
		t.Error("[7.2.2 step 9] the owner's keys come from trust_mark_owners, so a delegation for a type the anchor names no owner for has nothing to verify it against and must be dropped")
	}
}

func TestFilterByTrusted_ATypeWithNoOwnerNeedsNoDelegation(t *testing.T) {
	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("member")
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})

	tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, nil)
	if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 1 {
		t.Errorf("[7.3 step 8] a delegation is required only when the type appears in trust_mark_owners, got %d trust marks", len(got))
	}
}

func TestFilterByTrusted_AnUnusableOwnerKeyDoesNotBlockTheDelegation(t *testing.T) {
	tests := map[string]struct {
		reference string
		sibling   map[string]any
	}{
		"a sibling key with no kid": {
			reference: "RFC 7517 4.5",
			sibling:   map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB"},
		},
		"a sibling key of an unknown kty": {
			reference: "RFC 7517 5",
			sibling:   map[string]any{"kty": "AKP", "kid": "pq-key", "pub": "AQAB"},
		},
		"a sibling key whose kid is not a string": {
			reference: "RFC 7517 4.5",
			sibling:   map[string]any{"kty": "RSA", "kid": 7, "n": "AQAB", "e": "AQAB"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			ownerKey := rvKey(t)
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key", tc.sibling)}

			delegation := dlgSign(t, ownerKey, dlgHead("owner-key"), dlgBody(dlgOwner, issuer, rvType))
			tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)
			if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 1 {
				t.Errorf("[%s] a key beside the signing key that this library cannot use must not stop the delegation verifying, got %d trust marks", tc.reference, len(got))
			}
		})
	}
}

func TestValidate_ADelegationRefusalNamesTheClauseItFailed(t *testing.T) {
	tests := map[string]struct {
		reference string
		expect    string
		head      map[string]any
		body      func(owner, issuer string) map[string]any
	}{
		"an algorithm of none is not a key failure": {
			reference: "7.2.2 step 3",
			expect:    "'alg' header",
			head:      map[string]any{"kid": "owner-key", "typ": "trust-mark-delegation+jwt", "alg": "none"},
		},
		"a missing algorithm is not a key failure": {
			reference: "7.2.2 step 3",
			expect:    "'alg' header",
			head:      map[string]any{"kid": "owner-key", "typ": "trust-mark-delegation+jwt"},
		},
		"an expired delegation is not a signature failure": {
			reference: "7.2.2 step 7",
			expect:    "expired",
			body: func(owner, issuer string) map[string]any {
				body := dlgBody(owner, issuer, rvType)
				body["exp"] = time.Now().Add(-time.Hour).UTC().Unix()
				return body
			},
		},
		"a delegation issued in the future is not a signature failure": {
			reference: "7.2.2 step 6",
			expect:    "issuance time that has not yet arrived",
			body: func(owner, issuer string) map[string]any {
				body := dlgBody(owner, issuer, rvType)
				body["iat"] = time.Now().Add(time.Hour).UTC().Unix()
				return body
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			ownerKey := rvKey(t)
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")}

			body := dlgBody(dlgOwner, issuer, rvType)
			if tc.body != nil {
				body = tc.body(dlgOwner, issuer)
			}
			delegation := dlgSign(t, ownerKey, dlgHead("owner-key"), body)
			if tc.head != nil {
				delegation = dlgRaw(t, tc.head, body, "")
			}
			tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)

			_, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, tm, ValidateOptions{
				ExpectedType:             rvType,
				ExpectedSubject:          rvSub,
				AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(issuer)},
				TrustAnchor:              ta.Sub,
				TrustAnchorConfiguration: ta,
			}, nil)
			if err == nil {
				t.Fatalf("[%s] expected the delegation to be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("[%s] the refusal must name the step the delegation failed rather than blaming its signature, got %q", tc.reference, err.Error())
			}
		})
	}
}

func dlgRaw(t *testing.T, head, body map[string]any, signature string) string {
	t.Helper()
	headBytes, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(headBytes) + "." + base64.RawURLEncoding.EncodeToString(bodyBytes) + "." + signature
}

func TestFilterByTrusted_ADelegationMustNameASigningAlgorithm(t *testing.T) {
	tests := map[string]struct {
		reference string
		head      map[string]any
	}{
		"an alg of none": {
			reference: "7.2.2 step 3",
			head:      map[string]any{"kid": "owner-key", "typ": "trust-mark-delegation+jwt", "alg": "none"},
		},
		"no alg header": {
			reference: "7.2.2 step 3",
			head:      map[string]any{"kid": "owner-key", "typ": "trust-mark-delegation+jwt"},
		},
		"an alg that is not a string": {
			reference: "7.2.2 step 3",
			head:      map[string]any{"kid": "owner-key", "typ": "trust-mark-delegation+jwt", "alg": 256},
		},
		"an empty alg": {
			reference: "7.2.2 step 3",
			head:      map[string]any{"kid": "owner-key", "typ": "trust-mark-delegation+jwt", "alg": ""},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			ownerKey := rvKey(t)
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")}

			delegation := dlgRaw(t, tc.head, dlgBody(dlgOwner, issuer, rvType), "")
			tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)
			if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 0 {
				t.Errorf("[%s] a delegation must name an acceptable signing algorithm and it must not be 'none', got %d trust marks", tc.reference, len(got))
			}
		})
	}
}

func TestFilterByTrusted_AMalformedOwnerKeySharingTheKidIsSkipped(t *testing.T) {
	tests := map[string]struct {
		reference string
		malformed map[string]any
	}{
		"a kty that is an object": {
			reference: "RFC 7517 4.1",
			malformed: map[string]any{"kid": "owner-key", "kty": map[string]any{"nested": true}, "n": "AQAB", "e": "AQAB"},
		},
		"a kty that is a number": {
			reference: "RFC 7517 4.1",
			malformed: map[string]any{"kid": "owner-key", "kty": 7, "n": "AQAB", "e": "AQAB"},
		},
		"no kty at all": {
			reference: "RFC 7517 4.1",
			malformed: map[string]any{"kid": "owner-key", "n": "AQAB", "e": "AQAB"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("[%s] selecting the owner's key must not panic on an entry whose 'kty' is not a string: %v", tc.reference, recovered)
				}
			}()

			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			ownerKey := rvKey(t)
			owner := dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")
			owner.JWKs.Keys = append([]map[string]any{tc.malformed}, owner.JWKs.Keys...)
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: owner}

			delegation := dlgSign(t, ownerKey, dlgHead("owner-key"), dlgBody(dlgOwner, issuer, rvType))
			tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)
			if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 1 {
				t.Errorf("[%s] an unusable entry carrying the same 'kid' must be skipped so the usable key behind it is found, got %d trust marks", tc.reference, len(got))
			}
		})
	}
}
