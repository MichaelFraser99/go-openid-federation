package trust_marks

import (
	"bytes"
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func dlgSignRaw(t *testing.T, key *rsa.PrivateKey, head, body map[string]any) string {
	t.Helper()
	headBytes, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(headBytes) + "." + base64.RawURLEncoding.EncodeToString(bodyBytes)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(crand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

type dlgFixture struct {
	fed      *rvFed
	issuer   string
	anchor   model.EntityStatement
	ownerKey *rsa.PrivateKey
}

func dlgSetup(t *testing.T) dlgFixture {
	t.Helper()
	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("member")
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
	ownerKey := rvKey(t)
	ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")}
	return dlgFixture{fed: f, issuer: issuer, anchor: ta, ownerKey: ownerKey}
}

func (d dlgFixture) kept(t *testing.T, delegation string) int {
	t.Helper()
	tm := dlgMark(t, d.fed.ecKey["member"], "test-key", d.issuer, rvType, rvSub, &delegation)
	return len(d.fed.filter(t, d.anchor, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}))
}

func (d dlgFixture) refusal(t *testing.T, delegation string) error {
	t.Helper()
	tm := dlgMark(t, d.fed.ecKey["member"], "test-key", d.issuer, rvType, rvSub, &delegation)
	_, err := Validate(t.Context(), model.Configuration{HttpClient: d.fed.server.Client()}, tm, ValidateOptions{
		ExpectedType:             rvType,
		ExpectedSubject:          rvSub,
		AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(d.issuer)},
		TrustAnchor:              d.anchor.Sub,
		TrustAnchorConfiguration: d.anchor,
	}, nil)
	return err
}

func TestFilterByTrusted_ADelegationWithNoTypHeaderAtAllIsDropped(t *testing.T) {
	d := dlgSetup(t)
	delegation := dlgSignRaw(t, d.ownerKey, map[string]any{"kid": "owner-key", "alg": "RS256"}, dlgBody(dlgOwner, d.issuer, rvType))
	if got := d.kept(t, delegation); got != 0 {
		t.Errorf("[7.2.1] a delegation without a typ header must be rejected, got %d trust marks", got)
	}
}

func TestFilterByTrusted_ADelegationIsBoundToItsClaimsExactly(t *testing.T) {
	tests := map[string]struct {
		reference string
		body      func(d dlgFixture) map[string]any
	}{
		"a sub differing from the issuer only in case": {reference: "7.2.2 step 4", body: func(d dlgFixture) map[string]any {
			return dlgBody(dlgOwner, strings.ToUpper(d.issuer), rvType)
		}},
		"a sub that is a prefix of the issuer": {reference: "7.2.2 step 4", body: func(d dlgFixture) map[string]any {
			return dlgBody(dlgOwner, d.issuer[:len(d.issuer)-2], rvType)
		}},
		"an iss that is the issuer rather than the owner": {reference: "7.2.2 step 5", body: func(d dlgFixture) map[string]any {
			return dlgBody(d.issuer, d.issuer, rvType)
		}},
		"a trust_mark_type differing only in case": {reference: "7.2.2 step 8", body: func(d dlgFixture) map[string]any {
			return dlgBody(dlgOwner, d.issuer, strings.ToUpper(rvType))
		}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := dlgSetup(t)
			delegation := dlgSignRaw(t, d.ownerKey, dlgHead("owner-key"), tc.body(d))
			if got := d.kept(t, delegation); got != 0 {
				t.Errorf("[%s] an owner-signed delegation whose claims do not match exactly must be dropped, got %d trust marks", tc.reference, got)
			}
		})
	}
}

func TestFilterByTrusted_AKeyCarriedInTheDelegationIsNotTrusted(t *testing.T) {
	d := dlgSetup(t)
	attacker := rvKey(t)
	head := dlgHead("owner-key")
	head["jwk"] = federationPublicJwk(t, attacker.Public(), "owner-key")
	delegation := dlgSignRaw(t, attacker, head, dlgBody(dlgOwner, d.issuer, rvType))
	if got := d.kept(t, delegation); got != 0 {
		t.Errorf("[7.2.2 step 9] the owner's keys come only from trust_mark_owners, so a key the delegation carries must not verify it, got %d trust marks", got)
	}
}

func TestFilterByTrusted_AnUnusableOwnerKeyAheadOfTheSigningKeyDoesNotStopTheSearch(t *testing.T) {
	tests := map[string]struct {
		reference string
		shadow    func(t *testing.T) map[string]any
	}{
		"an encryption key under the same kid": {reference: "7.2.2 step 9", shadow: func(t *testing.T) map[string]any {
			key := federationPublicJwk(t, rvKey(t).Public(), "owner-key")
			key["use"] = "enc"
			return key
		}},
		"a weak key under the same kid": {reference: "7.2.2 step 9", shadow: func(t *testing.T) map[string]any {
			weak, err := rsa.GenerateKey(crand.Reader, 1024)
			if err != nil {
				t.Fatal(err)
			}
			return federationPublicJwk(t, weak.Public(), "owner-key")
		}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := dlgSetup(t)
			signing := federationPublicJwk(t, d.ownerKey.Public(), "owner-key")
			d.anchor.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: {Sub: dlgOwner, JWKs: josemodel.Jwks{Keys: []map[string]any{tc.shadow(t), signing}}}}
			delegation := dlgSignRaw(t, d.ownerKey, dlgHead("owner-key"), dlgBody(dlgOwner, d.issuer, rvType))
			if got := d.kept(t, delegation); got != 1 {
				t.Errorf("[%s] the signature must validate using one of the owner's keys carrying the kid, so a key the rules refuse ahead of the signing key must be skipped, got %d trust marks", tc.reference, got)
			}
		})
	}
}

func TestFilterByTrusted_AnOwnerKeyCarryingPrivateMaterialDoesNotAuthorise(t *testing.T) {
	tests := map[string]struct {
		reference string
		member    string
		value     any
	}{
		"an rsa private exponent": {reference: "RFC 7518 6.3.2", member: "d", value: "AQAB"},
		"an rsa first prime":      {reference: "RFC 7518 6.3.2", member: "p", value: "AQAB"},
		"a symmetric key value":   {reference: "RFC 7518 6.4.1", member: "k", value: "AQAB"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := dlgSetup(t)
			leaked := federationPublicJwk(t, d.ownerKey.Public(), "owner-key")
			leaked[tc.member] = tc.value
			d.anchor.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: {Sub: dlgOwner, JWKs: josemodel.Jwks{Keys: []map[string]any{leaked}}}}

			delegation := dlgSignRaw(t, d.ownerKey, dlgHead("owner-key"), dlgBody(dlgOwner, d.issuer, rvType))
			if got := d.kept(t, delegation); got != 0 {
				t.Errorf("[%s] an owner key the anchor published with private material lets anyone mint a delegation for this type, so it must not authorise one, got %d trust marks", tc.reference, got)
			}
		})
	}
}

func TestFilterByTrusted_AnEmptyDelegationOnAnUnownedTypeIsStillPresent(t *testing.T) {
	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("member")
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
	empty := ""
	tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &empty)
	if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 0 {
		t.Errorf("[7.3 step 9] a delegation claim present as the empty string is present and cannot be validated, so the trust mark must be dropped, got %d trust marks", len(got))
	}
}

func TestValidate_ADelegationRefusalNamesTheClaimItLacks(t *testing.T) {
	tests := map[string]struct {
		reference string
		build     func(t *testing.T, d dlgFixture) string
		expect    string
	}{
		"no sub claim": {reference: "7.2.1", expect: `missing the required claim "sub"`, build: func(t *testing.T, d dlgFixture) string {
			body := dlgBody(dlgOwner, d.issuer, rvType)
			delete(body, "sub")
			return dlgSignRaw(t, d.ownerKey, dlgHead("owner-key"), body)
		}},
		"no iss claim": {reference: "7.2.1", expect: `missing the required claim "iss"`, build: func(t *testing.T, d dlgFixture) string {
			body := dlgBody(dlgOwner, d.issuer, rvType)
			delete(body, "iss")
			return dlgSignRaw(t, d.ownerKey, dlgHead("owner-key"), body)
		}},
		"no trust_mark_type claim": {reference: "7.2.1", expect: `missing the required claim "trust_mark_type"`, build: func(t *testing.T, d dlgFixture) string {
			body := dlgBody(dlgOwner, d.issuer, rvType)
			delete(body, "trust_mark_type")
			return dlgSignRaw(t, d.ownerKey, dlgHead("owner-key"), body)
		}},
		"four segments": {reference: "7.2.2 step 1", expect: "not a signed JWT", build: func(t *testing.T, d dlgFixture) string {
			return dlgSignRaw(t, d.ownerKey, dlgHead("owner-key"), dlgBody(dlgOwner, d.issuer, rvType)) + ".extra"
		}},
		"a header that is not base64url": {reference: "7.2.2 step 1", expect: "header that cannot be decoded", build: func(t *testing.T, d dlgFixture) string {
			return "!!!!." + base64.RawURLEncoding.EncodeToString([]byte("{}")) + ".sig"
		}},
		"a body that is not base64url": {reference: "7.2.2 step 1", expect: "body that cannot be decoded", build: func(t *testing.T, d dlgFixture) string {
			head, err := json.Marshal(dlgHead("owner-key"))
			if err != nil {
				t.Fatal(err)
			}
			return base64.RawURLEncoding.EncodeToString(head) + ".!!!!.sig"
		}},
		"a kid the owner does not publish": {reference: "7.2.2 step 9", expect: "does not publish a usable key", build: func(t *testing.T, d dlgFixture) string {
			return dlgSignRaw(t, d.ownerKey, dlgHead("not-published"), dlgBody(dlgOwner, d.issuer, rvType))
		}},
		"a signature from a key the owner does not hold": {reference: "7.2.2 step 9", expect: "signature does not verify", build: func(t *testing.T, d dlgFixture) string {
			return dlgSignRaw(t, rvKey(t), dlgHead("owner-key"), dlgBody(dlgOwner, d.issuer, rvType))
		}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := dlgSetup(t)
			err := d.refusal(t, tc.build(t, d))
			if err == nil {
				t.Fatalf("[%s] expected the delegation to be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("[%s] expected the refusal to name %q, got %q", tc.reference, tc.expect, err.Error())
			}
		})
	}
}

func TestFilterByTrusted_EveryDelegationValueIsBoundedInTheLog(t *testing.T) {
	const marker = "DLG-VALUE-MARKER"
	long := strings.Repeat("h", 8192) + marker

	tests := map[string]struct {
		reference string
		head      func() map[string]any
		body      func(d dlgFixture) map[string]any
		ownerKid  string
		signWith  func(t *testing.T) *rsa.PrivateKey
	}{
		"a long sub":             {reference: "8.9", body: func(d dlgFixture) map[string]any { return dlgBody(dlgOwner, "https://x.example.com/"+long, rvType) }},
		"a long iss":             {reference: "8.9", body: func(d dlgFixture) map[string]any { return dlgBody("https://x.example.com/"+long, d.issuer, rvType) }},
		"a long trust_mark_type": {reference: "8.9", body: func(d dlgFixture) map[string]any { return dlgBody(dlgOwner, d.issuer, "https://x.example.com/"+long) }},
		"a long unpublished kid": {reference: "8.9", head: func() map[string]any { return dlgHead(long) }},
		"a long published kid with a bad signature": {reference: "8.9", head: func() map[string]any { return dlgHead(long) }, ownerKid: long, signWith: func(t *testing.T) *rsa.PrivateKey { return rvKey(t) }},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := dlgSetup(t)
			if tc.ownerKid != "" {
				d.anchor.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, d.ownerKey, tc.ownerKid)}
			}
			head := dlgHead("owner-key")
			if tc.head != nil {
				head = tc.head()
			}
			body := dlgBody(dlgOwner, d.issuer, rvType)
			if tc.body != nil {
				body = tc.body(d)
			}
			signer := d.ownerKey
			if tc.signWith != nil {
				signer = tc.signWith(t)
			}
			delegation := dlgSignRaw(t, signer, head, body)

			var logs bytes.Buffer
			cfg := model.Configuration{
				HttpClient: d.fed.server.Client(),
				Logger:     slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			}
			tm := dlgMark(t, d.fed.ecKey["member"], "test-key", d.issuer, rvType, rvSub, &delegation)
			resolved := &model.ResolveResponse{Sub: rvSub, Exp: time.Now().Add(time.Hour).UTC().Unix(),
				TrustMarks: []model.TrustMarkHolder{{TrustMarkType: rvType, TrustMark: tm}}}

			if err := FilterByTrusted(t.Context(), cfg, resolved, d.anchor, nil); err != nil {
				t.Fatalf("[%s] a mark whose delegation fails is dropped rather than refusing the resolve, got %v", tc.reference, err)
			}
			if len(resolved.TrustMarks) != 0 {
				t.Fatalf("[%s] expected the mark to be dropped", tc.reference)
			}
			if strings.Contains(logs.String(), marker) {
				t.Errorf("[%s] the tail of a value the trust mark issuer chose reached the log, so it is being logged whole", tc.reference)
			}
		})
	}
}
