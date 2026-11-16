package trust_marks

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func rawSigned(t *testing.T, key *rsa.PrivateKey, head, body string) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(head)) + "." + base64.RawURLEncoding.EncodeToString([]byte(body))
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(crand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func jsonWithRepeat(t *testing.T, object map[string]any, name string) string {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if name == "" {
		return string(raw)
	}
	value, err := json.Marshal(object[name])
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(string(raw), "}") + `,"` + name + `":` + string(value) + "}"
}

func (d dlgFixture) refusalOfMark(t *testing.T, trustMark string) error {
	t.Helper()
	_, err := Validate(t.Context(), model.Configuration{HttpClient: d.fed.server.Client()}, trustMark, ValidateOptions{
		ExpectedType:             rvType,
		ExpectedSubject:          rvSub,
		AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(d.issuer)},
		TrustAnchor:              d.anchor.Sub,
		TrustAnchorConfiguration: d.anchor,
	}, nil)
	return err
}

func TestValidate_RefusesARepeatedNameInADelegation(t *testing.T) {
	tests := map[string]struct {
		headRepeat string
		bodyRepeat string
		says       string
	}{
		"a clean delegation":                {},
		"a delegation header repeating kid": {headRepeat: "kid", says: "the JWT header repeats a member name"},
		"a delegation body repeating sub":   {bodyRepeat: "sub", says: "the JWT claims set repeats a member name"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := dlgSetup(t)
			delegation := rawSigned(t, d.ownerKey, jsonWithRepeat(t, dlgHead("owner-key"), tc.headRepeat), jsonWithRepeat(t, dlgBody(dlgOwner, d.issuer, rvType), tc.bodyRepeat))
			err := d.refusal(t, delegation)
			if tc.says == "" {
				if err != nil {
					t.Fatalf("expected the delegation to be accepted, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("[RFC 7515/7519 4] expected a refusal containing %q, got %v", tc.says, err)
			}
		})
	}
}

func TestValidate_RefusesARepeatedNameInATrustMark(t *testing.T) {
	tests := map[string]struct {
		headRepeat string
		bodyRepeat string
		says       string
	}{
		"a clean trust mark":                {},
		"a trust mark header repeating typ": {headRepeat: "typ", says: "the JWT header repeats a member name"},
		"a trust mark body repeating iss":   {bodyRepeat: "iss", says: "the JWT claims set repeats a member name"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := dlgSetup(t)
			delegation := dlgSignRaw(t, d.ownerKey, dlgHead("owner-key"), dlgBody(dlgOwner, d.issuer, rvType))
			head := map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256"}
			body := map[string]any{
				"iss": d.issuer, "sub": rvSub, "trust_mark_type": rvType,
				"iat": time.Now().UTC().Unix(), "exp": time.Now().Add(time.Hour).UTC().Unix(),
				"delegation": delegation,
			}
			trustMark := rawSigned(t, d.fed.ecKey["member"], jsonWithRepeat(t, head, tc.headRepeat), jsonWithRepeat(t, body, tc.bodyRepeat))
			err := d.refusalOfMark(t, trustMark)
			if tc.says == "" {
				if err != nil {
					t.Fatalf("expected the trust mark to be accepted, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("[RFC 7515/7519 4] expected a refusal containing %q, got %v", tc.says, err)
			}
		})
	}
}

func TestIssuedBy_ATrustMarkRepeatingItsIssuerIsNotThisServers(t *testing.T) {
	const server = model.EntityIdentifier("https://server.example.com")
	encode := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	mark := func(body string) string {
		return encode(`{"alg":"ES256"}`) + "." + encode(body) + "." + encode("signature")
	}

	if !issuedBy(mark(`{"iss":"https://server.example.com"}`), server, model.DefaultMaxStatementValues) {
		t.Fatalf("expected a mark this server issued to be recognised")
	}
	if issuedBy(mark(`{"iss":"https://other.example.com","iss":"https://server.example.com"}`), server, model.DefaultMaxStatementValues) {
		t.Errorf("[RFC 7519 4] expected a mark repeating iss not to be taken as this server's")
	}
}

func TestVerifyIssued_RefusesAHeaderRepeatingAName(t *testing.T) {
	const (
		issuer   = model.EntityIdentifier("https://server.example.com")
		subject  = model.EntityIdentifier("https://leaf.example.com")
		markType = "https://tm.example.com/a"
	)
	encode := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	body := encode(`{"iss":"https://server.example.com","sub":"https://leaf.example.com","trust_mark_type":"https://tm.example.com/a","iat":1}`)
	mark := func(head string) string { return encode(head) + "." + body + "." + encode("signature") }

	if err := verifyIssued(mark(`{"kid":"k","typ":"trust-mark+jwt","alg":"ES256"}`), issuer, markType, subject); err != nil {
		t.Fatalf("expected a well formed mark to pass, got %v", err)
	}
	err := verifyIssued(mark(`{"kid":"k","typ":"trust-mark+jwt","alg":"ES256","kid":"k"}`), issuer, markType, subject)
	if err == nil || !strings.Contains(err.Error(), "the JWT header repeats a member name") {
		t.Fatalf("[RFC 7515 4] expected a repeated header parameter to be refused, got %v", err)
	}
}
