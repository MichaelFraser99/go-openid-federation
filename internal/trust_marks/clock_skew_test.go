package trust_marks

import (
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func skewedTrustMark(t *testing.T, f *rvFed, issuer string, claim string, at time.Duration) string {
	t.Helper()
	body := map[string]any{
		"iss": issuer, "sub": rvSub, "trust_mark_type": rvType,
		"iat": time.Now().Add(-time.Minute).UTC().Unix(),
		"exp": time.Now().Add(time.Hour).UTC().Unix(),
	}
	body[claim] = time.Now().Add(at).UTC().Unix()
	token, err := jwt.New(f.ecKey["member"], map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256"}, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to sign the trust mark: %v", err)
	}
	return *token
}

func TestFilterByTrusted_ATrustMarkGetsTheSameClockSkewLeewayAsAStatement(t *testing.T) {
	tests := map[string]struct {
		reference string
		claim     string
		at        time.Duration
		keep      bool
	}{
		"an exp just inside the leeway":    {reference: "7.3 step 6", claim: "exp", at: -model.ClockSkewLeeway / 2, keep: true},
		"an exp well beyond the leeway":    {reference: "7.3 step 6", claim: "exp", at: -10 * model.ClockSkewLeeway, keep: false},
		"an iat just inside the leeway":    {reference: "7.3 step 5", claim: "iat", at: model.ClockSkewLeeway / 2, keep: true},
		"an iat well beyond the leeway":    {reference: "7.3 step 5", claim: "iat", at: 10 * model.ClockSkewLeeway, keep: false},
		"an exp comfortably in the future": {reference: "7.3 step 6", claim: "exp", at: time.Hour, keep: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})

			tm := skewedTrustMark(t, f, issuer, tc.claim, tc.at)
			got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm})
			if tc.keep && len(got) != 1 {
				t.Errorf("[%s] a trust mark within the clock skew allowance an entity statement gets must be kept, got %d trust marks", tc.reference, len(got))
			}
			if !tc.keep && len(got) != 0 {
				t.Errorf("[%s] a trust mark beyond the allowance must be dropped, got %d trust marks", tc.reference, len(got))
			}
		})
	}
}

func TestFilterByTrusted_ADelegationGetsTheSameClockSkewLeeway(t *testing.T) {
	tests := map[string]struct {
		reference string
		claim     string
		at        time.Duration
		keep      bool
	}{
		"an exp just inside the leeway": {reference: "7.2.2 step 7", claim: "exp", at: -model.ClockSkewLeeway / 2, keep: true},
		"an exp well beyond the leeway": {reference: "7.2.2 step 7", claim: "exp", at: -10 * model.ClockSkewLeeway, keep: false},
		"an iat just inside the leeway": {reference: "7.2.2 step 6", claim: "iat", at: model.ClockSkewLeeway / 2, keep: true},
		"an iat well beyond the leeway": {reference: "7.2.2 step 6", claim: "iat", at: 10 * model.ClockSkewLeeway, keep: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			ownerKey := rvKey(t)
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")}

			body := dlgBody(dlgOwner, issuer, rvType)
			body[tc.claim] = time.Now().Add(tc.at).UTC().Unix()
			delegation := dlgSign(t, ownerKey, dlgHead("owner-key"), body)
			tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)

			got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm})
			if tc.keep && len(got) != 1 {
				t.Errorf("[%s] a delegation within the clock skew allowance must be kept, got %d trust marks", tc.reference, len(got))
			}
			if !tc.keep && len(got) != 0 {
				t.Errorf("[%s] a delegation beyond the allowance must be dropped, got %d trust marks", tc.reference, len(got))
			}
		})
	}
}

func TestValidate_ASkewedDelegationStillNamesTheRightFault(t *testing.T) {
	tests := map[string]struct {
		reference string
		claim     string
		at        time.Duration
		expect    string
	}{
		"an expired delegation": {reference: "7.2.2 step 7", claim: "exp", at: -10 * model.ClockSkewLeeway, expect: "expired"},
		"a future delegation":   {reference: "7.2.2 step 6", claim: "iat", at: 10 * model.ClockSkewLeeway, expect: "issuance time that has not yet arrived"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			ownerKey := rvKey(t)
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")}

			body := dlgBody(dlgOwner, issuer, rvType)
			body[tc.claim] = time.Now().Add(tc.at).UTC().Unix()
			delegation := dlgSign(t, ownerKey, dlgHead("owner-key"), body)
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
				t.Errorf("[%s] the refusal must still name the clock fault rather than the signature, got %q", tc.reference, err.Error())
			}
		})
	}
}
