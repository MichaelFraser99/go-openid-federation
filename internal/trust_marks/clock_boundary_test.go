package trust_marks

import (
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func withinOneSecond(t *testing.T, run func(now int64) bool) {
	t.Helper()
	for attempt := 0; attempt < 6; attempt++ {
		next := time.Now().Truncate(time.Second).Add(time.Second + 5*time.Millisecond)
		time.Sleep(time.Until(next))
		started := time.Now().Unix()
		satisfied := run(started)
		if time.Now().Unix() == started {
			if !satisfied {
				t.FailNow()
			}
			return
		}
	}
	t.Skip("could not complete the check inside a single wall-clock second")
}

func markWithClaims(t *testing.T, f *rvFed, issuer string, claims map[string]any) string {
	t.Helper()
	body := map[string]any{"iss": issuer, "sub": rvSub, "trust_mark_type": rvType}
	for claim, value := range claims {
		if value == nil {
			delete(body, claim)
			continue
		}
		body[claim] = value
	}
	token, err := jwt.New(f.ecKey["member"], map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256"}, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to sign the trust mark: %v", err)
	}
	return *token
}

func TestValidate_TheTrustMarkAllowanceIsExactlySixtySeconds(t *testing.T) {
	tests := map[string]struct {
		reference string
		claim     string
		offset    int64
		valid     bool
	}{
		"an iat 60 seconds ahead is valid": {reference: "7.3 step 5", claim: "iat", offset: 60, valid: true},
		"an iat 61 seconds ahead is not":   {reference: "7.3 step 5", claim: "iat", offset: 61, valid: false},
		"an exp 59 seconds past is valid":  {reference: "7.3 step 6", claim: "exp", offset: -59, valid: true},
		"an exp 60 seconds past is not":    {reference: "7.3 step 6", claim: "exp", offset: -60, valid: false},
		"an nbf 60 seconds ahead is valid": {reference: "RFC 7519 4.1.5", claim: "nbf", offset: 60, valid: true},
		"an nbf 61 seconds ahead is not":   {reference: "RFC 7519 4.1.5", claim: "nbf", offset: 61, valid: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})

			withinOneSecond(t, func(now int64) bool {
				claims := map[string]any{"iat": now - 120, "exp": now + 3600}
				claims[tc.claim] = now + tc.offset
				_, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, markWithClaims(t, f, issuer, claims), ValidateOptions{
					ExpectedType:             rvType,
					ExpectedSubject:          rvSub,
					AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(issuer)},
					TrustAnchor:              ta.Sub,
					TrustAnchorConfiguration: ta,
				}, nil)
				if tc.valid && err != nil {
					t.Logf("[%s] expected valid at %+ds, got %v", tc.reference, tc.offset, err)
					return false
				}
				if !tc.valid && err == nil {
					t.Logf("[%s] expected invalid at %+ds, got no error", tc.reference, tc.offset)
					return false
				}
				return true
			})
		})
	}
}

func TestFilterByTrusted_TheDelegationAllowanceIsExactlySixtySeconds(t *testing.T) {
	tests := map[string]struct {
		reference string
		claim     string
		offset    int64
		keep      bool
	}{
		"an iat 60 seconds ahead is kept":    {reference: "7.2.2 step 6", claim: "iat", offset: 60, keep: true},
		"an iat 61 seconds ahead is dropped": {reference: "7.2.2 step 6", claim: "iat", offset: 61, keep: false},
		"an exp 59 seconds past is kept":     {reference: "7.2.2 step 7", claim: "exp", offset: -59, keep: true},
		"an exp 60 seconds past is dropped":  {reference: "7.2.2 step 7", claim: "exp", offset: -60, keep: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			ownerKey := rvKey(t)
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")}

			withinOneSecond(t, func(now int64) bool {
				body := dlgBody(dlgOwner, issuer, rvType)
				body["iat"] = now - 120
				body[tc.claim] = now + tc.offset
				delegation := dlgSign(t, ownerKey, dlgHead("owner-key"), body)
				tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)
				got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm})
				if tc.keep != (len(got) == 1) {
					t.Logf("[%s] keep=%v at %+ds but got %d marks", tc.reference, tc.keep, tc.offset, len(got))
					return false
				}
				return true
			})
		})
	}
}

func TestFilterByTrusted_TheOmissionBoundaryIsTheCurrentSecond(t *testing.T) {
	tests := map[string]struct {
		reference string
		offset    int64
		keep      bool
	}{
		"an expiry of exactly now is omitted": {reference: "8.3.2", offset: 0, keep: false},
		"an expiry one second ahead is kept":  {reference: "8.3.2", offset: 1, keep: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})

			withinOneSecond(t, func(now int64) bool {
				tm := markWithClaims(t, f, issuer, map[string]any{"iat": now - 120, "exp": now + tc.offset})
				got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm})
				if tc.keep != (len(got) == 1) {
					t.Logf("[%s] keep=%v at exp=now%+d but got %d marks", tc.reference, tc.keep, tc.offset, len(got))
					return false
				}
				return true
			})
		})
	}
}

func TestFilterByTrusted_OneExpiredMarkDoesNotCostTheOthers(t *testing.T) {
	const otherType = "https://tm.example.com/b"

	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("member")
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{
		rvType:    {model.EntityIdentifier(issuer)},
		otherType: {model.EntityIdentifier(issuer)},
	})

	now := time.Now().UTC().Unix()
	chainExpiry := now + 86400
	liveExpiry := now + 3600

	expired := markWithClaims(t, f, issuer, map[string]any{"iat": now - 120, "exp": now - 30})
	live := func() string {
		body := map[string]any{"iss": issuer, "sub": rvSub, "trust_mark_type": otherType, "iat": now - 120, "exp": liveExpiry}
		token, err := jwt.New(f.ecKey["member"], map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256"}, body, jwt.Opts{Algorithm: jwa.RS256})
		if err != nil {
			t.Fatal(err)
		}
		return *token
	}()

	for _, order := range [][]model.TrustMarkHolder{
		{{TrustMarkType: rvType, TrustMark: expired}, {TrustMarkType: otherType, TrustMark: live}},
		{{TrustMarkType: otherType, TrustMark: live}, {TrustMarkType: rvType, TrustMark: expired}},
	} {
		resolved := &model.ResolveResponse{Sub: rvSub, Exp: chainExpiry, TrustMarks: order}
		if err := FilterByTrusted(t.Context(), model.Configuration{HttpClient: f.server.Client()}, resolved, ta, nil); err != nil {
			t.Fatalf("[8.3.2] one expired mark must not refuse the response, got %v", err)
		}
		if len(resolved.TrustMarks) != 1 || resolved.TrustMarks[0].TrustMarkType != otherType {
			t.Fatalf("[8.3.2] expected only the live mark to remain, got %+v", resolved.TrustMarks)
		}
		if resolved.Exp != liveExpiry {
			t.Errorf("[8.3.2] the response expiry is the minimum over the marks it carries, so it must be the live mark's expiry %d, got %d", liveExpiry, resolved.Exp)
		}
	}
}

func TestFilterByTrusted_EveryMarkOmittedLeavesTheChainExpiry(t *testing.T) {
	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("member")
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})

	now := time.Now().UTC().Unix()
	chainExpiry := now + 86400
	resolved := &model.ResolveResponse{Sub: rvSub, Exp: chainExpiry,
		TrustMarks: []model.TrustMarkHolder{{TrustMarkType: rvType, TrustMark: markWithClaims(t, f, issuer, map[string]any{"iat": now - 120, "exp": now - 30})}}}

	if err := FilterByTrusted(t.Context(), model.Configuration{HttpClient: f.server.Client()}, resolved, ta, nil); err != nil {
		t.Fatalf("[8.3.2] unexpected error: %v", err)
	}
	if len(resolved.TrustMarks) != 0 {
		t.Errorf("[8.3.2] expected the expired mark to be omitted, got %d", len(resolved.TrustMarks))
	}
	if resolved.Exp != chainExpiry {
		t.Errorf("[8.3.2] omitting every mark must leave the chain's expiry %d untouched, got %d", chainExpiry, resolved.Exp)
	}
}

func TestFilterByTrusted_AMarkWithNoExpiryIsKept(t *testing.T) {
	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("member")
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})

	now := time.Now().UTC().Unix()
	chainExpiry := now + 86400
	resolved := &model.ResolveResponse{Sub: rvSub, Exp: chainExpiry,
		TrustMarks: []model.TrustMarkHolder{{TrustMarkType: rvType, TrustMark: markWithClaims(t, f, issuer, map[string]any{"iat": now - 120, "exp": nil})}}}

	if err := FilterByTrusted(t.Context(), model.Configuration{HttpClient: f.server.Client()}, resolved, ta, nil); err != nil {
		t.Fatalf("[7.1] unexpected error: %v", err)
	}
	if len(resolved.TrustMarks) != 1 {
		t.Errorf("[7.1] a trust mark issued without an expiry does not expire, so it must be kept, got %d", len(resolved.TrustMarks))
	}
	if resolved.Exp != chainExpiry {
		t.Errorf("[8.3.2] a mark with no expiry contributes nothing to the minimum, so the chain's expiry %d must stand, got %d", chainExpiry, resolved.Exp)
	}
}

func TestValidate_ADelegationAtTheEdgeOfItsAllowanceIsRefusedForItsExpiry(t *testing.T) {
	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("member")
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
	ownerKey := rvKey(t)
	ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")}

	withinOneSecond(t, func(now int64) bool {
		body := dlgBody(dlgOwner, issuer, rvType)
		body["iat"] = now - 120
		body["exp"] = now - 60
		delegation := dlgSign(t, ownerKey, dlgHead("owner-key"), body)
		tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)
		_, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, tm, ValidateOptions{
			ExpectedType:             rvType,
			ExpectedSubject:          rvSub,
			AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(issuer)},
			TrustAnchor:              ta.Sub,
			TrustAnchorConfiguration: ta,
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "the trust mark's delegation has expired") {
			t.Logf("[7.2.2 step 7] a delegation exactly 60 seconds past its exp must be refused for its expiry, not its signature, got %v", err)
			return false
		}
		return true
	})
}
