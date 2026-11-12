package trust_marks

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type loggedRecord struct {
	level   slog.Level
	message string
	attrs   map[string]slog.Value
}

type recordingHandler struct {
	mu      sync.Mutex
	records []loggedRecord
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := map[string]slog.Value{}
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, loggedRecord{level: record.Level, message: record.Message, attrs: attrs})
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

func (h *recordingHandler) atLevel(level slog.Level) []loggedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	matching := []loggedRecord{}
	for _, record := range h.records {
		if record.level == level {
			matching = append(matching, record)
		}
	}
	return matching
}

func (h *recordingHandler) withAttr(level slog.Level, key string) []loggedRecord {
	matching := []loggedRecord{}
	for _, record := range h.atLevel(level) {
		if _, ok := record.attrs[key]; ok {
			matching = append(matching, record)
		}
	}
	return matching
}

const unownedType = rvType + "/unowned"

func newJunkFixture(t *testing.T) (*rvFed, model.EntityStatement, func(head, body map[string]any) string) {
	t.Helper()
	f := newRvFed(t, map[string]string{"member": "ta"})
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{
		rvType:      {model.EntityIdentifier(f.id("member"))},
		unownedType: {model.EntityIdentifier(f.id("ta")), model.EntityIdentifier(f.id("nobody"))},
	})
	ta.JWKs.Keys = append(ta.JWKs.Keys, map[string]any{"kty": "RSA", "kid": "broken-key", "alg": "RS256", "n": "!!!", "e": "AQAB"})
	ownerKey := rvKey(t)
	leaky := federationPublicJwk(t, rvKey(t).Public(), "leaky-key")
	leaky["d"] = "AQAB"
	ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key", leaky)}
	signDelegation := func(head, body map[string]any) string { return rawRSAToken(t, ownerKey, head, body) }
	return f, ta, signDelegation
}

func TestFilterByTrusted_ARefusedTrustMarkIsLoggedAtInfoSoTheErrorLogDoesNotGrowWithJunk(t *testing.T) {
	f, ta, signDelegation := newJunkFixture(t)
	member := f.id("member")
	encode := func(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }
	overLimit := paddingOf(model.DefaultMaxStatementValues + 1)

	markHead := func() map[string]any {
		return map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256"}
	}
	markBody := func() map[string]any {
		return map[string]any{
			"iss": f.id("ta"), "sub": rvSub, "trust_mark_type": unownedType,
			"iat": time.Now().UTC().Unix(), "exp": time.Now().Add(time.Hour).UTC().Unix(),
		}
	}
	anchorMark := func(edit func(head, body map[string]any)) string {
		head, body := markHead(), markBody()
		edit(head, body)
		return rawRSAToken(t, f.ecKey["ta"], head, body)
	}
	unsigned := func(edit func(head, body map[string]any)) string {
		head, body := markHead(), markBody()
		edit(head, body)
		return paddedToken(t, head, body)
	}
	validHead := encode(`{"alg":"RS256","kid":"test-key","typ":"trust-mark+jwt"}`)

	delegationMark := func(trustMarkType, delegation string) string {
		return dlgMark(t, f.ecKey["member"], "test-key", member, trustMarkType, rvSub, &delegation)
	}
	delegation := func(edit func(head, body map[string]any)) string {
		head, body := dlgHead("owner-key"), dlgBody(dlgOwner, member, rvType)
		edit(head, body)
		return signDelegation(head, body)
	}
	unsignedDelegation := func(edit func(head, body map[string]any)) string {
		head, body := dlgHead("owner-key"), dlgBody(dlgOwner, member, rvType)
		edit(head, body)
		return paddedToken(t, head, body)
	}
	validDelegationHead := encode(`{"alg":"RS256","kid":"owner-key","typ":"trust-mark-delegation+jwt"}`)

	tests := []struct {
		name      string
		reference string
		holder    model.TrustMarkHolder
	}{
		{name: "a type the anchor does not trust", reference: "8.3", holder: model.TrustMarkHolder{TrustMarkType: rvType + "/untrusted", TrustMark: anchorMark(func(map[string]any, map[string]any) {})}},
		{name: "a mark that is not a JWT", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: "a.b"}},
		{name: "a header that is not base64url", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: "!!!.e30.c2ln"}},
		{name: "a header over the value limit", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: unsigned(func(head, _ map[string]any) { head["pad"] = overLimit })}},
		{name: "a header that is not JSON", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: encode("not json") + ".e30.c2ln"}},
		{name: "a header with no kid", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(head, _ map[string]any) { delete(head, "kid") })}},
		{name: "a header carrying crit", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(head, _ map[string]any) { head["crit"] = []string{"ext"}; head["ext"] = true })}},
		{name: "a body that is not base64url", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: validHead + ".!!!.c2ln"}},
		{name: "a body over the value limit", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: unsigned(func(_, body map[string]any) { body["pad"] = overLimit })}},
		{name: "a body that is not JSON", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: validHead + "." + encode("not json") + ".c2ln"}},
		{name: "a body with no issuer", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(_, body map[string]any) { delete(body, "iss") })}},
		{name: "a body with an empty issuer", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(_, body map[string]any) { body["iss"] = "" })}},
		{name: "an issuer that is not an entity identifier", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(_, body map[string]any) { body["iss"] = "http://plain.example.com" })}},
		{name: "a signed type other than the presented type", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(_, body map[string]any) { body["trust_mark_type"] = rvType })}},
		{name: "a subject other than the resolved subject", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(_, body map[string]any) { body["sub"] = "https://other.example.com" })}},
		{name: "an issuer the anchor does not authorise", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(_, body map[string]any) { body["iss"] = "https://stranger.example.com" })}},
		{name: "an issuer with no chain to the anchor", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(_, body map[string]any) { body["iss"] = f.id("nobody") })}},
		{name: "a kid the issuer does not publish", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(head, _ map[string]any) { head["kid"] = "unknown-kid" })}},
		{name: "an algorithm the issuer's key is not for", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(head, _ map[string]any) { head["alg"] = "RS384" })}},
		{name: "a kid naming a published key go-jose cannot read", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(head, _ map[string]any) { head["kid"] = "broken-key" })}},
		{name: "a signature that does not verify", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: unsigned(func(map[string]any, map[string]any) {})}},
		{name: "a typ other than trust-mark+jwt", reference: "7.3", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(head, _ map[string]any) { head["typ"] = "jwt" })}},
		{name: "an owned type with no delegation", reference: "7.3 step 8", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: dlgMark(t, f.ecKey["member"], "test-key", member, rvType, rvSub, nil)}},
		{name: "a delegation on a type with no owner", reference: "7.3 step 9", holder: model.TrustMarkHolder{TrustMarkType: unownedType, TrustMark: anchorMark(func(_, body map[string]any) { body["delegation"] = delegation(func(map[string]any, map[string]any) {}) })}},
		{name: "a delegation that is not a JWT", reference: "7.2.2", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, "a.b")}},
		{name: "a delegation header that is not base64url", reference: "7.2.2", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, "!!!.e30.c2ln")}},
		{name: "a delegation header over the value limit", reference: "7.2.2", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, unsignedDelegation(func(head, _ map[string]any) { head["pad"] = overLimit }))}},
		{name: "a delegation header that is not JSON", reference: "7.2.2", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, encode("not json")+".e30.c2ln")}},
		{name: "a delegation header carrying crit", reference: "7.2.2", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(head, _ map[string]any) { head["crit"] = []string{"ext"}; head["ext"] = true }))}},
		{name: "a delegation typ other than the delegation type", reference: "7.2.2 step 3", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(head, _ map[string]any) { head["typ"] = "jwt" }))}},
		{name: "a delegation alg of none", reference: "7.2.2", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, unsignedDelegation(func(head, _ map[string]any) { head["alg"] = "none" }))}},
		{name: "a delegation with no kid", reference: "7.2.2", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(head, _ map[string]any) { delete(head, "kid") }))}},
		{name: "a delegation body that is not base64url", reference: "7.2.2", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, validDelegationHead+".!!!.c2ln")}},
		{name: "a delegation body over the value limit", reference: "7.2.2", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, unsignedDelegation(func(_, body map[string]any) { body["pad"] = overLimit }))}},
		{name: "a delegation body that is not JSON", reference: "7.2.2", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, validDelegationHead+"."+encode("not json")+".c2ln")}},
		{name: "a delegation with no sub", reference: "7.2.2 step 4", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(_, body map[string]any) { delete(body, "sub") }))}},
		{name: "a delegation naming another issuer", reference: "7.2.2 step 4", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(_, body map[string]any) { body["sub"] = "https://other.example.com" }))}},
		{name: "a delegation with no iss", reference: "7.2.2 step 5", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(_, body map[string]any) { delete(body, "iss") }))}},
		{name: "a delegation from another owner", reference: "7.2.2 step 5", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(_, body map[string]any) { body["iss"] = "https://other-owner.example.com" }))}},
		{name: "a delegation with no trust_mark_type", reference: "7.2.2 step 8", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(_, body map[string]any) { delete(body, "trust_mark_type") }))}},
		{name: "a delegation for another type", reference: "7.2.2 step 8", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(_, body map[string]any) { body["trust_mark_type"] = unownedType }))}},
		{name: "a delegation iat that is not a number", reference: "7.2.1", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(_, body map[string]any) { body["iat"] = "yesterday" }))}},
		{name: "a delegation with no iat", reference: "7.2.1", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(_, body map[string]any) { delete(body, "iat") }))}},
		{name: "a delegation issued in the future", reference: "7.2.2 step 6", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(_, body map[string]any) { body["iat"] = time.Now().Add(time.Hour).UTC().Unix() }))}},
		{name: "a delegation exp that is not a number", reference: "7.2.1", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(_, body map[string]any) { body["exp"] = "tomorrow" }))}},
		{name: "an expired delegation", reference: "7.2.2 step 7", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(_, body map[string]any) { body["exp"] = time.Now().Add(-time.Hour).UTC().Unix() }))}},
		{name: "a delegation kid the owner does not publish", reference: "7.2.2 step 9", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(head, _ map[string]any) { head["kid"] = "unknown-kid" }))}},
		{name: "a delegation kid naming an owner key carrying private material", reference: "7.2.2 step 9", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(head, _ map[string]any) { head["kid"] = "leaky-key" }))}},
		{name: "a delegation algorithm the owner key is not for", reference: "7.2.2 step 9", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, delegation(func(head, _ map[string]any) { head["alg"] = "RS384" }))}},
		{name: "a delegation signature that does not verify", reference: "7.2.2 step 9", holder: model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: delegationMark(rvType, unsignedDelegation(func(map[string]any, map[string]any) {}))}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errorLines := map[int]int{}
			for _, copies := range []int{1, 5} {
				handler := &recordingHandler{}
				cfg := model.Configuration{HttpClient: f.server.Client(), Logger: slog.New(handler)}
				marks := slices.Repeat([]model.TrustMarkHolder{tc.holder}, copies)
				resolved := &model.ResolveResponse{Sub: rvSub, Exp: time.Now().Add(time.Hour).UTC().Unix(), TrustMarks: marks}

				if err := FilterByTrusted(t.Context(), cfg, resolved, ta, nil); err != nil {
					t.Fatalf("[%s] a mark that fails validation is dropped rather than refusing the resolve, got %v", tc.reference, err)
				}
				if len(resolved.TrustMarks) != 0 {
					t.Fatalf("[%s] the fixture is wrong: expected every copy of the mark to be dropped, %d kept", tc.reference, len(resolved.TrustMarks))
				}

				errorLines[copies] = len(handler.atLevel(slog.LevelError))
				summaries := handler.withAttr(slog.LevelInfo, "dropped")
				if len(summaries) != 1 {
					t.Fatalf("expected exactly one Info summary line per filter, got %d", len(summaries))
				}
				if dropped, presented := summaries[0].attrs["dropped"].Int64(), summaries[0].attrs["presented"].Int64(); dropped != int64(copies) || presented != int64(copies) {
					t.Errorf("expected the summary to say %d of %d marks were dropped, got %d of %d", copies, copies, dropped, presented)
				}
			}
			if errorLines[1] != 0 || errorLines[5] != 0 {
				t.Errorf("a refusal of a peer's trust mark is the peer's fault and is logged at Info, got %d Error lines for one copy and %d for five", errorLines[1], errorLines[5])
			}
		})
	}
}

func TestFilterByTrusted_TheIssuerCapRefusalIsLoggedAtInfo(t *testing.T) {
	f, ta, _ := newJunkFixture(t)
	handler := &recordingHandler{}
	cfg := model.Configuration{HttpClient: f.server.Client(), Logger: slog.New(handler), MaxTrustMarkIssuers: 1}
	resolved := &model.ResolveResponse{Sub: rvSub, Exp: time.Now().Add(time.Hour).UTC().Unix(), TrustMarks: []model.TrustMarkHolder{
		{TrustMarkType: unownedType, TrustMark: federationTrustMark(t, f.ecKey["ta"], "test-key", f.id("ta"), unownedType, rvSub)},
		{TrustMarkType: unownedType, TrustMark: federationTrustMark(t, f.ecKey["ta"], "test-key", f.id("nobody"), unownedType, rvSub)},
	}}

	if err := FilterByTrusted(t.Context(), cfg, resolved, ta, nil); err == nil {
		t.Fatalf("[8.9] the fixture is wrong: expected the issuer bound to refuse")
	}
	if errorLines := handler.atLevel(slog.LevelError); len(errorLines) != 0 {
		t.Errorf("a subject presenting more issuers than the bound is the peer's choice and is logged at Info, got %d Error lines", len(errorLines))
	}
}

func TestValidate_AnIssuerThisResolverCannotReachForItsOwnFaultIsLoggedAtError(t *testing.T) {
	f, ta, _ := newJunkFixture(t)
	handler := &recordingHandler{}
	cfg := model.Configuration{Logger: slog.New(handler)}
	member := f.id("member")
	mark := dlgMark(t, f.ecKey["member"], "test-key", member, unownedType, rvSub, nil)

	_, err := Validate(t.Context(), cfg, mark, ValidateOptions{
		ExpectedType:             unownedType,
		ExpectedSubject:          rvSub,
		AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(member)},
		TrustAnchor:              ta.Sub,
		TrustAnchorConfiguration: ta,
	}, nil)
	if err == nil {
		t.Fatalf("the fixture is wrong: a resolver with no HTTP client cannot walk to the issuer")
	}
	if errorLines := handler.atLevel(slog.LevelError); len(errorLines) == 0 {
		t.Errorf("a resolver that cannot walk to an issuer because of its own configuration is an operator's fault and is logged at Error")
	}
}

func TestFilterByTrusted_ConsidersAtMostTheTrustMarkLimitInTheOrderListed(t *testing.T) {
	everyMark := []string{"0", "1", "2", "3", "4"}
	tests := []struct {
		name           string
		reference      string
		limit          int
		issuerLimit    int
		kept           []string
		memberVerified bool
		capNoted       bool
	}{
		{name: "the marks past the limit are dropped unverified and never refused", reference: "8.3", limit: 3, issuerLimit: 1, kept: []string{"0", "1", "2"}, capNoted: true},
		{name: "a limit equal to the number of marks verifies every mark", reference: "8.3", limit: 5, kept: everyMark, memberVerified: true},
		{name: "the default limit verifies every mark", reference: "8.3", kept: everyMark, memberVerified: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			types := map[string][]model.EntityIdentifier{}
			marks := make([]model.TrustMarkHolder, 0, len(everyMark))
			for i := range everyMark {
				trustMarkType := fmt.Sprintf("%s/%d", rvType, i)
				issuer := "ta"
				if i >= 3 {
					issuer = "member"
				}
				types[trustMarkType] = []model.EntityIdentifier{model.EntityIdentifier(f.id(issuer))}
				marks = append(marks, model.TrustMarkHolder{TrustMarkType: trustMarkType, TrustMark: federationTrustMark(t, f.ecKey[issuer], "test-key", f.id(issuer), trustMarkType, rvSub)})
			}
			ta := f.taConfig(t, types)

			handler := &recordingHandler{}
			cfg := model.Configuration{HttpClient: f.server.Client(), Logger: slog.New(handler), MaxTrustMarks: tc.limit, MaxTrustMarkIssuers: tc.issuerLimit}
			resolved := &model.ResolveResponse{Sub: rvSub, Exp: time.Now().Add(time.Hour).UTC().Unix(), TrustMarks: marks}
			if err := FilterByTrusted(t.Context(), cfg, resolved, ta, nil); err != nil {
				t.Fatalf("[%s] a mark past the limit is dropped, never refused, got %v", tc.reference, err)
			}

			kept := make([]string, 0, len(resolved.TrustMarks))
			for _, holder := range resolved.TrustMarks {
				kept = append(kept, strings.TrimPrefix(holder.TrustMarkType, rvType+"/"))
			}
			if !slices.Equal(kept, tc.kept) {
				t.Errorf("[%s] expected the marks %v in the order listed, got %v", tc.reference, tc.kept, kept)
			}

			f.mu.Lock()
			fetched := f.hits["/member/.well-known/openid-federation"]
			f.mu.Unlock()
			if verified := fetched > 0; verified != tc.memberVerified {
				t.Errorf("[%s] expected the issuer of the marks past index 2 to be fetched to verify them: %t, fetched %d times", tc.reference, tc.memberVerified, fetched)
			}

			notes := handler.withAttr(slog.LevelInfo, "limit")
			if tc.capNoted && (len(notes) != 1 || notes[0].attrs["limit"].Int64() != int64(tc.limit)) {
				t.Errorf("expected one Info line naming the limit of %d, got %v", tc.limit, notes)
			}
			if !tc.capNoted && len(notes) != 0 {
				t.Errorf("expected no line about the limit when every mark fits it, got %v", notes)
			}

			dropped := len(everyMark) - len(tc.kept)
			summaries := handler.withAttr(slog.LevelInfo, "dropped")
			if len(summaries) != 1 || summaries[0].attrs["dropped"].Int64() != int64(dropped) || summaries[0].attrs["presented"].Int64() != int64(len(everyMark)) {
				t.Errorf("expected one summary line saying %d of %d marks were dropped, got %v", dropped, len(everyMark), summaries)
			}
		})
	}
}

func TestFilterByTrusted_ASubjectPresentingNoTrustMarksWritesNoSummary(t *testing.T) {
	tests := []struct {
		name  string
		marks []model.TrustMarkHolder
	}{
		{name: "a nil list", marks: nil},
		{name: "an empty list", marks: []model.TrustMarkHolder{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := &recordingHandler{}
			cfg := model.Configuration{Logger: slog.New(logs)}
			resolved := &model.ResolveResponse{Sub: "https://leaf.example.com", TrustMarks: tc.marks}

			if err := FilterByTrusted(t.Context(), cfg, resolved, model.EntityStatement{Sub: "https://ta.example.com"}, nil); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if summaries := logs.withAttr(slog.LevelInfo, "dropped"); len(summaries) != 0 {
				t.Errorf("a resolve with no trust marks has nothing to summarise, got %d summary lines", len(summaries))
			}
		})
	}
}

func TestFilterByTrusted_OnlyMarksOfTypesTheAnchorTrustsCountAgainstTheLimit(t *testing.T) {
	tests := []struct {
		name       string
		limit      int
		marks      []string
		kept       []string
		unverified int
		untrusted  int
		maxLines   int
	}{
		{name: "sixty-five marks from another federation before one this anchor trusts", marks: append(slices.Repeat([]string{"u"}, 65), "t0"), kept: []string{"t0"}, untrusted: 65},
		{name: "marks from another federation between trusted marks, past the limit", limit: 2, marks: []string{"u", "t0", "u", "t1", "u", "t2"}, kept: []string{"t0", "t1"}, unverified: 1, untrusted: 3},
		{name: "trusted marks exactly at the limit", limit: 2, marks: []string{"t0", "u", "t1"}, kept: []string{"t0", "t1"}, untrusted: 1},
		{name: "a trusted mark that fails verification still counts against the limit", limit: 1, marks: []string{"bad", "t0"}, kept: []string{}, unverified: 1},
		{name: "a thousand marks from another federation write no line each", marks: slices.Repeat([]string{"u"}, 1000), kept: []string{}, untrusted: 1000, maxLines: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			types := map[string][]model.EntityIdentifier{}
			marks := make([]model.TrustMarkHolder, 0, len(tc.marks))
			for i, mark := range tc.marks {
				switch mark {
				case "u":
					trustMarkType := fmt.Sprintf("%s/other-federation/%d", rvType, i)
					marks = append(marks, model.TrustMarkHolder{TrustMarkType: trustMarkType, TrustMark: federationTrustMark(t, f.ecKey["ta"], "test-key", f.id("ta"), trustMarkType, rvSub)})
				case "bad":
					trustMarkType := rvType + "/bad"
					types[trustMarkType] = []model.EntityIdentifier{model.EntityIdentifier(f.id("ta"))}
					marks = append(marks, model.TrustMarkHolder{TrustMarkType: trustMarkType, TrustMark: federationTrustMark(t, f.ecKey["member"], "test-key", f.id("ta"), trustMarkType, rvSub)})
				default:
					trustMarkType := rvType + "/" + mark
					types[trustMarkType] = []model.EntityIdentifier{model.EntityIdentifier(f.id("ta"))}
					marks = append(marks, model.TrustMarkHolder{TrustMarkType: trustMarkType, TrustMark: federationTrustMark(t, f.ecKey["ta"], "test-key", f.id("ta"), trustMarkType, rvSub)})
				}
			}
			ta := f.taConfig(t, types)

			handler := &recordingHandler{}
			cfg := model.Configuration{HttpClient: f.server.Client(), Logger: slog.New(handler), MaxTrustMarks: tc.limit}
			resolved := &model.ResolveResponse{Sub: rvSub, Exp: time.Now().Add(time.Hour).UTC().Unix(), TrustMarks: marks}
			if err := FilterByTrusted(t.Context(), cfg, resolved, ta, nil); err != nil {
				t.Fatalf("[8.3] a mark the resolver does not verify is dropped, never refused, got %v", err)
			}

			kept := make([]string, 0, len(resolved.TrustMarks))
			for _, holder := range resolved.TrustMarks {
				kept = append(kept, strings.TrimPrefix(holder.TrustMarkType, rvType+"/"))
			}
			if !slices.Equal(kept, tc.kept) {
				t.Errorf("[8.3] expected the marks %v kept in the order listed, got %v", tc.kept, kept)
			}

			limitLines := handler.withAttr(slog.LevelInfo, "unverified")
			if tc.unverified == 0 && len(limitLines) != 0 {
				t.Errorf("expected no line about the limit when the trusted marks fit it, got %v", limitLines)
			}
			if tc.unverified > 0 && (len(limitLines) != 1 || limitLines[0].attrs["unverified"].Int64() != int64(tc.unverified)) {
				t.Errorf("expected one line saying %d trusted marks went unverified past the limit, got %v", tc.unverified, limitLines)
			}

			summaries := handler.withAttr(slog.LevelInfo, "untrusted_types")
			if len(summaries) != 1 || summaries[0].attrs["untrusted_types"].Int64() != int64(tc.untrusted) || summaries[0].attrs["presented"].Int64() != int64(len(tc.marks)) {
				t.Errorf("expected one summary counting %d marks of types the anchor does not trust out of %d, got %v", tc.untrusted, len(tc.marks), summaries)
			}
			if tc.maxLines > 0 {
				if lines := len(handler.atLevel(slog.LevelInfo)) + len(handler.atLevel(slog.LevelError)); lines > tc.maxLines {
					t.Errorf("expected at most %d lines for marks of types the anchor does not trust, got %d", tc.maxLines, lines)
				}
			}
		})
	}
}
