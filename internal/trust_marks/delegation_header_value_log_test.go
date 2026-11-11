package trust_marks

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestFilterByTrusted_ADelegationHeaderMemberThatIsNotAStringIsLoggedByType(t *testing.T) {
	const marker = "jpsQnnGQmL-YBIffH1136cLvhgLlb8TXx0cfw3xQk9Q"

	for _, member := range []string{"typ", "alg", "kid"} {
		t.Run(member, func(t *testing.T) {
			d := dlgSetup(t)
			head := dlgHead("owner-key")
			head[member] = map[string]any{"kty": "EC", "d": marker}
			delegation := dlgSignRaw(t, d.ownerKey, head, dlgBody(dlgOwner, d.issuer, rvType))

			var logs bytes.Buffer
			cfg := model.Configuration{
				HttpClient: d.fed.server.Client(),
				Logger:     slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			}
			tm := dlgMark(t, d.fed.ecKey["member"], "test-key", d.issuer, rvType, rvSub, &delegation)
			resolved := &model.ResolveResponse{Sub: rvSub, Exp: time.Now().Add(time.Hour).UTC().Unix(),
				TrustMarks: []model.TrustMarkHolder{{TrustMarkType: rvType, TrustMark: tm}}}

			if err := FilterByTrusted(t.Context(), cfg, resolved, d.anchor, nil); err != nil {
				t.Fatalf("[7.2.1] a mark whose delegation fails is dropped rather than refusing the resolve, got %v", err)
			}
			if len(resolved.TrustMarks) != 0 {
				t.Fatalf("[7.2.1] expected a delegation whose %s header is not a string to be refused", member)
			}
			if strings.Contains(logs.String(), marker) {
				t.Errorf("expected the %s header described by type, but a value the issuer chose reached the log: %s", member, logs.String())
			}
			if !strings.Contains(logs.String(), "of type map[string]interface {}") {
				t.Errorf("expected the %s header described by its type, got %s", member, logs.String())
			}
		})
	}
}

func TestFilterByTrusted_ADelegationHeaderMemberThatIsAStringIsLoggedByValue(t *testing.T) {
	d := dlgSetup(t)
	head := dlgHead("owner-key")
	head["typ"] = "a-type-the-issuer-chose"
	delegation := dlgSignRaw(t, d.ownerKey, head, dlgBody(dlgOwner, d.issuer, rvType))

	var logs bytes.Buffer
	cfg := model.Configuration{
		HttpClient: d.fed.server.Client(),
		Logger:     slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	tm := dlgMark(t, d.fed.ecKey["member"], "test-key", d.issuer, rvType, rvSub, &delegation)
	resolved := &model.ResolveResponse{Sub: rvSub, Exp: time.Now().Add(time.Hour).UTC().Unix(),
		TrustMarks: []model.TrustMarkHolder{{TrustMarkType: rvType, TrustMark: tm}}}

	if err := FilterByTrusted(t.Context(), cfg, resolved, d.anchor, nil); err != nil {
		t.Fatalf("[7.2.1] a mark whose delegation fails is dropped rather than refusing the resolve, got %v", err)
	}
	if !strings.Contains(logs.String(), `"typ":"a-type-the-issuer-chose"`) {
		t.Errorf("expected a string typ logged as written, so an operator can see what the issuer sent, got %s", logs.String())
	}
}
