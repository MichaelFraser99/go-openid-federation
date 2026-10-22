package trust_marks

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestFilterByTrusted_AnUnverifiableTrustMarkIsBoundedInTheLog(t *testing.T) {
	const (
		marker   = "MARK-TAIL-MARKER"
		openType = "https://tm.example.com/open"
	)
	padding := strings.Repeat("g", 8192)

	tests := []struct {
		name      string
		reference string
		mark      func(t *testing.T, f *rvFed) string
	}{
		{
			name:      "a mark that is not a JWT at all",
			reference: "8.3",
			mark:      func(*testing.T, *rvFed) string { return padding + marker },
		},
		{
			name:      "a mark with a header the library cannot decode",
			reference: "8.3",
			mark:      func(*testing.T, *rvFed) string { return "!!!." + padding + marker + ".sig" },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{})

			mark := tc.mark(t, f)

			var logs bytes.Buffer
			cfg := model.Configuration{
				HttpClient: f.server.Client(),
				Logger:     slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			}
			resolved := &model.ResolveResponse{
				Sub:        "https://subject.example.com",
				Exp:        time.Now().Add(time.Hour).UTC().Unix(),
				TrustMarks: []model.TrustMarkHolder{{TrustMarkType: openType, TrustMark: mark}},
			}
			ta := model.EntityStatement{Sub: model.EntityIdentifier(f.id("ta")), TrustMarkIssuers: map[string][]model.EntityIdentifier{openType: {}}}

			if err := FilterByTrusted(t.Context(), cfg, resolved, ta, nil); err != nil {
				t.Fatalf("[%s] a mark that fails validation is dropped rather than refusing the resolve, got %v", tc.reference, err)
			}
			if len(resolved.TrustMarks) != 0 {
				t.Fatalf("[%s] expected the unverifiable mark to be dropped", tc.reference)
			}
			if logs.Len() >= len(mark) {
				t.Errorf("[%s] the log is %d bytes against an %d byte trust mark, so the mark itself is being logged whole", tc.reference, logs.Len(), len(mark))
			}
		})
	}
}

func paddedTrustMark(t *testing.T, signer crypto.Signer, kid, iss, trustMarkType, sub, padding string) string {
	t.Helper()
	head := map[string]any{"kid": kid, "typ": "trust-mark+jwt", "alg": "RS256"}
	body := map[string]any{
		"iss":             iss,
		"sub":             sub,
		"trust_mark_type": trustMarkType,
		"iat":             time.Now().UTC().Unix(),
		"exp":             time.Now().Add(time.Hour).UTC().Unix(),
		"ref":             "https://ref.example.com/" + padding,
	}
	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: josemodel.RS256})
	if err != nil {
		t.Fatalf("failed to create a padded trust mark: %v", err)
	}
	return *token
}

func TestValidate_AnUnverifiableTrustMarkIsBoundedInTheLog(t *testing.T) {
	const marker = "VALIDATE-TAIL-MARKER"
	padding := strings.Repeat("g", 8192)

	tests := []struct {
		name      string
		reference string
		signWith  string
	}{
		{name: "a mark the issuer's published key does not verify", reference: "8.3", signWith: "other"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{})
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("ta"))}})

			var logs bytes.Buffer
			cfg := model.Configuration{
				HttpClient: f.server.Client(),
				Logger:     slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			}

			tm := paddedTrustMark(t, rvSigningKey(t), "test-key", f.id("ta"), rvType, rvSub, padding+marker)
			_, err := Validate(t.Context(), cfg, tm, ValidateOptions{
				ExpectedType:             rvType,
				ExpectedSubject:          rvSub,
				AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(f.id("ta"))},
				TrustAnchor:              ta.Sub,
				TrustAnchorConfiguration: ta,
			}, nil)
			if err == nil {
				t.Fatalf("[%s] expected a mark signed by another key to be refused", tc.reference)
			}
			if logs.Len() >= len(tm) {
				t.Errorf("[%s] the log is %d bytes against an %d byte trust mark, so the mark itself is being logged whole", tc.reference, logs.Len(), len(tm))
			}
			if len(err.Error()) >= len(tm) {
				t.Errorf("[%s] the refusal is %d bytes against an %d byte trust mark", tc.reference, len(err.Error()), len(tm))
			}
		})
	}
}

func rvSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}
