package trust_marks

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwt"
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
		{
			name:      "a mark with a body that is not JSON",
			reference: "8.3",
			mark: func(*testing.T, *rvFed) string {
				encode := base64.RawURLEncoding.EncodeToString
				return encode([]byte(`{"alg":"RS256","kid":"k","typ":"trust-mark+jwt"}`)) + "." + encode([]byte(padding+marker)) + ".sig"
			},
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
			if strings.Contains(logs.String(), marker) {
				t.Errorf("[%s] the tail of the trust mark reached the log, so what the peer chose is not bounded there", tc.reference)
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
	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: jwa.RS256})
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

func TestFilterByTrusted_ADelegationTheIssuerChoseIsBoundedInTheLog(t *testing.T) {
	const marker = "DLG-TAIL-MARKER"
	padding := strings.Repeat("g", 8192)

	tests := []struct {
		name      string
		reference string
		head      map[string]any
		body      map[string]any
	}{
		{
			name:      "a typ header the library does not accept",
			reference: "7.2.2 step 2",
			head:      map[string]any{"kid": "owner-key", "alg": "RS256", "typ": padding + marker},
		},
		{
			name:      "a typ header that is not a string",
			reference: "7.2.2 step 2",
			head:      map[string]any{"kid": "owner-key", "alg": "RS256", "typ": []any{padding + marker}},
		},
		{
			name:      "an alg header that is not a string",
			reference: "7.2.2 step 3",
			head:      map[string]any{"kid": "owner-key", "typ": "trust-mark-delegation+jwt", "alg": []any{padding + marker}},
		},
		{
			name:      "a kid header that is not a string",
			reference: "7.2.1",
			head:      map[string]any{"typ": "trust-mark-delegation+jwt", "alg": "RS256", "kid": []any{padding + marker}},
		},
		{
			name:      "a body the library cannot read",
			reference: "7.2.2 step 1",
			head:      map[string]any{"kid": "owner-key", "typ": "trust-mark-delegation+jwt", "alg": "RS256"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			ownerKey := rvKey(t)
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, ownerKey, "owner-key")}

			delegation := ""
			if tc.body != nil {
				delegation = dlgRaw(t, tc.head, tc.body, "")
			} else if tc.name == "a body the library cannot read" {
				headBytes, err := json.Marshal(tc.head)
				if err != nil {
					t.Fatal(err)
				}
				delegation = base64.RawURLEncoding.EncodeToString(headBytes) + "." + base64.RawURLEncoding.EncodeToString([]byte("[1"+padding+marker)) + ".sig"
			} else {
				delegation = dlgRaw(t, tc.head, dlgBody(dlgOwner, issuer, rvType), "")
			}

			tm := dlgMark(t, f.ecKey["member"], "test-key", issuer, rvType, rvSub, &delegation)

			var logs bytes.Buffer
			cfg := model.Configuration{
				HttpClient: f.server.Client(),
				Logger:     slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			}
			resolved := &model.ResolveResponse{
				Sub:        rvSub,
				Exp:        time.Now().Add(time.Hour).UTC().Unix(),
				TrustMarks: []model.TrustMarkHolder{{TrustMarkType: rvType, TrustMark: tm}},
			}

			if err := FilterByTrusted(t.Context(), cfg, resolved, ta, nil); err != nil {
				t.Fatalf("[%s] a mark whose delegation fails validation is dropped rather than refusing the resolve, got %v", tc.reference, err)
			}
			if len(resolved.TrustMarks) != 0 {
				t.Fatalf("[%s] expected the mark to be dropped", tc.reference)
			}
			if strings.Contains(logs.String(), marker) {
				t.Errorf("[%s] the tail of a value the trust mark issuer chose reached the log, so it is being logged whole", tc.reference)
			}
			if logs.Len() >= len(delegation) {
				t.Errorf("[%s] the log is %d bytes against a %d byte delegation, so the delegation itself is being logged whole", tc.reference, logs.Len(), len(delegation))
			}
		})
	}
}
