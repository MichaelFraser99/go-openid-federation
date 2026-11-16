package subordinate_statement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_RefusesARepeatedNameInTheHeaderOrTheClaims(t *testing.T) {
	const (
		trustAnchor = model.EntityIdentifier("https://ta.example.com")
		leaf        = model.EntityIdentifier("https://leaf.example.com")
	)
	issuerKey := testKey(t)
	subjectKey := testKey(t)
	keySet, err := json.Marshal(map[string]any{"keys": []any{testPublicJwk(t, subjectKey.Public(), "leaf")}})
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"iss":%q,"sub":%q,"iat":%d,"exp":%d,"jwks":%s}`, trustAnchor, leaf, time.Now().Add(-time.Minute).UTC().Unix(), time.Now().Add(time.Hour).UTC().Unix(), keySet)
	sign := func(head, body string) string {
		input := base64.RawURLEncoding.EncodeToString([]byte(head)) + "." + base64.RawURLEncoding.EncodeToString([]byte(body))
		digest := sha256.Sum256([]byte(input))
		signature, err := rsa.SignPKCS1v15(rand.Reader, issuerKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return input + "." + base64.RawURLEncoding.EncodeToString(signature)
	}

	tests := map[string]struct {
		head string
		body string
		says string
	}{
		"a clean statement":         {head: `{"kid":"ta","typ":"entity-statement+jwt","alg":"RS256"}`, body: body},
		"a header that repeats kid": {head: `{"kid":"ta","typ":"entity-statement+jwt","alg":"RS256","kid":"ta"}`, body: body, says: "the JWT header repeats a member name"},
		"claims that repeat sub":    {head: `{"kid":"ta","typ":"entity-statement+jwt","alg":"RS256"}`, body: strings.TrimSuffix(body, "}") + fmt.Sprintf(`,"sub":%q}`, leaf), says: "the JWT claims set repeats a member name"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			issuer := testIssuerStatement(t, trustAnchor, testPublicJwk(t, issuerKey.Public(), "ta"))
			_, err := Validate(t.Context(), model.Configuration{}, issuer, sign(tc.head, tc.body))
			if tc.says == "" {
				if err != nil {
					t.Fatalf("expected the statement to be accepted, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("[RFC 7515/7519 4] expected a refusal containing %q, got %v", tc.says, err)
			}
			if !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("expected the refusal to answer invalid_trust_chain, got %v", err)
			}
		})
	}
}
