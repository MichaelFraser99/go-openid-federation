package entity_statement

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
)

func rawToken(head, body string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(head)) + "." + base64.RawURLEncoding.EncodeToString([]byte(body)) + "." + base64.RawURLEncoding.EncodeToString([]byte("signature"))
}

func TestExtractDetails_RefusesARepeatedName(t *testing.T) {
	const body = `{"iss":"https://ta.example.com","sub":"https://leaf.example.com"}`
	tests := map[string]struct {
		token string
		says  string
	}{
		"a clean token":          {token: rawToken(`{"kid":"a","alg":"ES256"}`, body)},
		"a header repeating kid": {token: rawToken(`{"kid":"a","alg":"ES256","kid":"b"}`, body), says: "the JWT header repeats a member name"},
		"claims repeating sub":   {token: rawToken(`{"kid":"a","alg":"ES256"}`, `{"iss":"https://ta.example.com","sub":"https://leaf.example.com","sub":"https://other.example.com"}`), says: "the JWT claims set repeats a member name"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := ExtractDetails(tc.token)
			if tc.says == "" {
				if err != nil {
					t.Fatalf("expected the details, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("[RFC 7515/7519 4] expected a refusal containing %q, got %v", tc.says, err)
			}
		})
	}
}

func TestVerifySelectedKey_RefusesAHeaderRepeatingAName(t *testing.T) {
	key := map[string]any{"kty": "EC", "crv": "P-256", "kid": "a", "alg": "ES256", "x": "x", "y": "y"}
	err := VerifySelectedKey(rawToken(`{"kid":"a","alg":"ES256","alg":"ES256"}`, `{}`), key, []jwa.Algorithm{jwa.ES256})
	if err == nil || !strings.Contains(err.Error(), "the JWT header repeats a member name") {
		t.Fatalf("[RFC 7515 4] expected a repeated header parameter to be refused, got %v", err)
	}
}
