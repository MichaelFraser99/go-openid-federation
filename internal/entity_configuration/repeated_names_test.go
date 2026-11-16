package entity_configuration

import (
	"context"
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

func signRawJSON(t *testing.T, key *rsa.PrivateKey, head, body string) string {
	t.Helper()
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(head)) + "." + base64.RawURLEncoding.EncodeToString([]byte(body))
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestValidate_RefusesARepeatedNameInTheHeaderOrTheClaims(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")
	realKey := headerJwkKey(t)
	attackerKey := headerJwkKey(t)
	keySet := func(jwk map[string]any) string {
		raw, err := json.Marshal(map[string]any{"keys": []any{jwk}})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	realSet := keySet(headerJwkPublicJwk(t, realKey.Public(), "leaf"))
	attackerSet := keySet(headerJwkPublicJwk(t, attackerKey.Public(), "leaf"))
	times := fmt.Sprintf(`"iat":%d,"exp":%d`, time.Now().Add(-time.Minute).UTC().Unix(), time.Now().Add(time.Hour).UTC().Unix())
	header := `{"kid":"leaf","typ":"entity-statement+jwt","alg":"RS256"}`
	body := fmt.Sprintf(`{"iss":%q,"sub":%q,%s,"jwks":%s}`, leaf, leaf, times, realSet)

	tests := map[string]struct {
		reference string
		key       *rsa.PrivateKey
		head      string
		body      string
		says      string
	}{
		"a clean statement": {
			reference: "RFC 7519 4", key: realKey, head: header, body: body,
		},
		"a header that repeats kid": {
			reference: "RFC 7515 4", key: realKey,
			head: `{"kid":"leaf","typ":"entity-statement+jwt","alg":"RS256","kid":"other"}`, body: body,
			says: "the JWT header repeats a member name",
		},
		"a header that repeats alg": {
			reference: "RFC 7515 4", key: realKey,
			head: `{"kid":"leaf","typ":"entity-statement+jwt","alg":"RS256","alg":"RS256"}`, body: body,
			says: "the JWT header repeats a member name",
		},
		"claims that repeat jwks, signed by the key in the second copy": {
			reference: "RFC 7519 4", key: attackerKey, head: header,
			body: fmt.Sprintf(`{"iss":%q,"sub":%q,%s,"jwks":%s,"jwks":%s}`, leaf, leaf, times, realSet, attackerSet),
			says: "the JWT claims set repeats a member name",
		},
		"claims that repeat iss": {
			reference: "RFC 7519 4", key: realKey, head: header,
			body: fmt.Sprintf(`{"iss":%q,"iss":%q,"sub":%q,%s,"jwks":%s}`, leaf, leaf, leaf, times, realSet),
			says: "the JWT claims set repeats a member name",
		},
		"a repeat nested inside a claim, below the top level": {
			reference: "RFC 7519 4", key: realKey, head: header,
			body: fmt.Sprintf(`{"iss":%q,"sub":%q,%s,"jwks":%s,"metadata":{"federation_entity":{"organization_name":"a","organization_name":"b"}}}`, leaf, leaf, times, realSet),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Validate(context.Background(), model.Configuration{}, leaf, signRawJSON(t, tc.key, tc.head, tc.body))
			if tc.says == "" {
				if err != nil {
					t.Fatalf("[%s] expected the statement to be accepted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("[%s] expected a refusal containing %q, got %v", tc.reference, tc.says, err)
			}
			if !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("expected the refusal to answer invalid_trust_chain, got %v", err)
			}
		})
	}
}
