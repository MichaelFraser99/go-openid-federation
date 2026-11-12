package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_ATrustMarkIssuerWalkReusesTheSubordinateStatementThisServerAlreadyIssued(t *testing.T) {
	const markType = "https://tm.example.com/self-issued"

	newSigner := func(t *testing.T) josemodel.Signer {
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		return signer
	}

	tests := []struct {
		name       string
		marks      int
		signatures int64
	}{
		{name: "a subject with no trust marks", signatures: 3},
		{name: "a subject that issues its own trust mark, so the issuer walk needs the statement the main walk built", marks: 1, signatures: 3},
		{name: "a subject that issues two of its own trust marks, walked once for the one issuer", marks: 2, signatures: 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			anchorSigner := newSigner(t)
			signatures := &atomic.Int64{}
			anchor := NewServer(model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: countingSigner{Signer: anchorSigner, signed: signatures}, KeyID: "ta"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
			})
			mux := http.NewServeMux()
			anchor.Configure(mux)
			anchorServer := httptest.NewTLSServer(mux)
			t.Cleanup(anchorServer.Close)
			anchor.SetEntityIdentifier(model.EntityIdentifier(anchorServer.URL))
			anchor.SetHttpClient(anchorServer.Client())

			leafSigner := newSigner(t)
			leafJWK, err := jwk.PublicJwk(leafSigner.Public())
			if err != nil {
				t.Fatalf("failed to read the leaf key: %v", err)
			}
			(*leafJWK)["kid"] = "leaf"
			sign := func(typ string, claims map[string]any) string {
				token, err := jwt.New(leafSigner, map[string]any{"kid": "leaf", "typ": typ, "alg": "ES256"}, claims, jwt.Opts{Algorithm: jwa.ES256})
				if err != nil {
					t.Fatalf("failed to sign: %v", err)
				}
				return *token
			}
			leafMux := http.NewServeMux()
			var leafIdentifier string
			leafMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
				now := time.Now().UTC()
				marks := []any{}
				for i := 0; i < tc.marks; i++ {
					marks = append(marks, map[string]any{
						"trust_mark_type": markType,
						"trust_mark": sign("trust-mark+jwt", map[string]any{
							"iss": leafIdentifier, "sub": leafIdentifier, "trust_mark_type": markType, "iat": now.Add(-time.Duration(i+1) * time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
						}),
					})
				}
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				_, _ = w.Write([]byte(sign("entity-statement+jwt", map[string]any{
					"iss":             leafIdentifier,
					"sub":             leafIdentifier,
					"iat":             now.Add(-time.Minute).Unix(),
					"exp":             now.Add(10 * time.Minute).Unix(),
					"jwks":            map[string]any{"keys": []any{*leafJWK}},
					"authority_hints": []any{anchorServer.URL},
					"metadata":        map[string]any{"federation_entity": map[string]any{}},
					"trust_marks":     marks,
				})))
			})
			leaf := httptest.NewTLSServer(leafMux)
			t.Cleanup(leaf.Close)
			leafIdentifier = leaf.URL
			anchor.cfg.EntityConfiguration.TrustMarkIssuers = map[string][]model.EntityIdentifier{markType: {model.EntityIdentifier(leaf.URL)}}
			anchor.cfg.IntermediateConfiguration.AddSubordinate(model.EntityIdentifier(leaf.URL), &model.SubordinateConfiguration{
				JWKs: josemodel.Jwks{Keys: []map[string]any{*leafJWK}},
			})

			response, err := anchorServer.Client().Get(anchorServer.URL + "/resolve?sub=" + leaf.URL + "&trust_anchor=" + anchorServer.URL)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("[10.2] expected 200, got %d %s", response.StatusCode, raw)
			}
			parts := strings.Split(string(raw), ".")
			if len(parts) != 3 {
				t.Fatalf("expected a signed resolve response, got %s", raw)
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("failed to decode the resolve response: %v", err)
			}
			var body map[string]any
			if err = json.Unmarshal(payload, &body); err != nil {
				t.Fatalf("failed to read the resolve response: %v", err)
			}
			marks, _ := body["trust_marks"].([]any)
			if len(marks) != tc.marks {
				t.Errorf("[10.2] expected each trust mark the anchor trusts verified and kept, got %d of %d", len(marks), tc.marks)
			}
			if got := signatures.Load(); got != tc.signatures {
				t.Errorf("expected the anchor to sign its entity configuration, its statement about the subject and the resolve response once each, got %d signatures where %d were expected", got, tc.signatures)
			}
		})
	}
}
