package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_RefusesASuperiorsUnusableRegisteredKeyWithoutReflectingIt(t *testing.T) {
	const marker = "SUPERIOR-KEY-MARKER-ZZZZ"

	tests := []struct {
		name       string
		reference  string
		registered map[string]any
	}{
		{
			name:       "a key type the library cannot parse",
			reference:  "8.9",
			registered: map[string]any{"kid": "peer", "kty": marker},
		},
		{
			name:       "a curve the library cannot parse",
			reference:  "8.9",
			registered: map[string]any{"kid": "peer", "kty": "EC", "crv": marker, "x": "AQAB", "y": "AQAB"},
		},
		{
			name:       "an algorithm the subordinate does not sign with",
			reference:  "8.9",
			registered: map[string]any{"kid": "peer", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "alg": marker},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leafSigner, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build leaf signer: %v", err)
			}
			leafJWK, err := jwk.PublicJwk(leafSigner.Public())
			if err != nil {
				t.Fatalf("failed to build leaf jwk: %v", err)
			}
			(*leafJWK)["kid"] = "peer"

			anchorSigner, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build anchor signer: %v", err)
			}

			anchor := NewServer(model.ServerConfiguration{
				SignerConfiguration: model.SignerConfiguration{
					Algorithm: "ES256", Signer: anchorSigner, KeyID: "anchor",
				},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration: &model.IntermediateConfiguration{
					SubordinateStatementLifetime: 10 * time.Minute,
				},
			})
			anchorMux := http.NewServeMux()
			anchor.Configure(anchorMux)
			anchorServer := httptest.NewTLSServer(anchorMux)
			defer anchorServer.Close()
			anchor.SetEntityIdentifier(model.EntityIdentifier(anchorServer.URL))
			anchor.SetHttpClient(anchorServer.Client())

			leafMux := http.NewServeMux()
			var leafIdentifier string
			leafMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
				token, tokenErr := jwt.New(leafSigner, map[string]any{
					"kid": "peer", "typ": "entity-statement+jwt", "alg": "ES256",
				}, map[string]any{
					"iss":             leafIdentifier,
					"sub":             leafIdentifier,
					"iat":             time.Now().Add(-time.Minute).UTC().Unix(),
					"exp":             time.Now().Add(10 * time.Minute).UTC().Unix(),
					"jwks":            map[string]any{"keys": []any{*leafJWK}},
					"authority_hints": []any{anchorServer.URL},
					"metadata":        map[string]any{},
				}, jwt.Opts{Algorithm: jwa.ES256})
				if tokenErr != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				_, _ = w.Write([]byte(*token))
			})
			leaf := httptest.NewTLSServer(leafMux)
			defer leaf.Close()
			leafIdentifier = leaf.URL

			anchor.cfg.IntermediateConfiguration.AddSubordinate(model.EntityIdentifier(leafIdentifier), &model.SubordinateConfiguration{
				JWKs: josemodel.Jwks{Keys: []map[string]any{tc.registered}},
			})

			response, err := anchorServer.Client().Get(anchorServer.URL + "/resolve?sub=" + leafIdentifier + "&trust_anchor=" + anchorServer.URL)
			if err != nil {
				t.Fatalf("resolve request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read body: %v", err)
			}

			if response.StatusCode == http.StatusOK {
				t.Fatalf("[%s] expected the chain to be refused, got 200: %s", tc.reference, raw)
			}
			if strings.Contains(string(raw), marker) {
				t.Fatalf("[%s] a superior's registered key material reached the resolve body: %s", tc.reference, raw)
			}
			if len(raw) > model.MaxErrorDescriptionBytes+256 {
				t.Errorf("[%s] expected a bounded body, got %d bytes", tc.reference, len(raw))
			}
		})
	}
}
