package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_DoesNotReflectPeerStatementContent(t *testing.T) {
	const marker = "REFLECTION-MARKER-ZZZZ"

	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build signer: %v", err)
	}
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to build public jwk: %v", err)
	}
	(*publicJWK)["kid"] = "peer"

	tests := []struct {
		name   string
		claims func(identifier string) map[string]any
	}{
		{
			name: "a trust mark owner key the peer controls",
			claims: func(identifier string) map[string]any {
				return map[string]any{
					"trust_mark_owners": map[string]any{
						"https://tm.example.com/" + strings.Repeat(marker, 200): map[string]any{},
					},
				}
			},
		},
		{
			name: "an authority hint the peer controls",
			claims: func(identifier string) map[string]any {
				return map[string]any{
					"authority_hints": []any{"http://" + strings.Repeat(marker, 200) + ".example.com"},
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			var identifier string
			mux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
				body := map[string]any{
					"iss":  identifier,
					"sub":  identifier,
					"iat":  time.Now().Add(-time.Minute).UTC().Unix(),
					"exp":  time.Now().Add(10 * time.Minute).UTC().Unix(),
					"jwks": map[string]any{"keys": []any{*publicJWK}},
				}
				for claim, value := range tc.claims(identifier) {
					body[claim] = value
				}
				token, tokenErr := jwt.New(signer, map[string]any{
					"kid": "peer", "typ": "entity-statement+jwt", "alg": "ES256",
				}, body, jwt.Opts{Algorithm: josemodel.ES256})
				if tokenErr != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				_, _ = w.Write([]byte(*token))
			})
			peer := httptest.NewTLSServer(mux)
			defer peer.Close()
			identifier = peer.URL

			anchorSigner, err := jws.GetSigner(josemodel.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build anchor signer: %v", err)
			}
			anchorJWK, err := jwk.PublicJwk(anchorSigner.Public())
			if err != nil {
				t.Fatalf("failed to build anchor jwk: %v", err)
			}
			(*anchorJWK)["kid"] = "anchor"

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

			response, err := anchorServer.Client().Get(anchorServer.URL + "/resolve?sub=" + identifier + "&trust_anchor=" + anchorServer.URL)
			if err != nil {
				t.Fatalf("resolve request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read body: %v", err)
			}

			if strings.Contains(string(raw), marker) {
				t.Fatalf("the peer's statement content was reflected into the resolve response (%d bytes): %s", len(raw), raw)
			}
			if len(raw) > model.MaxErrorDescriptionBytes+256 {
				t.Fatalf("expected the error description to be bounded by %d bytes, got a %d byte body: %s", model.MaxErrorDescriptionBytes, len(raw), raw)
			}
		})
	}
}
