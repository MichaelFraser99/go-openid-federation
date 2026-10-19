package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_MalformedPeerKeyDoesNotPanic(t *testing.T) {
	tests := []struct {
		name string
		jwks map[string]any
	}{
		{name: "kty that is a number", jwks: map[string]any{"keys": []any{map[string]any{"kid": "peer", "kty": 7}}}},
		{name: "kty that is an object", jwks: map[string]any{"keys": []any{map[string]any{"kid": "peer", "kty": map[string]any{}}}}},
		{name: "an EC key with no crv", jwks: map[string]any{"keys": []any{map[string]any{"kid": "peer", "kty": "EC", "x": "AQAB", "y": "AQAB"}}}},
		{name: "an EC key with a numeric crv", jwks: map[string]any{"keys": []any{map[string]any{"kid": "peer", "kty": "EC", "crv": 7, "x": "AQAB", "y": "AQAB"}}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peerMux := http.NewServeMux()
			var peerIdentifier string
			peerMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
				encode := func(v any) string {
					raw, _ := json.Marshal(v)
					return base64.RawURLEncoding.EncodeToString(raw)
				}
				head := encode(map[string]any{"kid": "peer", "typ": "entity-statement+jwt", "alg": "ES256"})
				body := encode(map[string]any{
					"iss":  peerIdentifier,
					"sub":  peerIdentifier,
					"iat":  time.Now().Add(-time.Minute).UTC().Unix(),
					"exp":  time.Now().Add(10 * time.Minute).UTC().Unix(),
					"jwks": tc.jwks,
				})
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				_, _ = w.Write([]byte(head + "." + body + ".signature"))
			})
			peer := httptest.NewTLSServer(peerMux)
			defer peer.Close()
			peerIdentifier = peer.URL

			anchorSigner, err := jws.GetSigner(josemodel.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the anchor signer: %v", err)
			}
			anchorJWK, err := jwk.PublicJwk(anchorSigner.Public())
			if err != nil {
				t.Fatalf("failed to build the anchor jwk: %v", err)
			}
			(*anchorJWK)["kid"] = "anchor"

			anchor := NewServer(model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: anchorSigner, KeyID: "anchor"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
			})
			anchorMux := http.NewServeMux()
			anchor.Configure(anchorMux)
			anchorServer := httptest.NewTLSServer(anchorMux)
			defer anchorServer.Close()
			anchor.SetEntityIdentifier(model.EntityIdentifier(anchorServer.URL))
			anchor.SetHttpClient(anchorServer.Client())

			response, err := anchorServer.Client().Get(anchorServer.URL + "/resolve?sub=" + peerIdentifier + "&trust_anchor=" + anchorServer.URL)
			if err != nil {
				t.Fatalf("the resolve handler did not answer, which is what a panic looks like to a caller: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck

			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			if response.StatusCode == http.StatusOK {
				t.Fatalf("expected a malformed peer key to be refused, got 200 with %s", raw)
			}
			if !strings.Contains(string(raw), `"error"`) {
				t.Fatalf("expected a JSON error response, got %s", raw)
			}
		})
	}
}
