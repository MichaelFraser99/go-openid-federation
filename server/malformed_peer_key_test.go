package server

import (
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_MalformedPeerKeyDoesNotPanic(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(published map[string]any)
	}{
		{name: "kty that is a number", corrupt: func(p map[string]any) { p["kty"] = 7 }},
		{name: "kty that is an object", corrupt: func(p map[string]any) { p["kty"] = map[string]any{} }},
		{name: "kty that is absent", corrupt: func(p map[string]any) { delete(p, "kty") }},
		{name: "an EC key with no crv", corrupt: func(p map[string]any) { delete(p, "crv") }},
		{name: "an EC key with a numeric crv", corrupt: func(p map[string]any) { p["crv"] = 7 }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peerSigner, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the peer signer: %v", err)
			}
			peerJWK, err := jwk.PublicJwk(peerSigner.Public())
			if err != nil {
				t.Fatalf("failed to build the peer jwk: %v", err)
			}
			(*peerJWK)["kid"] = "peer"

			published := map[string]any{}
			maps.Copy(published, *peerJWK)
			tc.corrupt(published)

			peerMux := http.NewServeMux()
			var peerIdentifier string
			peerMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
				token, signErr := jwt.New(peerSigner, map[string]any{
					"kid": "peer", "typ": "entity-statement+jwt", "alg": "ES256",
				}, map[string]any{
					"iss":  peerIdentifier,
					"sub":  peerIdentifier,
					"iat":  time.Now().Add(-time.Minute).UTC().Unix(),
					"exp":  time.Now().Add(10 * time.Minute).UTC().Unix(),
					"jwks": map[string]any{"keys": []any{published}},
				}, jwt.Opts{Algorithm: jwa.ES256})
				if signErr != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				_, _ = w.Write([]byte(*token))
			})
			peer := httptest.NewTLSServer(peerMux)
			defer peer.Close()
			peerIdentifier = peer.URL

			anchorSigner, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the anchor signer: %v", err)
			}

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
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected a malformed peer key to be refused as a bad chain, got %d with %s", response.StatusCode, raw)
			}
			if !strings.Contains(string(raw), `"invalid_trust_chain"`) {
				t.Fatalf("expected the chain to be refused as invalid, got %s", raw)
			}
		})
	}
}
