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
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_ALimitAnswersTheTrustAnchorCodeNotAFault(t *testing.T) {
	tests := []struct {
		name        string
		reference   string
		maxDepth    int
		maxEntities int
		hints       map[string][]string
		wantBody    string
	}{
		{
			name:        "a chain longer than the depth bound",
			reference:   "8.9",
			maxDepth:    2,
			maxEntities: 1000,
			hints:       map[string][]string{"n0": {"n1"}, "n1": {"n2"}, "n2": {"anchor"}},
			wantBody:    "maximum trust chain depth",
		},
		{
			name:        "more entity configurations than the fetch bound",
			reference:   "8.9",
			maxEntities: 2,
			hints:       map[string][]string{"n0": {"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"}},
			wantBody:    "entity configurations it may fetch",
		},
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

			var peerIdentifier string
			var anchorIdentifier string
			peerMux := http.NewServeMux()
			peerMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-federation") {
					http.NotFound(w, r)
					return
				}
				node := strings.Trim(strings.TrimSuffix(r.URL.Path, "/.well-known/openid-federation"), "/")
				hs, served := tc.hints[node]
				if !served {
					http.NotFound(w, r)
					return
				}
				hints := make([]string, 0, len(hs))
				for _, h := range hs {
					if h == "anchor" {
						hints = append(hints, anchorIdentifier)
						continue
					}
					hints = append(hints, peerIdentifier+"/"+h)
				}
				self := peerIdentifier + "/" + node
				token, signErr := jwt.New(peerSigner, map[string]any{
					"kid": "peer", "typ": "entity-statement+jwt", "alg": "ES256",
				}, map[string]any{
					"iss":             self,
					"sub":             self,
					"iat":             time.Now().Add(-time.Minute).UTC().Unix(),
					"exp":             time.Now().Add(10 * time.Minute).UTC().Unix(),
					"jwks":            map[string]any{"keys": []any{*peerJWK}},
					"authority_hints": hints,
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
				Configuration: model.Configuration{
					MaxTrustChainDepth:   tc.maxDepth,
					MaxEntitiesTraversed: tc.maxEntities,
				},
			})
			anchorMux := http.NewServeMux()
			anchor.Configure(anchorMux)
			anchorServer := httptest.NewTLSServer(anchorMux)
			defer anchorServer.Close()
			anchorIdentifier = anchorServer.URL
			anchor.SetEntityIdentifier(model.EntityIdentifier(anchorServer.URL))
			anchor.SetHttpClient(anchorServer.Client())

			response, err := anchorServer.Client().Get(anchorServer.URL + "/resolve?sub=" + peerIdentifier + "/n0&trust_anchor=" + anchorServer.URL)
			if err != nil {
				t.Fatalf("the resolve handler did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck

			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			body := string(raw)

			if response.StatusCode != http.StatusNotFound {
				t.Errorf("[%s] a configured bound is not a fault of this server, expected 404, got %d with %s", tc.reference, response.StatusCode, body)
			}
			if !strings.Contains(body, `"`+model.InvalidTrustAnchor+`"`) {
				t.Errorf("[%s] expected the error code for a trust anchor that cannot be used, got %s", tc.reference, body)
			}
			if !strings.Contains(body, tc.wantBody) {
				t.Errorf("[%s] expected the description to name the bound reached, got %s", tc.reference, body)
			}
		})
	}
}
