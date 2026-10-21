package server

import (
	"crypto"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

const peerFetchMarker = "PEER-FETCH-MARKER-ZZZZ"

type peerFederation struct {
	server    *httptest.Server
	anchorID  string
	leafID    string
	signer    crypto.Signer
	publicJWK map[string]any
}

func newPeerKey(t *testing.T) (crypto.Signer, map[string]any) {
	t.Helper()
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the peer signer: %v", err)
	}
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to build the peer jwk: %v", err)
	}
	(*publicJWK)["kid"] = "peer"
	return signer, *publicJWK
}

func writePeerStatement(w http.ResponseWriter, signer crypto.Signer, claims map[string]any) {
	token, err := jwt.New(signer, map[string]any{
		"kid": "peer", "typ": "entity-statement+jwt", "alg": "ES256",
	}, claims, jwt.Opts{Algorithm: josemodel.ES256})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	_, _ = w.Write([]byte(*token))
}

func startPeerFederation(t *testing.T, anchorMetadata func(base string) map[string]any, fetch http.HandlerFunc) *peerFederation {
	t.Helper()
	signer, publicJWK := newPeerKey(t)
	peer := &peerFederation{signer: signer, publicJWK: publicJWK}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		claims := map[string]any{
			"iat":  time.Now().Add(-time.Minute).UTC().Unix(),
			"exp":  time.Now().Add(10 * time.Minute).UTC().Unix(),
			"jwks": map[string]any{"keys": []any{publicJWK}},
		}
		switch r.URL.Path {
		case "/anchor/.well-known/openid-federation":
			claims["iss"] = base + "/anchor"
			claims["sub"] = base + "/anchor"
			if metadata := anchorMetadata(base); metadata != nil {
				claims["metadata"] = metadata
			}
		case "/leaf/.well-known/openid-federation":
			claims["iss"] = base + "/leaf"
			claims["sub"] = base + "/leaf"
			claims["authority_hints"] = []string{base + "/anchor"}
		default:
			if fetch != nil && r.URL.Path == "/fetch" {
				fetch(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
		writePeerStatement(w, signer, claims)
	})
	peer.server = httptest.NewTLSServer(mux)
	t.Cleanup(peer.server.Close)
	peer.anchorID = peer.server.URL + "/anchor"
	peer.leafID = peer.server.URL + "/leaf"
	return peer
}

func startResolverFor(t *testing.T, peer *peerFederation, cfg model.Configuration) *httptest.Server {
	t.Helper()
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the resolver signer: %v", err)
	}
	resolver := NewServer(model.ServerConfiguration{
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "resolver"},
		EntityConfigurationLifetime: 10 * time.Minute,
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
		Configuration:               cfg,
	})
	mux := http.NewServeMux()
	resolver.Configure(mux)
	resolverServer := httptest.NewTLSServer(mux)
	t.Cleanup(resolverServer.Close)
	resolver.SetEntityIdentifier(model.EntityIdentifier(resolverServer.URL))
	resolver.SetHttpClient(peer.server.Client())
	return resolverServer
}

func federationFetchEndpointMetadata(endpoint string) map[string]any {
	return map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": endpoint}}
}

func TestServer_Resolve_DoesNotReflectSubordinateStatementFetchDetail(t *testing.T) {
	const peerResponseLimit = 4096

	tests := []struct {
		name      string
		reference string
		metadata  func(base string) map[string]any
		fetch     func(signer crypto.Signer, publicJWK map[string]any) http.HandlerFunc
		forbidden []string
	}{
		{
			name:      "a fetch endpoint that refuses the connection",
			reference: "8.9 invalid_trust_chain",
			metadata: func(string) map[string]any {
				return federationFetchEndpointMetadata("https://127.0.0.1:1/" + peerFetchMarker)
			},
			forbidden: []string{peerFetchMarker, "127.0.0.1:1", "connection refused", "dial"},
		},
		{
			name:      "a fetch endpoint that answers a status of its choosing",
			reference: "8.9 invalid_trust_chain",
			metadata: func(base string) map[string]any {
				return federationFetchEndpointMetadata(base + "/fetch")
			},
			fetch: func(crypto.Signer, map[string]any) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					http.Error(w, peerFetchMarker, http.StatusForbidden)
				}
			},
			forbidden: []string{peerFetchMarker, "403", "Forbidden"},
		},
		{
			name:      "a fetch endpoint that answers a content type of its choosing",
			reference: "8.9 invalid_trust_chain",
			metadata: func(base string) map[string]any {
				return federationFetchEndpointMetadata(base + "/fetch")
			},
			fetch: func(crypto.Signer, map[string]any) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json; profile="+peerFetchMarker)
					_, _ = w.Write([]byte("{}"))
				}
			},
			forbidden: []string{peerFetchMarker, "application/json"},
		},
		{
			name:      "a fetch endpoint that answers more than the response limit",
			reference: "8.9 invalid_trust_chain",
			metadata: func(base string) map[string]any {
				return federationFetchEndpointMetadata(base + "/fetch")
			},
			fetch: func(crypto.Signer, map[string]any) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/entity-statement+jwt")
					_, _ = w.Write([]byte(strings.Repeat(peerFetchMarker, peerResponseLimit)))
				}
			},
			forbidden: []string{peerFetchMarker, "response limit"},
		},
		{
			name:      "a superior that advertises no fetch endpoint",
			reference: "8.9 invalid_trust_chain",
			metadata: func(string) map[string]any {
				return map[string]any{"federation_entity": map[string]any{"organization_name": peerFetchMarker}}
			},
			forbidden: []string{peerFetchMarker, "federation metadata"},
		},
		{
			name:      "a fetch endpoint that answers a statement about another subject",
			reference: "8.9 invalid_trust_chain",
			metadata: func(base string) map[string]any {
				return federationFetchEndpointMetadata(base + "/fetch")
			},
			fetch: func(signer crypto.Signer, publicJWK map[string]any) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					base := "https://" + r.Host
					writePeerStatement(w, signer, map[string]any{
						"iss":  base + "/anchor",
						"sub":  base + "/" + peerFetchMarker,
						"iat":  time.Now().Add(-time.Minute).UTC().Unix(),
						"exp":  time.Now().Add(10 * time.Minute).UTC().Unix(),
						"jwks": map[string]any{"keys": []any{publicJWK}},
					})
				}
			},
			forbidden: []string{peerFetchMarker, "'sub' claim does not match"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var handler http.HandlerFunc
			peer := startPeerFederation(t, tc.metadata, func(w http.ResponseWriter, r *http.Request) {
				if handler == nil {
					http.NotFound(w, r)
					return
				}
				handler(w, r)
			})
			if tc.fetch != nil {
				handler = tc.fetch(peer.signer, peer.publicJWK)
			}

			resolverServer := startResolverFor(t, peer, model.Configuration{MaxPeerResponseBytes: peerResponseLimit})

			response, err := resolverServer.Client().Get(resolverServer.URL + "/resolve?sub=" + url.QueryEscape(peer.leafID) + "&trust_anchor=" + url.QueryEscape(peer.anchorID))
			if err != nil {
				t.Fatalf("the resolve handler did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			body := string(raw)

			if response.StatusCode != http.StatusBadRequest {
				t.Errorf("[%s] a superior the caller named is not a fault of this server, expected 400, got %d with %s", tc.reference, response.StatusCode, body)
			}
			if !strings.Contains(body, `"`+model.InvalidTrustChain+`"`) {
				t.Errorf("[%s] expected the error code for a chain that cannot be validated, got %s", tc.reference, body)
			}
			if !strings.Contains(body, subordinateStatementFetchDescription) {
				t.Errorf("[%s] expected the fixed description %q, got %s", tc.reference, subordinateStatementFetchDescription, body)
			}
			for _, forbidden := range tc.forbidden {
				if strings.Contains(body, forbidden) {
					t.Errorf("[%s] the response reveals %q about the request made to the superior the caller named: %s", tc.reference, forbidden, body)
				}
			}
			if len(raw) > model.MaxErrorDescriptionBytes+256 {
				t.Errorf("[%s] expected the error description to be bounded by %d bytes, got a %d byte body: %s", tc.reference, model.MaxErrorDescriptionBytes, len(raw), body)
			}
		})
	}
}

const subordinateStatementFetchDescription = "failed to retrieve a usable subordinate statement for an entity in the trust chain"
