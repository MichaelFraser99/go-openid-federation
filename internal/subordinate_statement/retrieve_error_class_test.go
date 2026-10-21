package subordinate_statement

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const retrieveMarker = "RETRIEVE-MARKER-ZZZZ"

type peerResponse struct {
	status      int
	contentType string
	body        func(t *testing.T, issuerKey *rsa.PrivateKey, issuerJwk map[string]any, issuer model.EntityIdentifier) string
	handler     http.HandlerFunc
}

func TestRetrieve_ClassifiesWhoseFaultTheFailureIs(t *testing.T) {
	const limit int64 = 4096

	issuerKey := testKey(t)
	issuerJwk := testPublicJwk(t, issuerKey.Public(), "ta")

	statementAbout := func(sub string) func(*testing.T, *rsa.PrivateKey, map[string]any, model.EntityIdentifier) string {
		return func(t *testing.T, key *rsa.PrivateKey, keyJwk map[string]any, issuer model.EntityIdentifier) string {
			return testSign(t, key, map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"}, map[string]any{
				"iss":  string(issuer),
				"sub":  sub,
				"iat":  time.Now().Add(-time.Minute).UTC().Unix(),
				"exp":  time.Now().Add(time.Hour).UTC().Unix(),
				"jwks": map[string]any{"keys": []any{keyJwk}},
			})
		}
	}

	tests := map[string]struct {
		reference   string
		noClient    bool
		issuerIsNot bool
		endpoint    func(base string) any
		response    *peerResponse
		expectKind  error
		forbidden   []string
	}{
		"this server with no http client of its own": {
			reference:  "8.9 server_error",
			noClient:   true,
			expectKind: model.ErrServerError,
		},
		"an issuer that is not an entity configuration": {
			reference:   "8.9 server_error",
			issuerIsNot: true,
			expectKind:  model.ErrServerError,
		},
		"a superior that advertises no fetch endpoint": {
			reference:  "8.9 invalid_trust_chain",
			endpoint:   func(string) any { return nil },
			expectKind: model.ErrInvalidTrustChain,
		},
		"a fetch endpoint that is not a usable url": {
			reference:  "8.9 invalid_trust_chain",
			endpoint:   func(string) any { return "https://\x7f.example.com/" + retrieveMarker },
			expectKind: model.ErrInvalidTrustChain,
			forbidden:  []string{retrieveMarker},
		},
		"a fetch endpoint that cannot be reached": {
			reference:  "8.9 invalid_trust_chain",
			endpoint:   func(string) any { return "https://127.0.0.1:1/" + retrieveMarker },
			expectKind: model.ErrInvalidTrustChain,
			forbidden:  []string{retrieveMarker, "127.0.0.1:1", "connection refused"},
		},
		"a fetch endpoint that answers a non-200": {
			reference:  "8.9 invalid_trust_chain",
			response:   &peerResponse{status: http.StatusForbidden, contentType: "text/plain", body: nil},
			expectKind: model.ErrInvalidTrustChain,
			forbidden:  []string{"403", "Forbidden"},
		},
		"a fetch endpoint that answers the wrong content type": {
			reference:  "8.9 invalid_trust_chain",
			response:   &peerResponse{contentType: "application/json; profile=" + retrieveMarker},
			expectKind: model.ErrInvalidTrustChain,
			forbidden:  []string{retrieveMarker, "application/json"},
		},
		"a fetch endpoint that answers more than the response limit": {
			reference: "8.9 invalid_trust_chain",
			response: &peerResponse{
				contentType: "application/entity-statement+jwt",
				body: func(*testing.T, *rsa.PrivateKey, map[string]any, model.EntityIdentifier) string {
					return strings.Repeat(retrieveMarker, int(limit))
				},
			},
			expectKind: model.ErrInvalidTrustChain,
			forbidden:  []string{retrieveMarker},
		},
		"a fetch endpoint that cuts the response short": {
			reference: "8.9 invalid_trust_chain",
			response: &peerResponse{
				handler: func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/entity-statement+jwt")
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					_, _ = w.Write([]byte(retrieveMarker))
					w.(http.Flusher).Flush()
					panic(http.ErrAbortHandler)
				},
			},
			expectKind: model.ErrInvalidTrustChain,
			forbidden:  []string{retrieveMarker, "unexpected EOF"},
		},
		"a fetch endpoint that answers a statement about another subject": {
			reference: "8.9 invalid_trust_chain",
			response: &peerResponse{
				contentType: "application/entity-statement+jwt",
				body:        statementAbout("https://" + strings.ToLower(retrieveMarker) + ".example.com"),
			},
			expectKind: model.ErrInvalidTrustChain,
			forbidden:  []string{strings.ToLower(retrieveMarker)},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var served string
			var servedType string
			servedStatus := http.StatusOK
			if tc.response != nil {
				servedType = tc.response.contentType
				if tc.response.status != 0 {
					servedStatus = tc.response.status
				}
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if servedType != "" {
					w.Header().Set("Content-Type", servedType)
				}
				w.WriteHeader(servedStatus)
				_, _ = w.Write([]byte(served))
			})
			if tc.response != nil && tc.response.handler != nil {
				handler = tc.response.handler
			}
			server := httptest.NewTLSServer(handler)
			t.Cleanup(server.Close)

			issuerIdentifier := model.EntityIdentifier(server.URL)
			if tc.response != nil && tc.response.body != nil {
				served = tc.response.body(t, issuerKey, issuerJwk, issuerIdentifier)
			}

			cfg := model.Configuration{HttpClient: server.Client(), MaxPeerResponseBytes: limit}
			if tc.noClient {
				cfg.HttpClient = nil
			}

			issuer := model.EntityStatement{
				Iss:      issuerIdentifier,
				Sub:      issuerIdentifier,
				Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{"federation_fetch_endpoint": server.URL + "/fetch"}},
				JWKs:     josemodel.Jwks{Keys: []map[string]any{issuerJwk}},
			}
			if tc.issuerIsNot {
				issuer.Iss = "https://someone-else.example.com"
			}
			if tc.endpoint != nil {
				if endpoint := tc.endpoint(server.URL); endpoint == nil {
					issuer.Metadata = nil
				} else {
					issuer.Metadata = &model.Metadata{FederationMetadata: &model.FederationMetadata{"federation_fetch_endpoint": endpoint}}
				}
			}

			_, _, err := Retrieve(t.Context(), cfg, issuer, "https://leaf.example.com")
			if err == nil {
				t.Fatalf("[%s] expected the retrieval to be refused", tc.reference)
			}
			if !errors.Is(err, tc.expectKind) {
				t.Fatalf("[%s] expected the failure to carry the class the spec defines for it, got %v", tc.reference, err)
			}
			if tc.expectKind != model.ErrServerError && errors.Is(err, model.ErrServerError) {
				t.Errorf("[%s] a fault that is not this server's must not be reported as server_error, got %v", tc.reference, err)
			}
			for _, forbidden := range tc.forbidden {
				if strings.Contains(err.Error(), forbidden) {
					t.Errorf("[%s] the error reveals %q about the superior or the request made to it: %v", tc.reference, forbidden, err)
				}
			}
		})
	}
}
