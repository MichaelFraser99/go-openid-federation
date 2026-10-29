package server

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const signerSecret = "kms: AccessDenied arn:aws:kms:eu-west-2:123456789012:key/abcd"

type signingEndpoint struct {
	name        string
	description string
	signed      string
	request     func(t *testing.T, refuse error) *http.Response
}

func signerFor(t *testing.T, refuse error) crypto.Signer {
	t.Helper()
	working, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	if refuse == nil {
		return working
	}
	return refusingSigner{public: working.Public(), err: refuse}
}

func leafSubordinate(t *testing.T) *model.SubordinateConfiguration {
	t.Helper()
	leafSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the leaf signer: %v", err)
	}
	leafJWK, err := jwk.PublicJwk(leafSigner.Public())
	if err != nil {
		t.Fatalf("failed to build the leaf jwk: %v", err)
	}
	return &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{*leafJWK}}}
}

func signingServer(t *testing.T, refuse error, apply func(cfg *model.ServerConfiguration)) *httptest.Server {
	t.Helper()
	return contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.SignerConfiguration.Signer = signerFor(t, refuse)
		apply(cfg)
	})
}

func get(t *testing.T, ts *httptest.Server, path string) *http.Response {
	t.Helper()
	response, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatalf("the handler did not answer: %v", err)
	}
	return response
}

func resolveWithSigner(t *testing.T, refuse error) *http.Response {
	t.Helper()
	var peer *peerFederation
	peer = startPeerFederation(t, func(base string) map[string]any {
		return federationFetchEndpointMetadata(base + "/fetch")
	}, func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		writePeerStatement(w, peer.signer, map[string]any{
			"iss":  base + "/anchor",
			"sub":  base + "/leaf",
			"iat":  time.Now().Add(-time.Minute).UTC().Unix(),
			"exp":  time.Now().Add(10 * time.Minute).UTC().Unix(),
			"jwks": map[string]any{"keys": []any{peer.publicJWK}},
		})
	})

	resolver := NewServer(model.ServerConfiguration{
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signerFor(t, refuse), KeyID: "resolver"},
		EntityConfigurationLifetime: 10 * time.Minute,
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
	})
	mux := http.NewServeMux()
	resolver.Configure(mux)
	resolverServer := httptest.NewTLSServer(mux)
	t.Cleanup(resolverServer.Close)
	resolver.SetEntityIdentifier(model.EntityIdentifier(resolverServer.URL))
	resolver.SetHttpClient(peer.server.Client())

	return get(t, resolverServer, "/resolve?sub="+url.QueryEscape(peer.leafID)+"&trust_anchor="+url.QueryEscape(peer.anchorID))
}

func signingEndpoints() []signingEndpoint {
	return []signingEndpoint{
		{
			name:        "/.well-known/openid-federation",
			description: entityConfigurationUnavailableError,
			request: func(t *testing.T, refuse error) *http.Response {
				return get(t, signingServer(t, refuse, func(*model.ServerConfiguration) {}), "/.well-known/openid-federation")
			},
		},
		{
			name:        "/fetch",
			description: subordinateStatementUnavailableError,
			request: func(t *testing.T, refuse error) *http.Response {
				ts := signingServer(t, refuse, func(cfg *model.ServerConfiguration) {
					cfg.IntermediateConfiguration.SubordinateCacheTime = time.Minute
					cfg.IntermediateConfiguration.AddSubordinate("https://leaf.example.com", leafSubordinate(t))
				})
				return get(t, ts, "/fetch?sub="+url.QueryEscape("https://leaf.example.com"))
			},
		},
		{
			name:        "/extended-list",
			description: extendedListingUnavailableError,
			signed:      `"subordinate_statement":"`,
			request: func(t *testing.T, refuse error) *http.Response {
				ts := signingServer(t, refuse, func(cfg *model.ServerConfiguration) {
					cfg.IntermediateConfiguration.SubordinateCacheTime = time.Minute
					cfg.IntermediateConfiguration.AddSubordinate("https://leaf.example.com", leafSubordinate(t))
					cfg.Extensions = model.Extensions{
						ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: listingWithOneEntity{}},
					}
				})
				return get(t, ts, "/extended-list?claims=subordinate_statement")
			},
		},
		{
			name:        "/resolve",
			description: resolveUnavailableError,
			request:     resolveWithSigner,
		},
		{
			name:        "/subordinate-status",
			description: subordinateStatusUnavailableError,
			request: func(t *testing.T, refuse error) *http.Response {
				ts := signingServer(t, refuse, func(cfg *model.ServerConfiguration) {
					cfg.Extensions = model.Extensions{
						SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: sharedStatusRetriever{shared: &model.SubordinateStatusResponse{}}},
					}
				})
				return get(t, ts, "/subordinate-status?sub="+url.QueryEscape("https://leaf.example.com"))
			},
		},
		{
			name:        "/trust-mark-status",
			description: trustMarkStatusUnavailableError,
			request: func(t *testing.T, refuse error) *http.Response {
				ts := signingServer(t, refuse, func(cfg *model.ServerConfiguration) {
					cfg.TrustMarkRetriever = testTrustMarkRetriever{status: model.Pointer("active")}
				})
				form := url.Values{"trust_mark": {"a.b.c"}}
				response, err := ts.Client().Post(ts.URL+"/trust-mark-status", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
				if err != nil {
					t.Fatalf("the handler did not answer: %v", err)
				}
				return response
			},
		},
	}
}

func TestServer_EverySigningEndpointClassifiesASignerFailureAlike(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		refuse    error
		status    int
		code      string
	}{
		{
			name:      "a signer that refuses for a reason of its own",
			reference: "8.9 server_error",
			refuse:    errors.New(signerSecret),
			status:    http.StatusInternalServerError,
			code:      model.ServerError,
		},
		{
			name:      "a signer that wraps not_found",
			reference: "8.9 server_error",
			refuse:    fmt.Errorf("%w%s", model.ErrNotFound, signerSecret),
			status:    http.StatusInternalServerError,
			code:      model.ServerError,
		},
		{
			name:      "a signer that wraps invalid_request",
			reference: "8.9 server_error",
			refuse:    fmt.Errorf("%w%s", model.ErrInvalidRequest, signerSecret),
			status:    http.StatusInternalServerError,
			code:      model.ServerError,
		},
		{
			name:      "a signer that says it is temporarily unable to sign",
			reference: "8.9 temporarily_unavailable",
			refuse:    fmt.Errorf("%w%s", model.ErrTemporarilyUnavailable, signerSecret),
			status:    http.StatusServiceUnavailable,
			code:      model.TemporarilyUnavailable,
		},
	}

	for _, endpoint := range signingEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			control := endpoint.request(t, nil)
			controlBody, err := io.ReadAll(control.Body)
			_ = control.Body.Close()
			if err != nil {
				t.Fatalf("failed to read the control response body: %v", err)
			}
			if control.StatusCode != http.StatusOK || !strings.Contains(string(controlBody), endpoint.signed) {
				t.Fatalf("the fixture is wrong: with a working signer %s answered %d with %s", endpoint.name, control.StatusCode, controlBody)
			}

			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					response := endpoint.request(t, tc.refuse)
					defer response.Body.Close() //nolint:errcheck
					raw, err := io.ReadAll(response.Body)
					if err != nil {
						t.Fatalf("failed to read the response body: %v", err)
					}
					body := string(raw)

					if response.StatusCode != tc.status {
						t.Errorf("[%s] expected %d, got %d with %s", tc.reference, tc.status, response.StatusCode, body)
					}
					if !strings.Contains(body, `"`+tc.code+`"`) {
						t.Errorf("[%s] expected the error code %q, got %s", tc.reference, tc.code, body)
					}
					if !strings.Contains(body, endpoint.description) {
						t.Errorf("[%s] expected the fixed description %q, got %s", tc.reference, endpoint.description, body)
					}
					for _, forbidden := range []string{"kms", "arn:", "AccessDenied"} {
						if strings.Contains(body, forbidden) {
							t.Errorf("[%s] the response reveals %q from the signer's own error: %s", tc.reference, forbidden, body)
						}
					}
				})
			}
		})
	}
}

type failingSubordinatesStore struct{ err error }

func (s failingSubordinatesStore) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return nil, s.err
}

func (s failingSubordinatesStore) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return nil, s.err
}

func (s failingSubordinatesStore) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, s.err
}

func TestServer_List_ARetrieverFailureKeepsItsErrorClass(t *testing.T) {
	tests := []struct {
		name        string
		reference   string
		err         error
		status      int
		code        string
		description string
	}{
		{
			name:        "a store that says it is broken",
			reference:   "8.9 server_error",
			err:         model.NewServerError("the subordinate table is corrupt"),
			status:      http.StatusInternalServerError,
			code:        model.ServerError,
			description: "the subordinate table is corrupt",
		},
		{
			name:        "a store that says it is down for maintenance",
			reference:   "8.9 temporarily_unavailable",
			err:         model.NewTemporarilyUnavailableError("the subordinate store is down for maintenance"),
			status:      http.StatusServiceUnavailable,
			code:        model.TemporarilyUnavailable,
			description: "the subordinate store is down for maintenance",
		},
		{
			name:        "a store failure with no class of its own",
			reference:   "8.9 server_error",
			err:         errors.New("pq: relation \"subordinates\" does not exist"),
			status:      http.StatusInternalServerError,
			code:        model.ServerError,
			description: listingUnavailableError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := contractServer(t, func(cfg *model.ServerConfiguration) {
				cfg.MetadataRetriever = failingSubordinatesStore{err: tc.err}
			})
			response := get(t, ts, "/list")
			validateErrorResponse(t, response, nil, tc.status, tc.code, tc.description)
		})
	}
}
