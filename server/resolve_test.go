package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/model_test"
)

func TestServer_Resolve(t *testing.T) {
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating signer, got %q", err.Error())
	}
	signerPublicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("expected no error creating public JWK, got %q", err.Error())
	}

	trustAnchorSigner, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating trust anchor signer, got %q", err.Error())
	}
	trustAnchorPublicJWK, err := jwk.PublicJwk(trustAnchorSigner.Public())
	if err != nil {
		t.Fatalf("expected no error creating trust anchor public JWK, got %q", err.Error())
	}

	directChildSigner, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating direct child signer, got %q", err.Error())
	}
	directChildPublicJWK, err := jwk.PublicJwk(directChildSigner.Public())
	if err != nil {
		t.Fatalf("expected no error creating direct child public JWK, got %q", err.Error())
	}

	trustAnchorServer := NewServer(model.ServerConfiguration{
		SignerConfiguration: model.SignerConfiguration{
			Algorithm: "ES256",
			Signer:    trustAnchorSigner,
			KeyID:     (*trustAnchorPublicJWK)["kid"].(string),
		},
		EntityConfiguration:         model.EntityStatement{},
		EntityConfigurationLifetime: 10 * time.Minute,
		IntermediateConfiguration: &model.IntermediateConfiguration{
			SubordinateStatementLifetime: 1 * time.Minute,
			SubordinateCacheTime:         5 * time.Minute,
		},
		Configuration: model.Configuration{
			Logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
		},
	})

	tam := http.NewServeMux()
	trustAnchorServer.Configure(tam)
	tas := httptest.NewTLSServer(tam)
	trustAnchorServer.SetEntityIdentifier(model.EntityIdentifier(tas.URL))

	t.Cleanup(func() {
		tas.Close()
	})

	directChildEntityServer := NewServer(model.ServerConfiguration{
		SignerConfiguration: model.SignerConfiguration{
			Algorithm: "ES256",
			Signer:    directChildSigner,
			KeyID:     (*directChildPublicJWK)["kid"].(string),
		},
		EntityConfiguration: model.EntityStatement{
			Metadata: &model.Metadata{
				OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
					"scope":                     "openid address",
					"redirect_uris":             []string{"https://my-client.com/cb"},
					"client_registration_types": []string{"automatic"},
				},
			},
		},
		EntityConfigurationLifetime: 10 * time.Minute,
	})

	dcm := http.NewServeMux()
	directChildEntityServer.Configure(dcm)
	dcs := httptest.NewTLSServer(dcm)
	directChildEntityServer.SetEntityIdentifier(model.EntityIdentifier(dcs.URL))

	t.Cleanup(func() {
		dcs.Close()
	})

	validTrustAnchor := tas.URL
	validEntityIdentifier := dcs.URL

	tests := map[string]struct {
		requestSub        string
		trustAnchor       *string
		trustAnchorPolicy model.MetadataPolicy
		entityTypes       []string
		validate          func(t *testing.T, response *http.Response, err error)
	}{
		"we can resolve a valid entity": {
			requestSub: dcs.URL,
			validate: func(t *testing.T, response *http.Response, err error) {
				validateFetchResponse(t, response, err, http.StatusOK)
			},
		},
		"missing sub parameter returns an error": {
			requestSub: "", // Empty sub parameter
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_request", "request missing required parameter 'sub'")
			},
		},
		"missing trust_anchor parameter returns an error": {
			requestSub:  validEntityIdentifier,
			trustAnchor: model.Pointer(""),
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_request", "missing required parameter 'trust_anchor'")
			},
		},
		"invalid sub parameter returns an error": {
			requestSub: "invalid-url", // Invalid URL format
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_request", "malformed 'sub' parameter")
			},
		},
		"invalid trust_anchor parameter returns an error": {
			requestSub:  validEntityIdentifier,
			trustAnchor: model.Pointer("invalid-url"), // Invalid URL format
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_request", "malformed 'trust_anchor' parameter")
			},
		},
		"entity not found returns an error": {
			requestSub: "https://non-existent-entity.com/", // Entity that doesn't exist
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusNotFound, "not_found", "failed to retrieve leaf entity configuration: https://non-existent-entity.com/")
			},
		},
		"trust anchor not found returns an error": {
			requestSub:  validEntityIdentifier,
			trustAnchor: model.Pointer("https://non-existent-trust-anchor.com/"), // Trust anchor that doesn't exist
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusNotFound, "invalid_trust_anchor", "unable to build trust chain from specified 'sub' to specified 'trust_anchor'")
			},
		},
		"error resolving trust chain metadata returns an error": {
			requestSub:  validEntityIdentifier,
			trustAnchor: &validTrustAnchor,
			trustAnchorPolicy: model.MetadataPolicy{
				OpenIDRelyingPartyMetadata: map[string]model.PolicyOperators{
					"scope": {
						Metadata: []model.MetadataPolicyOperator{
							model_test.NewSupersetOf(t, []any{"foo", "bar"}),
							model_test.NewSubsetOf(t, []any{"baz", "bing"}),
							model_test.NewEssential(t, true),
						},
					},
				},
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_metadata", "unresolvable metadata policy encountered")
			},
		},
		"valid trust chain with more complex metadata": {
			requestSub:  validEntityIdentifier,
			trustAnchor: &validTrustAnchor,
			trustAnchorPolicy: model.MetadataPolicy{
				OpenIDRelyingPartyMetadata: map[string]model.PolicyOperators{
					"scope": {
						Metadata: []model.MetadataPolicyOperator{
							model_test.NewAdd(t, []any{"phone_number"}),
							model_test.NewSubsetOf(t, []any{"openid", "address", "phone_number"}),
							model_test.NewSupersetOf(t, []any{"openid"}),
						},
					},
				},
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				validateFetchResponse(t, response, err, http.StatusOK)
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			trustAnchorServer.cfg.IntermediateConfiguration.FlushCache()
			intermediateConfigurations := &model.IntermediateConfiguration{
				SubordinateStatementLifetime: 1 * time.Minute,
			}
			intermediateConfigurations.AddSubordinate(model.EntityIdentifier(dcs.URL), &model.SubordinateConfiguration{})

			tr := TestRetriever{}
			tr.Configure(map[string]*model.SubordinateConfiguration{
				dcs.URL: {
					JWKs: josemodel.Jwks{
						Keys: []map[string]any{*directChildPublicJWK},
					},
				},
			})

			serverConfig := model.ServerConfiguration{
				AuthorityHints: []model.EntityIdentifier{
					model.EntityIdentifier(tas.URL),
				},
				SignerConfiguration: model.SignerConfiguration{
					Algorithm: "ES256",
					Signer:    signer,
					KeyID:     (*signerPublicJWK)["kid"].(string),
				},
				IntermediateConfiguration:   intermediateConfigurations,
				EntityConfiguration:         model.EntityStatement{},
				EntityConfigurationLifetime: 10 * time.Minute,
				MetadataRetriever:           tr,
				Configuration: model.Configuration{
					Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
				},
			}
			server := NewServer(serverConfig)
			server.WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
			m := http.NewServeMux()
			server.Configure(m)
			s := httptest.NewTLSServer(m)
			t.Cleanup(func() {
				s.Close()
			})
			testClient := s.Client()
			server.SetEntityIdentifier(model.EntityIdentifier(s.URL))
			server.SetHttpClient(testClient)

			trustAnchorServer.cfg.IntermediateConfiguration.AddSubordinate(model.EntityIdentifier(s.URL), &model.SubordinateConfiguration{
				CachedAt: time.Now().UTC().Unix(),
				JWKs: josemodel.Jwks{
					Keys: []map[string]any{*signerPublicJWK},
				},
				Policies: tt.trustAnchorPolicy,
			})

			directChildEntityServer.AddAuthorityHint(model.EntityIdentifier(s.URL))

			// Build the request URL with the test-specific parameters
			requestURL := fmt.Sprintf("%s/resolve", s.URL)
			params := url.Values{}
			if tt.requestSub != "" {
				params.Add("sub", tt.requestSub)
			}
			if tt.trustAnchor == nil {
				params.Add("trust_anchor", s.URL)
			} else {
				params.Add("trust_anchor", *tt.trustAnchor)
			}
			for _, entityType := range tt.entityTypes {
				params.Add("entity_type", entityType)
			}
			if len(params) > 0 {
				requestURL = fmt.Sprintf("%s?%s", requestURL, params.Encode())
			}

			req, err := http.NewRequest("GET", requestURL, nil)
			if err != nil {
				t.Fatalf("expected no error creating request, got %q", err.Error())
			}

			resp, err := testClient.Do(req)

			tt.validate(t, resp, err)
		})
	}
}
