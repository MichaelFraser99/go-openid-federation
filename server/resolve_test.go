package server

import (
	"fmt"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
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

	directChildSigner, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating direct child signer, got %q", err.Error())
	}
	directChildPublicJWK, err := jwk.PublicJwk(directChildSigner.Public())
	if err != nil {
		t.Fatalf("expected no error creating direct child public JWK, got %q", err.Error())
	}

	directChildEntityServer := NewServer(model.ServerConfiguration{
		SignerConfiguration: model.SignerConfiguration{
			Algorithm: "ES256",
			Signer:    directChildSigner,
			KeyID:     (*directChildPublicJWK)["kid"].(string),
		},
		EntityConfiguration:         model.EntityStatement{},
		EntityConfigurationLifetime: 10 * time.Minute,
	})
	dcm := http.NewServeMux()
	directChildEntityServer.Configure(dcm)
	dcs := httptest.NewTLSServer(dcm)
	directChildEntityServer.SetEntityIdentifier(model.EntityIdentifier(dcs.URL))

	tests := map[string]struct {
		requestSub  string   // The sub parameter to use in the request
		trustAnchor *string  // The trust_anchor parameter to use in the request
		entityTypes []string // The entity_type parameters to use in the request
		validate    func(t *testing.T, response *http.Response, err error)
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
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_request", "missing 'sub' parameter")
			},
		},
		"missing trust_anchor parameter returns an error": {
			requestSub:  "https://some-entity.com/",
			trustAnchor: model.Pointer(""),
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_request", "missing 'trust_anchor' parameter")
			},
		},
		"invalid sub parameter returns an error": {
			requestSub: "invalid-url", // Invalid URL format
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusNotFound, "not_found", "unknown subject")
			},
		},
		"invalid trust_anchor parameter returns an error": {
			requestSub:  "https://some-entity.com/",
			trustAnchor: model.Pointer("invalid-url"), // Invalid URL format
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusNotFound, "not_found", "unknown trust anchor")
			},
		},
		"entity not found returns an error": {
			requestSub: "https://non-existent-entity.com/", // Entity that doesn't exist
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusNotFound, "not_found", "unknown entity identifier")
			},
		},
		"trust anchor not found returns an error": {
			requestSub:  "https://some-entity.com/",
			trustAnchor: model.Pointer("https://non-existent-trust-anchor.com/"), // Trust anchor that doesn't exist
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusNotFound, "not_found", "unknown entity identifier")
			},
		},
		"error building trust chain returns an error": {
			requestSub:  "https://some-entity.com/",
			trustAnchor: model.Pointer("https://some-trust-anchor.com/"),
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusNotFound, "not_found", "unknown entity identifier")
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
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
				SignerConfiguration: model.SignerConfiguration{
					Algorithm: "ES256",
					Signer:    signer,
					KeyID:     (*signerPublicJWK)["kid"].(string),
				},
				IntermediateConfiguration:   intermediateConfigurations,
				EntityConfiguration:         model.EntityStatement{},
				EntityConfigurationLifetime: 10 * time.Minute,
				MetadataRetriever:           tr,
			}
			server := NewServer(serverConfig)
			server.WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
			m := http.NewServeMux()
			server.Configure(m)
			s := httptest.NewTLSServer(m)
			testClient := s.Client()
			server.SetEntityIdentifier(model.EntityIdentifier(s.URL))
			server.SetHttpClient(testClient)

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
