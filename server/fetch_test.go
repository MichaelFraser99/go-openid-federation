package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/model_test"

	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestServer_Fetch(t *testing.T) {
	subordinateSigner, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating subordinate signer, got %q", err.Error())
	}
	subordinateJWK, err := jwk.PublicJwk(subordinateSigner.Public())
	if err != nil {
		t.Fatalf("expected no error creating subordinate JWK, got %q", err.Error())
	}
	tests := map[string]struct {
		iss           string
		requestSub    string // The sub parameter to use in the request
		configuration func() *model.IntermediateConfiguration
		validate      func(t *testing.T, response *http.Response, err error)
	}{
		"we can fetch a subordinate statement for an entity": {
			iss:        "https://some-trust-anchor.com/",
			requestSub: "https://some-federation.com/some-path",
			configuration: func() *model.IntermediateConfiguration {
				testConfiguration := &model.IntermediateConfiguration{
					SubordinateCacheTime: 5 * time.Minute,
				}
				testConfiguration.AddSubordinate("https://some-federation.com/some-path", &model.SubordinateConfiguration{
					Policies: model.MetadataPolicy{
						OpenIDRelyingPartyMetadata: map[string]model.PolicyOperators{
							"contacts": {
								Metadata: []model.MetadataPolicyOperator{
									model_test.NewAdd(t, []any{"ops@edugain.geant.org"}),
								},
							},
						},
					},
					JWKs: josemodel.Jwks{
						Keys: []map[string]any{*subordinateJWK},
					},
				})
				return testConfiguration
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				defer response.Body.Close()
				responseBytes, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("expected status code 200, got %d (response: %s)", response.StatusCode, responseBytes)
				}
				t.Log(string(responseBytes))
			},
		},
		"missing sub parameter returns an error": {
			iss:        "https://some-trust-anchor.com/",
			requestSub: "", // Empty sub parameter
			configuration: func() *model.IntermediateConfiguration {
				return &model.IntermediateConfiguration{
					SubordinateCacheTime: 5 * time.Minute,
				}
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_request", "request missing required parameter 'sub'")
			},
		},
		"invalid sub parameter returns an error": {
			iss:        "https://some-trust-anchor.com/",
			requestSub: "invalid-url", // Invalid URL format
			configuration: func() *model.IntermediateConfiguration {
				return &model.IntermediateConfiguration{
					SubordinateCacheTime: 5 * time.Minute,
				}
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_request", "malformed 'sub' parameter")
			},
		},
		"entity trying to issue statement for itself returns an error": {
			iss:        "https://some-trust-anchor.com/",
			requestSub: "https://some-trust-anchor.com/", // Same as the entity identifier
			configuration: func() *model.IntermediateConfiguration {
				return &model.IntermediateConfiguration{
					SubordinateCacheTime: 5 * time.Minute,
				}
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_request", "an entity cannot issue a subordinate statement for itself")
			},
		},
		"entity not found returns an error": {
			iss:        "https://some-trust-anchor.com/",
			requestSub: "https://non-existent-entity.com/", // Entity that doesn't exist in cfg
			configuration: func() *model.IntermediateConfiguration {
				return &model.IntermediateConfiguration{
					SubordinateCacheTime: 5 * time.Minute,
				}
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusNotFound, "not_found", "unknown entity identifier")
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := jws.GetSigner(josemodel.ES256, nil)
			if err != nil {
				t.Fatalf("expected no error creating signer, got %q", err.Error())
			}
			signerPublicJWK, err := jwk.PublicJwk(signer.Public())
			if err != nil {
				t.Fatalf("expected no error creating public JWK, got %q", err.Error())
			}
			signerPublicJWKBytes, err := json.Marshal(signerPublicJWK)
			if err != nil {
				t.Fatalf("expected no error marshaling public JWK, got %q", err.Error())
			}
			t.Log(string(signerPublicJWKBytes))
			serverConfig := model.ServerConfiguration{
				SignerConfiguration: model.SignerConfiguration{
					Algorithm: "ES256",
					Signer:    signer,
					KeyID:     (*signerPublicJWK)["kid"].(string),
				},
				EntityIdentifier:          model.EntityIdentifier(tt.iss),
				IntermediateConfiguration: tt.configuration(),
				EntityConfiguration: model.EntityStatement{
					Iss: model.EntityIdentifier(tt.iss),
				},
				Configuration: model.Configuration{
					Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
				},
			}
			server := NewServer(serverConfig)
			m := http.NewServeMux()
			server.Configure(m)
			s := httptest.NewServer(m)
			testClient := s.Client()

			// Build the request URL with the test-specific sub parameter
			requestURL := fmt.Sprintf("%s/fetch", s.URL)
			if tt.requestSub != "" {
				requestURL = fmt.Sprintf("%s?sub=%s", requestURL, url.QueryEscape(tt.requestSub))
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
