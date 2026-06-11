package server

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/model_test"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	_ model.Retriever                  = TestRetriever{}
	_ model.ExtendedListingRetriever   = TestExtendedRetriever{}
	_ model.SubordinateStatusRetriever = TestSubordinateStatusRetriever{}
)

type TestRetriever struct {
	configuration map[string]*model.SubordinateConfiguration
}

func (t *TestRetriever) Configure(configuration map[string]*model.SubordinateConfiguration) {
	t.configuration = configuration
}

func (t TestRetriever) GetSubordinate(ctx context.Context, identifier model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	if val, ok := t.configuration[string(identifier)]; ok {
		return val, nil
	} else {
		return nil, model.NewNotFoundError(fmt.Sprintf("subordinate cfg not found: %s", identifier))
	}
}

func (t TestRetriever) GetSubordinates(ctx context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	//TODO implement me
	panic("implement me")
}

func (t TestRetriever) GetSubordinateSigners(ctx context.Context) ([]model.SignerConfiguration, error) {
	var response []model.SignerConfiguration
	for _, val := range t.configuration {
		if val.SignerConfiguration != nil {
			response = append(response, *val.SignerConfiguration)
		}
	}
	return response, nil
}

type TestExtendedRetriever struct{}

func (r TestExtendedRetriever) GetExtendedSubordinates(ctx context.Context, from *model.EntityIdentifier, size int, claims []string) (*model.ExtendedListingResponse, error) {
	identifiers := []string{
		"https://a-some-fourth-federation.com/some-path",
		"https://b-some-other-federation.com/some-path",
		"https://c-some-federation.com/some-path",
		"https://d-some-third-federation.com/some-path",
		"https://e-some-fifth-federation.com/some-path",
	}

	if from != nil {
		if !slices.Contains(identifiers, string(*from)) {
			return nil, fmt.Errorf("unknown entity identifier: %s", *from)
		}
		identifiers = identifiers[slices.Index(identifiers, string(*from)):]
	}

	response := model.ExtendedListingResponse{}

	for _, identifier := range identifiers {
		response.ImmediateSubordinateEntities = append(response.ImmediateSubordinateEntities, map[string]any{
			"id": identifier,
		})
	}

	if len(response.ImmediateSubordinateEntities) > size {
		nextIdentifier, _ := model.ValidateEntityIdentifier(response.ImmediateSubordinateEntities[size]["id"].(string))
		response.NextEntityID = nextIdentifier
		response.ImmediateSubordinateEntities = response.ImmediateSubordinateEntities[:size]
	}

	return &response, nil
}

type TestSubordinateStatusRetriever struct{}

func (t TestSubordinateStatusRetriever) GetSubordinateStatus(ctx context.Context, sub model.EntityIdentifier) (*model.SubordinateStatusResponse, error) {
	identifiers := map[string]model.SubordinateStatusResponse{
		"https://federation.com/no-events": {Events: make([]model.SubordinateStatusEvent, 0)},
		"https://federation.com/one-event": {Events: []model.SubordinateStatusEvent{{
			Iat:   time.Now().Add(-24 * time.Hour).UTC().Unix(),
			Event: "registration",
		}}},
		"https://federation.com/lifecycle": {Events: []model.SubordinateStatusEvent{
			{
				Iat:   time.Now().Add(-24 * time.Hour).UTC().Unix(),
				Event: "registration",
			},
			{
				Iat:   time.Now().Add(-12 * time.Hour).UTC().Unix(),
				Event: "metadata_update",
			},
			{
				Iat:              time.Now().Add(-6 * time.Hour).UTC().Unix(),
				Event:            "suspension",
				EventDescription: model.Pointer("suspicious activity detected"),
			},
			{
				Iat:   time.Now().Add(-1 * time.Hour).UTC().Unix(),
				Event: "revocation",
			},
		}},
	}

	if response, ok := identifiers[string(sub)]; ok {
		return &response, nil
	}
	return nil, model.NewNotFoundError(fmt.Sprintf("unknown entity identifier: %s", sub))
}

func TestServer_HandleWellKnown(t *testing.T) {
	subjectIdentifier, err := model.ValidateEntityIdentifier("https://some-federation.com/some-path")
	if err != nil {
		t.Fatalf("expected no error creating subject entity identifier, got %q", err.Error())
	}

	authorityHintIdentifier1, err := model.ValidateEntityIdentifier("https://some-authority-one.com/some-path")
	if err != nil {
		t.Fatalf("expected no error creating authority hint entity identifier one, got %q", err.Error())
	}
	authorityHintIdentifier2, err := model.ValidateEntityIdentifier("https://some-authority-two.com/some-path")
	if err != nil {
		t.Fatalf("expected no error creating authority hint entity identifier two, got %q", err.Error())
	}

	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating signer, got %q", err.Error())
	}
	signerPublicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("expected no error creating public JWK, got %q", err.Error())
	}

	tests := map[string]struct {
		entityIdentifier         model.EntityIdentifier
		authorityHintIdentifiers []model.EntityIdentifier
		entityConfiguration      model.EntityStatement
		keyID                    string
		signer                   crypto.Signer
		validate                 func(t *testing.T, expectedIdentifier model.EntityIdentifier, response *http.Response, err error)
	}{
		"happy path - minimal entity statement provided": {
			entityIdentifier:         *subjectIdentifier,
			authorityHintIdentifiers: []model.EntityIdentifier{*authorityHintIdentifier1, *authorityHintIdentifier2},
			entityConfiguration: model.EntityStatement{
				Metadata: &model.Metadata{
					FederationMetadata: &model.FederationMetadata{},
					OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
						"issuer": "https://some-issuer.com/some-path",
						"redirect_uris": []string{
							"https://some-issuer.com/some-path/callback",
						},
						"client_registration_types": []string{
							"automatic",
						},
					},
					OpenIDConnectOpenIDProviderMetadata: &model.OpenIDConnectOpenIDProviderMetadata{},
				},
			},
			keyID:  (*signerPublicJWK)["kid"].(string),
			signer: signer,
			validate: func(t *testing.T, expectedIdentifier model.EntityIdentifier, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("expected status code 200, got %d", response.StatusCode)
				}
				if response.Header.Get("Content-Type") != "application/entity-statement+jwt" {
					t.Fatalf("expected content type 'application/entity-statement+jwt', got %q", response.Header.Get("Content-Type"))
				}

				defer response.Body.Close() //nolint:errcheck
				responseBytes, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				t.Log(string(responseBytes))

				tokenParts := strings.Split(string(responseBytes), ".")
				if len(tokenParts) != 3 {
					t.Fatalf("expected JWT to have 3 parts, got %d parts", len(tokenParts))
				}

				decodedBody, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
				if err != nil {
					t.Fatalf("failed to decode JWT body: %v", err)
				}
				t.Log(string(decodedBody))

				expectedBody := `{
					"authority_hints": [
						"https://some-authority-one.com/some-path",
						"https://some-authority-two.com/some-path"
					],
					"iss": "https://some-federation.com/some-path",
					"metadata": {
						"federation_entity": {},
						"openid_provider": {},
						"openid_relying_party": {
							"client_registration_types": [
								"automatic"
							],
							"issuer": "https://some-issuer.com/some-path",
							"redirect_uris": [
								"https://some-issuer.com/some-path/callback"
							]
						}
					},
					"sub": "https://some-federation.com/some-path"
				}`

				var actualBody map[string]any
				if err := json.Unmarshal(decodedBody, &actualBody); err != nil {
					t.Fatalf("failed to unmarshal JWT body: %v", err)
				}

				var expectedBodyMap map[string]any
				if err := json.Unmarshal([]byte(expectedBody), &expectedBodyMap); err != nil {
					t.Fatalf("failed to unmarshal expected body: %v", err)
				}

				for key, expectedValue := range expectedBodyMap {
					actualValue, exists := actualBody[key]
					if !exists {
						t.Fatalf("key %q is missing in actual body", key)
					}
					if !reflect.DeepEqual(expectedValue, actualValue) {
						t.Fatalf("value for key %q does not match. Expected: %v, Actual: %v", key, expectedValue, actualValue)
					}
				}
				if err != nil {
					t.Fatalf("expected no error validating entity identifier, got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server := NewServer(model.ServerConfiguration{
				SignerConfiguration: model.SignerConfiguration{
					Signer:    signer,
					KeyID:     (*signerPublicJWK)["kid"].(string),
					Algorithm: "ES256",
				},
				EntityIdentifier:    tt.entityIdentifier,
				AuthorityHints:      tt.authorityHintIdentifiers,
				EntityConfiguration: tt.entityConfiguration,
			})

			m := http.NewServeMux()
			server.Configure(m)
			s := httptest.NewServer(m)
			testClient := s.Client()

			req, err := http.NewRequest("GET", s.URL+"/.well-known/openid-federation", nil)
			if err != nil {
				t.Fatalf("expected no error creating request, got %q", err.Error())
			}

			resp, err := testClient.Do(req)

			tt.validate(t, tt.entityIdentifier, resp, err)
		})
	}
}

func TestServer_List(t *testing.T) {
	tests := map[string]struct {
		configuration func() *model.IntermediateConfiguration
		validate      func(t *testing.T, response *http.Response, err error)
	}{
		"we can list entities": {
			configuration: func() *model.IntermediateConfiguration {
				testConfiguration := &model.IntermediateConfiguration{}
				testConfiguration.AddSubordinate("https://some-federation.com/some-path", &model.SubordinateConfiguration{})
				testConfiguration.AddSubordinate("https://some-other-federation.com/some-path", &model.SubordinateConfiguration{})
				testConfiguration.AddSubordinate("https://some-third-federation.com/some-path", &model.SubordinateConfiguration{})
				testConfiguration.AddSubordinate("https://some-fourth-federation.com/some-path", &model.SubordinateConfiguration{})
				testConfiguration.AddSubordinate("https://some-fifth-federation.com/some-path", &model.SubordinateConfiguration{})

				return testConfiguration
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("expected status code 200, got %d", response.StatusCode)
				}
				defer response.Body.Close() //nolint:errcheck
				responseBytes, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				var responseList []string
				if err := json.Unmarshal(responseBytes, &responseList); err != nil {
					t.Fatalf("failed to unmarshal response body: %v", err)
				}
				if len(responseList) != 5 {
					t.Fatalf("expected 5 entities in response, got %d", len(responseList))
				}
				if !slices.Contains(responseList, "https://some-federation.com/some-path") {
					t.Errorf("expected response to contain 'https://some-federation.com/some-path', got %q", responseList)
				}
				if !slices.Contains(responseList, "https://some-other-federation.com/some-path") {
					t.Errorf("expected response to contain 'https://some-other-federation.com/some-path', got %q", responseList)
				}
				if !slices.Contains(responseList, "https://some-third-federation.com/some-path") {
					t.Errorf("expected response to contain 'https://some-third-federation.com/some-path', got %q", responseList)
				}
				if !slices.Contains(responseList, "https://some-fourth-federation.com/some-path") {
					t.Errorf("expected response to contain 'https://some-fourth-federation.com/some-path', got %q", responseList)
				}
				if !slices.Contains(responseList, "https://some-fifth-federation.com/some-path") {
					t.Errorf("expected response to contain 'https://some-fifth-federation.com/some-path', got %q", responseList)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server := NewServer(model.ServerConfiguration{
				IntermediateConfiguration: tt.configuration(),
			})
			m := http.NewServeMux()
			server.Configure(m)
			s := httptest.NewServer(m)
			testClient := s.Client()

			req, err := http.NewRequest("GET", s.URL+"/list", nil)
			if err != nil {
				t.Fatalf("expected no error creating request, got %q", err.Error())
			}

			resp, err := testClient.Do(req)

			tt.validate(t, resp, err)
		})
	}
}

func TestServer_ExtendedList(t *testing.T) {
	tests := map[string]struct {
		extraQueryParameters map[string]string
		validate             func(t *testing.T, response *http.Response, err error)
	}{
		"we can list entities": {
			extraQueryParameters: nil,
			validate: func(t *testing.T, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				defer response.Body.Close() //nolint:errcheck
				responseBytes, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("expected status code 200, got %d (response: %s)", response.StatusCode, responseBytes)
				}
				if string(responseBytes) != `{"immediate_subordinate_entities":[{"id":"https://a-some-fourth-federation.com/some-path"},{"id":"https://b-some-other-federation.com/some-path"},{"id":"https://c-some-federation.com/some-path"},{"id":"https://d-some-third-federation.com/some-path"},{"id":"https://e-some-fifth-federation.com/some-path"}]}` {
					t.Errorf("unexpected response', got %q", responseBytes)
				}
			},
		},
		"we can list entities with a limit": {
			extraQueryParameters: map[string]string{"limit": "2"},
			validate: func(t *testing.T, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				defer response.Body.Close() //nolint:errcheck
				responseBytes, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("expected status code 200, got %d (response: %s)", response.StatusCode, responseBytes)
				}
				if string(responseBytes) != `{"immediate_subordinate_entities":[{"id":"https://a-some-fourth-federation.com/some-path"},{"id":"https://b-some-other-federation.com/some-path"}],"next_entity_id":"https://c-some-federation.com/some-path"}` {
					t.Errorf("unexpected response', got %q", responseBytes)
				}
			},
		},
		"we can list entities with pagination with a defined cursor": {
			extraQueryParameters: map[string]string{"from_entity_id": url.QueryEscape("https://c-some-federation.com/some-path")},
			validate: func(t *testing.T, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				defer response.Body.Close() //nolint:errcheck
				responseBytes, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("expected status code 200, got %d (response: %s)", response.StatusCode, responseBytes)
				}
				if string(responseBytes) != `{"immediate_subordinate_entities":[{"id":"https://c-some-federation.com/some-path"},{"id":"https://d-some-third-federation.com/some-path"},{"id":"https://e-some-fifth-federation.com/some-path"}]}` {
					t.Errorf("unexpected response', got %q", responseBytes)
				}
			},
		},
		"we can list entities with pagination with a defined cursor and a limit": {
			extraQueryParameters: map[string]string{"limit": "2", "from_entity_id": url.QueryEscape("https://c-some-federation.com/some-path")},
			validate: func(t *testing.T, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				defer response.Body.Close() //nolint:errcheck
				responseBytes, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("expected status code 200, got %d (response: %s)", response.StatusCode, responseBytes)
				}
				if string(responseBytes) != `{"immediate_subordinate_entities":[{"id":"https://c-some-federation.com/some-path"},{"id":"https://d-some-third-federation.com/some-path"}],"next_entity_id":"https://e-some-fifth-federation.com/some-path"}` {
					t.Errorf("unexpected response', got %q", responseBytes)
				}
			},
		},
		"we can list entities with a subordinate_statement claim": {
			extraQueryParameters: map[string]string{"claims": "subordinate_statement"},
			validate: func(t *testing.T, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				defer response.Body.Close() //nolint:errcheck
				responseBytes, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("expected status code 200, got %d (response: %s)", response.StatusCode, responseBytes)
				}
				if strings.Count(string(responseBytes), "subordinate_statement") != 1 {
					t.Errorf("expected subordinate_statement to contain subordinate_statement once - found %d", strings.Count(string(responseBytes), "subordinate_statement"))
				}
			},
		},
	}

	for name, tt := range tests {
		identifier, err := model.ValidateEntityIdentifier("https://a-some-fourth-federation.com/some-path")
		if err != nil {
			t.Fatalf("expected no error, got %q", err.Error())
		}
		signer, err := jws.GetSigner(josemodel.ES256, nil)
		if err != nil {
			t.Fatalf("expected no error creating signer, got %q", err.Error())
		}
		signerPublicJWK, err := jwk.PublicJwk(signer.Public())
		if err != nil {
			t.Fatalf("expected no error creating public JWK, got %q", err.Error())
		}
		leafSigner, err := jws.GetSigner(josemodel.ES256, nil)
		if err != nil {
			t.Fatalf("expected no error creating leaf signer, got %q", err.Error())
		}
		leafSignerPublicJWK, err := jwk.PublicJwk(leafSigner.Public())
		if err != nil {
			t.Fatalf("expected no error creating leaf public JWK, got %q", err.Error())
		}
		(*leafSignerPublicJWK)["alg"] = "ES256"
		t.Run(name, func(t *testing.T) {
			testIntermediateConfiguration := &model.IntermediateConfiguration{
				SubordinateCacheTime: 5 * time.Minute,
			}
			testIntermediateConfiguration.AddSubordinate(*identifier, &model.SubordinateConfiguration{
				JWKs: josemodel.Jwks{Keys: []map[string]any{*leafSignerPublicJWK}},
				Policies: model.MetadataPolicy{
					OpenIDRelyingPartyMetadata: map[string]model.PolicyOperators{
						"scope": {
							Metadata: []model.MetadataPolicyOperator{
								model_test.NewValue(t, "openid accounts"),
							},
						},
					},
				},
			})
			server := NewServer(model.ServerConfiguration{
				EntityIdentifier:          "https://some-trust-source.com",
				IntermediateConfiguration: testIntermediateConfiguration,
				Extensions: model.Extensions{
					ExtendedListing: model.ExtendedListingConfiguration{
						Enabled:           true,
						SizeLimit:         50,
						MetadataRetriever: TestExtendedRetriever{},
					},
				},
				SignerConfiguration: model.SignerConfiguration{
					Signer:    signer,
					KeyID:     (*signerPublicJWK)["kid"].(string),
					Algorithm: "ES256",
				},
			})
			m := http.NewServeMux()
			server.Configure(m)
			s := httptest.NewServer(m)
			testClient := s.Client()

			queryString := "?"
			for key, value := range tt.extraQueryParameters {
				queryString = fmt.Sprintf("%s&%s=%s", queryString, key, value)
			}

			req, err := http.NewRequest("GET", s.URL+"/extended-list"+queryString, nil)
			if err != nil {
				t.Fatalf("expected no error creating request, got %q", err.Error())
			}

			resp, err := testClient.Do(req)

			tt.validate(t, resp, err)
		})
	}
}

func TestServer_SubordinateStatus(t *testing.T) {
	tests := map[string]struct {
		sub      string
		validate func(t *testing.T, response *http.Response, err error)
	}{
		"we can retrieve the status of an entity with one event": {
			sub: "https://federation.com/one-event",
			validate: func(t *testing.T, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				defer response.Body.Close() //nolint:errcheck
				responseBytes, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("expected status code 200, got %d (response: %s)", response.StatusCode, responseBytes)
				}
				if response.Header.Get("Content-Type") != "application/entity-events-statement+jwt" {
					t.Errorf("expected content type application/entity-events-statement+jwt, got %s", response.Header.Get("Content-Type"))
				}
				validateSubordinateStatusJWT(t, responseBytes, "https://federation.com/one-event", []map[string]any{
					{"event": "registration"},
				})
			},
		},
		"we can retrieve the status of an entity with no events": {
			sub: "https://federation.com/no-events",
			validate: func(t *testing.T, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				defer response.Body.Close() //nolint:errcheck
				responseBytes, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("expected status code 200, got %d (response: %s)", response.StatusCode, responseBytes)
				}
				if response.Header.Get("Content-Type") != "application/entity-events-statement+jwt" {
					t.Errorf("expected content type application/entity-events-statement+jwt, got %s", response.Header.Get("Content-Type"))
				}
				validateSubordinateStatusJWT(t, responseBytes, "https://federation.com/no-events", []map[string]any{})
			},
		},
		"we can retrieve the status of an entity with a full lifecycle": {
			sub: "https://federation.com/lifecycle",
			validate: func(t *testing.T, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				defer response.Body.Close() //nolint:errcheck
				responseBytes, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("expected status code 200, got %d (response: %s)", response.StatusCode, responseBytes)
				}
				if response.Header.Get("Content-Type") != "application/entity-events-statement+jwt" {
					t.Errorf("expected content type application/entity-events-statement+jwt, got %s", response.Header.Get("Content-Type"))
				}
				validateSubordinateStatusJWT(t, responseBytes, "https://federation.com/lifecycle", []map[string]any{
					{"event": "registration"},
					{"event": "metadata_update"},
					{"event": "suspension", "event_description": "suspicious activity detected"},
					{"event": "revocation"},
				})
			},
		},
		"we get an error when requesting status for an unknown entity": {
			sub: "https://federation.com/unknown",
			validate: func(t *testing.T, response *http.Response, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if response == nil {
					t.Fatal("expected result to be non-nil")
				}
				validateErrorResponse(t, response, err, http.StatusNotFound, "not_found", "unknown entity identifier: https://federation.com/unknown")
			},
		},
	}

	for name, tt := range tests {
		signer, err := jws.GetSigner(josemodel.ES256, nil)
		if err != nil {
			t.Fatalf("expected no error creating signer, got %q", err.Error())
		}
		signerPublicJWK, err := jwk.PublicJwk(signer.Public())
		if err != nil {
			t.Fatalf("expected no error creating public JWK, got %q", err.Error())
		}
		t.Run(name, func(t *testing.T) {
			server := NewServer(model.ServerConfiguration{
				EntityIdentifier:          "https://some-trust-source.com",
				IntermediateConfiguration: &model.IntermediateConfiguration{},
				Extensions: model.Extensions{
					SubordinateStatus: model.SubordinateStatusConfiguration{
						Enabled:           true,
						ResponseLifetime:  model.Pointer(1 * time.Hour),
						MetadataRetriever: TestSubordinateStatusRetriever{},
					},
				},
				SignerConfiguration: model.SignerConfiguration{
					Signer:    signer,
					KeyID:     (*signerPublicJWK)["kid"].(string),
					Algorithm: "ES256",
				},
				Configuration: model.Configuration{
					Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
				},
			})
			m := http.NewServeMux()
			server.Configure(m)
			s := httptest.NewServer(m)
			testClient := s.Client()

			req, err := http.NewRequest("GET", fmt.Sprintf("%s/subordinate-status?sub=%s", s.URL, tt.sub), nil)
			if err != nil {
				t.Fatalf("expected no error creating request, got %q", err.Error())
			}

			resp, err := testClient.Do(req)

			tt.validate(t, resp, err)
		})
	}
}

func validateSubordinateStatusJWT(t *testing.T, responseBytes []byte, expectedSub string, expectedEvents []map[string]any) {
	parts := strings.Split(string(responseBytes), ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("expected no error decoding header, got %q", err.Error())
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("expected no error decoding body, got %q", err.Error())
	}

	var parsedHead, parsedBody map[string]any
	if err = json.Unmarshal(head, &parsedHead); err != nil {
		t.Fatalf("expected no error parsing head, got %q", err.Error())
	}

	if err = json.Unmarshal(body, &parsedBody); err != nil {
		t.Fatalf("expected no error parsing body, got %q", err.Error())
	}

	if diff := cmp.Diff(map[string]any{
		"alg": "ES256",
		"typ": "entity-events-statement+jwt",
	}, parsedHead, cmpopts.IgnoreMapEntries(func(k string, v any) bool {
		return k == "kid"
	})); diff != "" {
		t.Errorf("mismatch (-expected +got):\n%s", diff)
	}

	if diff := cmp.Diff(map[string]any{
		"federation_registration_events": expectedEvents,
		"iss":                            "https://some-trust-source.com",
		"sub":                            expectedSub,
	}, parsedBody, cmpopts.IgnoreMapEntries(func(k string, v any) bool {
		return k == "iat" || k == "exp" || k == "federation_registration_events"
	})); diff != "" {
		t.Errorf("mismatch (-expected +got):\n%s", diff)
	}

	if _, ok := parsedBody["exp"]; !ok {
		t.Errorf("expected exp field, got none")
	}
	if _, ok := parsedBody["iat"]; !ok {
		t.Errorf("expected iat field, got none")
	}

	events := parsedBody["federation_registration_events"].([]any)
	if len(events) != len(expectedEvents) {
		t.Fatalf("expected %d events, got %d", len(expectedEvents), len(events))
	}

	for i, event := range events {
		eventMap := event.(map[string]any)
		if _, ok := eventMap["iat"]; !ok {
			t.Errorf("expected event to have an iat field, got none")
		}
		if eventMap["event"] != expectedEvents[i]["event"] {
			t.Errorf("expected event type %q, got %q", expectedEvents[i]["event"], eventMap["event"])
		}
		if desc, ok := expectedEvents[i]["event_description"]; ok {
			if eventMap["event_description"] != desc {
				t.Errorf("expected event description %q, got %q", desc, eventMap["event_description"])
			}
		}
	}
}

func validateFetchResponse(t *testing.T, response *http.Response, err error, expectedStatusCode int) {
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	if response == nil {
		t.Fatal("expected response to be non-nil")
	}
	if response.StatusCode != expectedStatusCode {
		t.Errorf("expected status code %d, got %d", expectedStatusCode, response.StatusCode)
	}
	defer response.Body.Close() //nolint:errcheck
	if response.Header["Content-Type"][0] != "application/resolve-response+jwt" {
		t.Errorf("expected response type 'application/resolve-response+jwt', got %s", response.Header["Content-Type"][0])
	}

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("expected no error reading response body, got %q", err.Error())
	}

	parts := strings.Split(string(bodyBytes), ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("expected no error decoding header, got %q", err.Error())
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("expected no error decoding body, got %q", err.Error())
	}

	t.Log(string(body))

	var parsedHead, parsedBody map[string]any
	if err = json.Unmarshal(head, &parsedHead); err != nil {
		t.Fatalf("expected no error parsing head, got %q", err.Error())
	}

	if err = json.Unmarshal(body, &parsedBody); err != nil {
		t.Fatalf("expected no error parsing body, got %q", err.Error())
	}

	if v, ok := parsedHead["typ"]; !ok {
		t.Fatalf("expected header 'typ' property to be present, got %v", v)
	} else if v != "resolve-response+jwt" {
		t.Fatalf("expected header 'typ' property to be 'resolve-response+jwt', got %s", v)
	} //todo: we should check kid and alg here too...

	//todo: we could use the client code to validate the trust chain...
}

func validateErrorResponse(t *testing.T, response *http.Response, err error, expectedStatusCode int, expectedErrorType string, expectedErrorDescription string) {
	if err != nil {
		t.Fatalf("expected no error making request, got %q", err.Error())
	}
	if response == nil {
		t.Fatal("expected response to be non-nil")
	}
	defer response.Body.Close() //nolint:errcheck

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if response.StatusCode != expectedStatusCode {
		t.Fatalf("expected status code %d, got %d (response: %s)", expectedStatusCode, response.StatusCode, responseBytes)
	}

	var errorResponse struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	err = json.Unmarshal(responseBytes, &errorResponse)
	if err != nil {
		t.Fatalf("failed to unmarshal error response: %v (response: %s)", err, responseBytes)
	}

	if errorResponse.Error != expectedErrorType {
		t.Fatalf("expected error type %q, got %q", expectedErrorType, errorResponse.Error)
	}

	if errorResponse.ErrorDescription != expectedErrorDescription {
		t.Fatalf("expected error description %q, got %q", expectedErrorDescription, errorResponse.ErrorDescription)
	}
}
