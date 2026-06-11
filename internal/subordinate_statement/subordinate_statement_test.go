package subordinate_statement

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/model_test"
	"github.com/MichaelFraser99/go-openid-federation/server_test"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestRetrieve(t *testing.T) {
	testServer := server_test.TestServer(t)
	testHttpClient := testServer.Client()
	testServerURL := testServer.URL
	cfg := model.Configuration{
		HttpClient: testHttpClient,
	}

	tests := map[string]struct {
		httpClient              *http.Client
		issuingEntity           func(t *testing.T) model.EntityStatement
		subjectEntityIdentifier model.EntityIdentifier
		validate                func(t *testing.T, issuer model.EntityStatement, result *model.EntityStatement, signedResult *string, err error)
	}{
		"we can retrieve and validate an entity identifier": {
			httpClient: testHttpClient,
			issuingEntity: func(t *testing.T) model.EntityStatement {
				req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/int1/.well-known/openid-federation", testServerURL), nil)
				if err != nil {
					t.Fatalf("error constructing request to intermediate entity configuration from test server: %s", err.Error())
				}
				resp, err := testHttpClient.Do(req)
				if err != nil {
					t.Fatalf("error retrieving intermediate entity configuration from test server: %s", err.Error())
				}
				respBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("error reading intermediate entity configuration response bytes: %s", err.Error())
				}

				parts := strings.Split(string(respBytes), ".")

				decodedBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
				if err != nil {
					t.Fatalf("error decoding response jwt: %s", err.Error())
				}

				var entityStatement model.EntityStatement
				if err = json.Unmarshal(decodedBytes, &entityStatement); err != nil {
					t.Fatalf("error unmarshalling entity configuration response to an entity statement: %s (response: %s)", err.Error(), respBytes)
				}
				return entityStatement
			},
			subjectEntityIdentifier: model.EntityIdentifier(fmt.Sprintf("%s/leaf", testServerURL)),
			validate: func(t *testing.T, issuer model.EntityStatement, result *model.EntityStatement, signedResult *string, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if signedResult == nil {
					t.Fatal("expected signed result to be non-nil")
				}
				if result.Sub == "" {
					t.Error("expected result.Sub to be non-nil")
				}
				if result.Iss == "" {
					t.Error("expected result.Iss to be non-nil")
				}
				if result.Exp == 0 {
					t.Error("expected result.Exp to be non-zero")
				}
				if result.Iat == 0 {
					t.Error("expected result.Exp to be non-zero")
				}
				if len(result.AuthorityHints) != 0 {
					t.Error("expected result.AuthorityHints to be nil")
				}
				if result.Metadata != nil {
					t.Fatal("expected result.Metadata to be nil")
				}
				if result.MetadataPolicy == nil {
					t.Fatal("expected result.MetadataPolicy to be non-nil")
				}
				parsedSignedResult, err := Validate(issuer, *signedResult)
				if err != nil {
					t.Fatalf("expected no error parsing signed response, got %q", err.Error())
				}
				if diff := cmp.Diff(*result, *parsedSignedResult, cmpopts.IgnoreUnexported(model.Add{}, model.Default{}, model.Essential{}, model.OneOf{}, model.SupersetOf{}, model.SubsetOf{}, model.Value{}), cmpopts.SortSlices(func(x, y any) bool {
					if sx, ok := x.(string); ok {
						if sy, ok := y.(string); ok {
							return sx < sy
						}
					}
					return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
				})); diff != "" {
					t.Errorf("mismatch (-expected +got):\n%s", diff)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			issuerConfiguration := tt.issuingEntity(t)
			signedResult, result, err := Retrieve(t.Context(), cfg, issuerConfiguration, tt.subjectEntityIdentifier)
			tt.validate(t, issuerConfiguration, result, signedResult, err)
		})
	}
}

func TestNew(t *testing.T) {
	issuerIdentifier, err := model.ValidateEntityIdentifier("https://some-issuing-federation.com/some-path")
	if err != nil {
		t.Fatalf("expected no error creating subject entity identifier, got %q", err.Error())
	}

	subjectIdentifier, err := model.ValidateEntityIdentifier("https://some-federation.com/some-path")
	if err != nil {
		t.Fatalf("expected no error creating subject entity identifier, got %q", err.Error())
	}

	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating signer, got %q", err.Error())
	}
	signerPublicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("expected no error creating public JWK, got %q", err.Error())
	}
	(*signerPublicJWK)["alg"] = "ES256"

	leafSigner, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating leaf signer, got %q", err.Error())
	}
	leafSignerPublicJWK, err := jwk.PublicJwk(leafSigner.Public())
	if err != nil {
		t.Fatalf("expected no error creating leaf public JWK, got %q", err.Error())
	}
	(*leafSignerPublicJWK)["alg"] = "ES256"
	leafSignerPublicJWKBytes, err := json.Marshal(leafSignerPublicJWK)
	if err != nil {
		t.Fatalf("expected no error creating leaf public jwk bytes, got %q", err.Error())
	}

	tests := map[string]struct {
		serverConfiguration func() model.ServerConfiguration
		validate            func(t *testing.T, issuer model.EntityStatement, result *string, err error)
	}{
		"happy path - minimal entity statement provided": {
			serverConfiguration: func() model.ServerConfiguration {
				testConfiguration := model.ServerConfiguration{
					EntityIdentifier: *issuerIdentifier,
					IntermediateConfiguration: &model.IntermediateConfiguration{
						SubordinateStatementLifetime: 1 * time.Hour,
						SubordinateCacheTime:         5 * time.Minute,
					},
					SignerConfiguration: model.SignerConfiguration{
						KeyID:     (*signerPublicJWK)["kid"].(string),
						Algorithm: "ES256",
						Signer:    signer,
					},
					EntityConfiguration: model.EntityStatement{
						Iss: *issuerIdentifier,
						Sub: *issuerIdentifier,
						JWKs: josemodel.Jwks{
							Keys: []map[string]any{
								*signerPublicJWK,
							},
						},
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
						},
					},
				}
				testConfiguration.IntermediateConfiguration.AddSubordinate(*subjectIdentifier, &model.SubordinateConfiguration{
					SignerConfiguration: &model.SignerConfiguration{
						Signer:    leafSigner,
						KeyID:     (*leafSignerPublicJWK)["kid"].(string),
						Algorithm: "ES256",
					},
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
				return testConfiguration
			},
			validate: func(t *testing.T, issuer model.EntityStatement, result *string, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				_, err = Validate(issuer, *result)
				if err != nil {
					t.Fatalf("expected no error validating entity identifier, got %q", err.Error())
				}
				// Decode and validate the body of the JWT
				tokenParts := strings.Split(*result, ".")
				if len(tokenParts) != 3 {
					t.Fatalf("expected JWT to have 3 parts, got %d parts", len(tokenParts))
				}

				decodedBody, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
				if err != nil {
					t.Fatalf("failed to decode JWT body: %v", err)
				}

				expectedBody := fmt.Sprintf(`{
					"jwks": {
						"keys": [%s]
					},
					"iss": "https://some-issuing-federation.com/some-path",
					"metadata_policy": {
						"openid_relying_party": {
							"scope": {
								"value": "openid accounts"
							}
						}
					},
					"sub": "https://some-federation.com/some-path"
				}`, string(leafSignerPublicJWKBytes))

				var actualBody map[string]any
				if err := json.Unmarshal(decodedBody, &actualBody); err != nil {
					t.Fatalf("failed to unmarshal JWT body: %v", err)
				}

				var expectedBodyMap map[string]any
				if err := json.Unmarshal([]byte(expectedBody), &expectedBodyMap); err != nil {
					t.Fatalf("failed to unmarshal expected body: %v", err)
				}

				if diff := cmp.Diff(expectedBodyMap, actualBody,
					cmpopts.SortSlices(func(x, y any) bool { //sort slices before comparison
						if sx, ok := x.(string); ok {
							if sy, ok := y.(string); ok {
								return sx < sy
							}
						}
						return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
					}),
					cmpopts.IgnoreMapEntries(func(k string, v any) bool { //ignore time fields
						return slices.Contains([]string{"exp", "iat"}, k)
					}),
				); diff != "" {
					t.Errorf("mismatch (-expected +got):\n%s", diff)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			testConfiguration := tt.serverConfiguration()
			result, err := New(t.Context(), *subjectIdentifier, func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
				subordinate, cErr := testConfiguration.GetSubordinate(t.Context(), *subjectIdentifier)
				if cErr != nil {
					return nil, nil, cErr
				}
				return subordinate, &testConfiguration.SignerConfiguration, nil
			}, testConfiguration)
			tt.validate(t, testConfiguration.EntityConfiguration, result, err)
		})
	}
}
