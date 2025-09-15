package entity_configuration

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

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

	tests := map[string]struct {
		httpClient       *http.Client
		entityIdentifier model.EntityIdentifier
		validate         func(t *testing.T, result *model.EntityStatement, signedResult *string, err error)
	}{
		"we can retrieve and validate an entity identifier": {
			httpClient:       testHttpClient,
			entityIdentifier: model.EntityIdentifier(fmt.Sprintf("%s/leaf", testServerURL)),
			validate: func(t *testing.T, result *model.EntityStatement, signedResult *string, err error) {
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
				if len(result.AuthorityHints) == 0 {
					t.Error("expected result.AuthorityHints to be non-empty")
				}
				if result.Metadata == nil {
					t.Fatal("expected result.Metadata to be non-nil")
				}
				if result.Metadata.FederationMetadata != nil {
					t.Error("expected result.Metadata.FederationMetadata to be nil")
				}
				if result.Metadata.OpenIDRelyingPartyMetadata != nil {
					t.Error("expected result.Metadata.OpenIDRelyingPartyMetadata to be nil")
				}
				if result.Metadata.OpenIDConnectOpenIDProviderMetadata == nil {
					t.Fatal("expected result.Metadata.OpenIDConnectOpenIDProviderMetadata to be non-nil")
				}
				parsedSignedResult, err := Validate(result.Sub, *signedResult)
				if err != nil {
					t.Fatalf("expected no error parsing signed response, got %q", err.Error())
				}
				if diff := cmp.Diff(*result, *parsedSignedResult, cmpopts.SortSlices(func(x, y any) bool {
					if sx, ok := x.(string); ok {
						if sy, ok := y.(string); ok {
							return sx < sy
						}
					}
					return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
				})); diff != "" {
					t.Errorf("mismatch (-expected +got):\n%s", diff)
				}
				//todo: validate the full returned object
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			signedResult, result, err := Retrieve(tt.httpClient, tt.entityIdentifier)
			tt.validate(t, result, signedResult, err)
		})
	}
}

func TestNew(t *testing.T) {
	subjectIdentifier, err := model.ValidateEntityIdentifier("https://some-federation.com/some-path")
	if err != nil {
		t.Fatalf("expected no error creating subject entity identifier, got %q", err.Error())
	}
	leafIdentifier1, err := model.ValidateEntityIdentifier("https://some-federation.com/leaf1")
	if err != nil {
		t.Fatalf("expected no error creating leaf entity identifier 1, got %q", err.Error())
	}
	leafIdentifier2, err := model.ValidateEntityIdentifier("https://some-federation.com/leaf2")
	if err != nil {
		t.Fatalf("expected no error creating leaf entity identifier 2, got %q", err.Error())
	}
	leafIdentifier3, err := model.ValidateEntityIdentifier("https://some-federation.com/leaf3")
	if err != nil {
		t.Fatalf("expected no error creating leaf entity identifier 3, got %q", err.Error())
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
	(*signerPublicJWK)["alg"] = "ES256"
	signerPublicJwkBytes, err := json.Marshal(signerPublicJWK)
	if err != nil {
		t.Fatalf("expected no error creating public jwk bytes, got %q", err.Error())
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
	leafSignerPublicJWKBytes, err := json.Marshal(leafSignerPublicJWK)
	if err != nil {
		t.Fatalf("expected no error creating leaf public jwk bytes, got %q", err.Error())
	}

	tests := map[string]struct {
		serverConfiguration func() model.ServerConfiguration
		validate            func(t *testing.T, expectedIdentifier model.EntityIdentifier, result *string, err error)
	}{
		"happy path - minimal entity statement provided": {
			serverConfiguration: func() model.ServerConfiguration {
				return model.ServerConfiguration{
					EntityIdentifier: *subjectIdentifier,
					AuthorityHints:   []model.EntityIdentifier{*authorityHintIdentifier1, *authorityHintIdentifier2},
					SignerConfiguration: model.SignerConfiguration{
						KeyID:     (*signerPublicJWK)["kid"].(string),
						Algorithm: "ES256",
						Signer:    signer,
					},
					EntityConfiguration: model.EntityStatement{
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
			},
			validate: func(t *testing.T, expectedIdentifier model.EntityIdentifier, result *string, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				_, err = Validate(expectedIdentifier, *result)
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
					"authority_hints": [
						"https://some-authority-one.com/some-path",
						"https://some-authority-two.com/some-path"
					],
					"jwks": {
						"keys": [%s]
					},
					"iss": "https://some-federation.com/some-path",
					"metadata": {
						"federation_entity": {},
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
				}`, string(signerPublicJwkBytes))

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
		"happy path - entity with subordinates": {
			//todo: confirm behaviour in issues for openid federation regarding empty json - technically this should
			// probably return empty json ({}) for openid_provider metadata as a subordinate is configured with
			// policies however I feel this is not enforceable at scale an should be dropped from the spec - confirm
			// in the working group
			serverConfiguration: func() model.ServerConfiguration {
				testConfiguration := model.ServerConfiguration{
					EntityIdentifier: *subjectIdentifier,
					AuthorityHints:   []model.EntityIdentifier{},
					SignerConfiguration: model.SignerConfiguration{
						KeyID:     (*signerPublicJWK)["kid"].(string),
						Algorithm: "ES256",
						Signer:    signer,
					},
					IntermediateConfiguration: &model.IntermediateConfiguration{},
					EntityConfiguration: model.EntityStatement{
						Metadata: &model.Metadata{
							FederationMetadata: &model.FederationMetadata{},
							OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
								"issuer": "https://some-issuer.com/some-path",
								"redirect_uris": []any{
									"https://some-issuer.com/some-path/callback",
								},
								"client_registration_types": []any{
									"automatic",
								},
							},
						},
					},
				}
				testConfiguration.IntermediateConfiguration.AddSubordinate(*leafIdentifier1, &model.SubordinateConfiguration{
					Policies: model.MetadataPolicy{
						OpenIDRelyingPartyMetadata: map[string]model.PolicyOperators{
							"key1": {Metadata: []model.MetadataPolicyOperator{
								model_test.NewAdd(t, []any{"foo", "bar"}),
								model_test.NewSubsetOf(t, []any{"foo", "bar", "baz", "bin"}),
								model_test.NewSupersetOf(t, []any{"foo", "bar"}),
							}},
						},
					},
					SignerConfiguration: &model.SignerConfiguration{
						Signer:    leafSigner,
						KeyID:     (*leafSignerPublicJWK)["kid"].(string),
						Algorithm: "ES256",
					},
				})
				testConfiguration.IntermediateConfiguration.AddSubordinate(*leafIdentifier2, &model.SubordinateConfiguration{
					Policies: model.MetadataPolicy{
						OpenIDRelyingPartyMetadata: map[string]model.PolicyOperators{
							"key1": {Metadata: []model.MetadataPolicyOperator{
								model_test.NewValue(t, []any{"foo", "bar"}),
							}},
						},
					},
					SignerConfiguration: &model.SignerConfiguration{
						Signer:    leafSigner,
						KeyID:     (*leafSignerPublicJWK)["kid"].(string),
						Algorithm: "ES256",
					},
				})
				testConfiguration.IntermediateConfiguration.AddSubordinate(*leafIdentifier3, &model.SubordinateConfiguration{
					Policies: model.MetadataPolicy{
						OpenIDConnectOpenIDProviderMetadata: map[string]model.PolicyOperators{
							"key1": {Metadata: []model.MetadataPolicyOperator{
								model_test.NewValue(t, []any{"foo", "bar"}),
							}},
						},
					},
				})
				return testConfiguration
			},
			validate: func(t *testing.T, expectedIdentifier model.EntityIdentifier, result *string, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				_, err = Validate(expectedIdentifier, *result)
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
					"iss": "https://some-federation.com/some-path",
					"jwks": {
						"keys": [%s, %s]
					},
					"metadata": {
						"federation_entity": {
							"federation_fetch_endpoint": "https://some-federation.com/some-path/fetch",
							"federation_list_endpoint":  "https://some-federation.com/some-path/list",
							"federation_resolve_endpoint":  "https://some-federation.com/some-path/resolve"
						},
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
				}`, string(signerPublicJwkBytes), string(leafSignerPublicJWKBytes))

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
			result, err := New(tt.serverConfiguration())
			tt.validate(t, tt.serverConfiguration().EntityIdentifier, result, err)
		})
	}
}
