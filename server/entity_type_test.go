package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/model_test"
)

const verifierProviderEntityTypeIdentifier = "openid_verifier_provider"

func decodeEntityStatementClaims(t *testing.T, response *http.Response) map[string]any {
	t.Helper()
	if response == nil {
		t.Fatal("expected response to be non-nil")
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", response.StatusCode)
	}

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("expected no error reading response body, got %q", err.Error())
	}
	parts := strings.Split(string(bodyBytes), ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("expected no error decoding body, got %q", err.Error())
	}
	var claims map[string]any
	if err = json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("expected no error parsing body, got %q", err.Error())
	}
	return claims
}

type verifierProviderEntityType struct{}

func (verifierProviderEntityType) Identifier() string {
	return verifierProviderEntityTypeIdentifier
}

func (verifierProviderEntityType) VerifyMetadata(metadata map[string]any) error {
	if len(metadata) == 0 {
		return nil
	}
	if _, ok := metadata["vp_formats_supported"]; !ok {
		return errors.New("missing required 'vp_formats_supported' claim")
	}
	return nil
}

func (verifierProviderEntityType) VerifyMetadataPolicy(policy map[string]model.PolicyOperators) error {
	if _, ok := policy["client_id_prefixes_supported"]; ok {
		return errors.New("'client_id_prefixes_supported' may not be set by policy")
	}
	return nil
}

func (verifierProviderEntityType) VerifyResolvedMetadata(metadata map[string]any) error {
	if len(metadata) == 0 {
		return nil
	}
	if _, ok := metadata["vp_formats_supported"]; !ok {
		return errors.New("policy removed the required 'vp_formats_supported' claim")
	}
	return nil
}

func TestServer_Resolve_ExtensionEntityTypes(t *testing.T) {
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

	verifierSigner, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating verifier signer, got %q", err.Error())
	}
	verifierPublicJWK, err := jwk.PublicJwk(verifierSigner.Public())
	if err != nil {
		t.Fatalf("expected no error creating verifier public JWK, got %q", err.Error())
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
	t.Cleanup(func() { tas.Close() })

	verifierEntityServer := NewServer(model.ServerConfiguration{
		SignerConfiguration: model.SignerConfiguration{
			Algorithm: "ES256",
			Signer:    verifierSigner,
			KeyID:     (*verifierPublicJWK)["kid"].(string),
		},
		EntityConfiguration: model.EntityStatement{
			Metadata: &model.Metadata{
				OpenIDWalletProviderMetadata: &model.OpenIDWalletProviderMetadata{
					"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}},
				},
				Extensions: map[string]map[string]any{
					verifierProviderEntityTypeIdentifier: {
						"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}},
						"organization_name":    "Original Verifier",
					},
				},
			},
		},
		EntityConfigurationLifetime: 10 * time.Minute,
	})

	vm := http.NewServeMux()
	verifierEntityServer.Configure(vm)
	vs := httptest.NewTLSServer(vm)
	verifierEntityServer.SetEntityIdentifier(model.EntityIdentifier(vs.URL))
	t.Cleanup(func() { vs.Close() })

	tests := map[string]struct {
		entityTypes         []string
		registry            model.EntityTypeRegistry
		discardUnrecognised bool
		trustAnchorPolicy   model.MetadataPolicy
		validate            func(t *testing.T, response *http.Response, err error)
	}{
		"an unregistered extension entity type survives resolution": {
			validate: func(t *testing.T, response *http.Response, err error) {
				metadata := decodeResolveMetadata(t, response, err)
				if _, ok := metadata[verifierProviderEntityTypeIdentifier]; !ok {
					t.Errorf("expected %s to survive resolution, got keys %v", verifierProviderEntityTypeIdentifier, metadataKeys(metadata))
				}
			},
		},
		"a registered extension entity type survives resolution": {
			registry: model.EntityTypeRegistry{
				verifierProviderEntityTypeIdentifier: verifierProviderEntityType{},
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				metadata := decodeResolveMetadata(t, response, err)
				if _, ok := metadata[verifierProviderEntityTypeIdentifier]; !ok {
					t.Errorf("expected %s to survive resolution, got keys %v", verifierProviderEntityTypeIdentifier, metadataKeys(metadata))
				}
			},
		},
		"filtering to the extension entity type retains only it": {
			entityTypes: []string{verifierProviderEntityTypeIdentifier},
			validate: func(t *testing.T, response *http.Response, err error) {
				metadata := decodeResolveMetadata(t, response, err)
				if _, ok := metadata[verifierProviderEntityTypeIdentifier]; !ok {
					t.Errorf("expected %s to be retained, got keys %v", verifierProviderEntityTypeIdentifier, metadataKeys(metadata))
				}
				if _, ok := metadata["openid_wallet_provider"]; ok {
					t.Errorf("expected openid_wallet_provider to be filtered out, got keys %v", metadataKeys(metadata))
				}
			},
		},
		"filtering to a different entity type strips the extension": {
			entityTypes: []string{"openid_wallet_provider"},
			validate: func(t *testing.T, response *http.Response, err error) {
				metadata := decodeResolveMetadata(t, response, err)
				if _, ok := metadata[verifierProviderEntityTypeIdentifier]; ok {
					t.Errorf("expected %s to be filtered out, got keys %v", verifierProviderEntityTypeIdentifier, metadataKeys(metadata))
				}
				if _, ok := metadata["openid_wallet_provider"]; !ok {
					t.Errorf("expected openid_wallet_provider to be retained, got keys %v", metadataKeys(metadata))
				}
			},
		},
		"unrecognised entity types are discarded when configured": {
			discardUnrecognised: true,
			validate: func(t *testing.T, response *http.Response, err error) {
				metadata := decodeResolveMetadata(t, response, err)
				if _, ok := metadata[verifierProviderEntityTypeIdentifier]; ok {
					t.Errorf("expected %s to be discarded, got keys %v", verifierProviderEntityTypeIdentifier, metadataKeys(metadata))
				}
				if _, ok := metadata["openid_wallet_provider"]; !ok {
					t.Errorf("expected openid_wallet_provider to survive discarding, got keys %v", metadataKeys(metadata))
				}
			},
		},
		"a registered extension entity type is not discarded": {
			discardUnrecognised: true,
			registry: model.EntityTypeRegistry{
				verifierProviderEntityTypeIdentifier: verifierProviderEntityType{},
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				metadata := decodeResolveMetadata(t, response, err)
				if _, ok := metadata[verifierProviderEntityTypeIdentifier]; !ok {
					t.Errorf("expected registered %s to survive discarding, got keys %v", verifierProviderEntityTypeIdentifier, metadataKeys(metadata))
				}
			},
		},
		"metadata policy applies to extension entity types": {
			trustAnchorPolicy: model.MetadataPolicy{
				Extensions: map[string]map[string]model.PolicyOperators{
					verifierProviderEntityTypeIdentifier: {
						"organization_name": {Metadata: []model.MetadataPolicyOperator{model_test.NewValue(t, "Policed Verifier")}},
					},
				},
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				metadata := decodeResolveMetadata(t, response, err)
				extension, ok := metadata[verifierProviderEntityTypeIdentifier].(map[string]any)
				if !ok {
					t.Fatalf("expected %s metadata, got keys %v", verifierProviderEntityTypeIdentifier, metadataKeys(metadata))
				}
				if extension["organization_name"] != "Policed Verifier" {
					t.Errorf("expected policy to be applied to extension metadata, got %v", extension["organization_name"])
				}
			},
		},
		"metadata policy validation rejects a forbidden operator": {
			registry: model.EntityTypeRegistry{
				verifierProviderEntityTypeIdentifier: verifierProviderEntityType{},
			},
			trustAnchorPolicy: model.MetadataPolicy{
				Extensions: map[string]map[string]model.PolicyOperators{
					verifierProviderEntityTypeIdentifier: {
						"client_id_prefixes_supported": {Metadata: []model.MetadataPolicyOperator{model_test.NewValue(t, []any{"origin:"})}},
					},
				},
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_metadata", "failed to retrieve subordinate statement: invalid openid_verifier_provider metadata policy: 'client_id_prefixes_supported' may not be set by policy")
			},
		},
		"an unregistered extension entity type skips policy validation": {
			trustAnchorPolicy: model.MetadataPolicy{
				Extensions: map[string]map[string]model.PolicyOperators{
					verifierProviderEntityTypeIdentifier: {
						"client_id_prefixes_supported": {Metadata: []model.MetadataPolicyOperator{model_test.NewValue(t, []any{"origin:"})}},
					},
				},
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				metadata := decodeResolveMetadata(t, response, err)
				if _, ok := metadata[verifierProviderEntityTypeIdentifier]; !ok {
					t.Errorf("expected %s to survive resolution, got keys %v", verifierProviderEntityTypeIdentifier, metadataKeys(metadata))
				}
			},
		},
		"resolved metadata validation rejects policy that removes a required claim": {
			registry: model.EntityTypeRegistry{
				verifierProviderEntityTypeIdentifier: verifierProviderEntityType{},
			},
			trustAnchorPolicy: model.MetadataPolicy{
				Extensions: map[string]map[string]model.PolicyOperators{
					verifierProviderEntityTypeIdentifier: {
						"vp_formats_supported": {Metadata: []model.MetadataPolicyOperator{model_test.NewValue(t, nil)}},
					},
				},
			},
			validate: func(t *testing.T, response *http.Response, err error) {
				validateErrorResponse(t, response, err, http.StatusBadRequest, "invalid_metadata", "invalid resolved openid_verifier_provider metadata: policy removed the required 'vp_formats_supported' claim")
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			trustAnchorServer.cfg.IntermediateConfiguration.FlushCache()
			intermediateConfigurations := &model.IntermediateConfiguration{
				SubordinateStatementLifetime: 1 * time.Minute,
			}
			intermediateConfigurations.AddSubordinate(model.EntityIdentifier(vs.URL), &model.SubordinateConfiguration{})

			tr := TestRetriever{}
			tr.Configure(map[string]*model.SubordinateConfiguration{
				vs.URL: {
					JWKs: josemodel.Jwks{Keys: []map[string]any{*verifierPublicJWK}},
				},
			})

			server := NewServer(model.ServerConfiguration{
				AuthorityHints:      []model.EntityIdentifier{model.EntityIdentifier(tas.URL)},
				SignerConfiguration: model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: (*signerPublicJWK)["kid"].(string)},

				IntermediateConfiguration:   intermediateConfigurations,
				EntityConfiguration:         model.EntityStatement{},
				EntityConfigurationLifetime: 10 * time.Minute,
				MetadataRetriever:           tr,
				Configuration: model.Configuration{
					Logger:                         slog.New(slog.NewJSONHandler(os.Stdout, nil)),
					EntityTypes:                    tt.registry,
					DiscardUnrecognisedEntityTypes: tt.discardUnrecognised,
				},
			})

			m := http.NewServeMux()
			server.Configure(m)
			s := httptest.NewTLSServer(m)
			t.Cleanup(func() { s.Close() })
			testClient := s.Client()
			server.SetEntityIdentifier(model.EntityIdentifier(s.URL))
			server.SetHttpClient(testClient)

			trustAnchorServer.cfg.IntermediateConfiguration.AddSubordinate(model.EntityIdentifier(s.URL), &model.SubordinateConfiguration{
				CachedAt: time.Now().UTC().Unix(),
				JWKs:     josemodel.Jwks{Keys: []map[string]any{*signerPublicJWK}},
				Policies: tt.trustAnchorPolicy,
			})

			verifierEntityServer.AddAuthorityHint(model.EntityIdentifier(s.URL))

			params := url.Values{}
			params.Add("sub", vs.URL)
			params.Add("trust_anchor", tas.URL)
			for _, entityType := range tt.entityTypes {
				params.Add("entity_type", entityType)
			}

			req, err := http.NewRequest("GET", fmt.Sprintf("%s/resolve?%s", s.URL, params.Encode()), nil)
			if err != nil {
				t.Fatalf("expected no error creating request, got %q", err.Error())
			}

			resp, err := testClient.Do(req)
			tt.validate(t, resp, err)
		})
	}
}

func TestServer_List_PassesExtensionEntityTypesToRetriever(t *testing.T) {
	retriever := &testListingRetriever{
		result: []model.EntityIdentifier{"https://verifier.example.com"},
	}
	s := startListServer(t, model.ServerConfiguration{
		IntermediateConfiguration: &model.IntermediateConfiguration{},
		MetadataRetriever:         retriever,
	})

	query := url.Values{"entity_type": {verifierProviderEntityTypeIdentifier}}
	resp, err := s.Client().Get(s.URL + "/list?" + query.Encode())
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if retriever.received == nil {
		t.Fatal("expected the listing retriever to receive a filter")
	}
	if len(retriever.received.EntityTypes) != 1 || retriever.received.EntityTypes[0] != verifierProviderEntityTypeIdentifier {
		t.Errorf("expected the extension entity type to reach the retriever unmodified, got %v", retriever.received.EntityTypes)
	}
}

func TestServer_HandleWellKnown_PublishesExtensionEntityTypes(t *testing.T) {
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating signer, got %q", err.Error())
	}
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("expected no error creating public JWK, got %q", err.Error())
	}

	server := NewServer(model.ServerConfiguration{
		SignerConfiguration: model.SignerConfiguration{
			Algorithm: "ES256",
			Signer:    signer,
			KeyID:     (*publicJWK)["kid"].(string),
		},
		EntityConfiguration: model.EntityStatement{
			Metadata: &model.Metadata{
				Extensions: map[string]map[string]any{
					verifierProviderEntityTypeIdentifier: {
						"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}},
					},
				},
			},
		},
		EntityConfigurationLifetime: 10 * time.Minute,
	})

	m := http.NewServeMux()
	server.Configure(m)
	s := httptest.NewTLSServer(m)
	t.Cleanup(func() { s.Close() })
	server.SetEntityIdentifier(model.EntityIdentifier(s.URL))

	resp, err := s.Client().Get(s.URL + "/.well-known/openid-federation")
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}

	claims := decodeEntityStatementClaims(t, resp)
	metadata, ok := claims["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata claim, got %v", claims)
	}
	if _, ok = metadata[verifierProviderEntityTypeIdentifier]; !ok {
		t.Errorf("expected %s to be published, got keys %v", verifierProviderEntityTypeIdentifier, metadataKeys(metadata))
	}
}

func TestServer_Fetch_PublishesExtensionEntityTypePolicy(t *testing.T) {
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating signer, got %q", err.Error())
	}
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("expected no error creating public JWK, got %q", err.Error())
	}

	subordinateSigner, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating subordinate signer, got %q", err.Error())
	}
	subordinatePublicJWK, err := jwk.PublicJwk(subordinateSigner.Public())
	if err != nil {
		t.Fatalf("expected no error creating subordinate public JWK, got %q", err.Error())
	}

	intermediateConfiguration := &model.IntermediateConfiguration{
		SubordinateStatementLifetime: 1 * time.Minute,
		SubordinateCacheTime:         5 * time.Minute,
	}
	intermediateConfiguration.AddSubordinate("https://verifier.example.com", &model.SubordinateConfiguration{
		JWKs: josemodel.Jwks{Keys: []map[string]any{*subordinatePublicJWK}},
		Policies: model.MetadataPolicy{
			Extensions: map[string]map[string]model.PolicyOperators{
				verifierProviderEntityTypeIdentifier: {
					"organization_name": {Metadata: []model.MetadataPolicyOperator{model_test.NewValue(t, "Policed Verifier")}},
				},
			},
		},
	})

	server := NewServer(model.ServerConfiguration{
		EntityIdentifier: "https://intermediate.example.com",
		SignerConfiguration: model.SignerConfiguration{
			Algorithm: "ES256",
			Signer:    signer,
			KeyID:     (*publicJWK)["kid"].(string),
		},
		EntityConfiguration:         model.EntityStatement{},
		EntityConfigurationLifetime: 10 * time.Minute,
		IntermediateConfiguration:   intermediateConfiguration,
	})

	m := http.NewServeMux()
	server.Configure(m)
	s := httptest.NewTLSServer(m)
	t.Cleanup(func() { s.Close() })

	resp, err := s.Client().Get(s.URL + "/fetch?sub=" + url.QueryEscape("https://verifier.example.com"))
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}

	claims := decodeEntityStatementClaims(t, resp)
	policy, ok := claims["metadata_policy"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata_policy claim, got %v", claims)
	}
	extension, ok := policy[verifierProviderEntityTypeIdentifier].(map[string]any)
	if !ok {
		t.Fatalf("expected %s policy to be published, got keys %v", verifierProviderEntityTypeIdentifier, metadataKeys(policy))
	}
	organizationName, ok := extension["organization_name"].(map[string]any)
	if !ok {
		t.Fatalf("expected organization_name policy, got %v", extension)
	}
	if organizationName["value"] != "Policed Verifier" {
		t.Errorf("expected the value operator to be published, got %v", organizationName)
	}
}
