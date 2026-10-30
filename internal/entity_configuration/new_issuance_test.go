package entity_configuration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type issuanceTrustMarkRetriever struct{}

func (issuanceTrustMarkRetriever) GetTrustMarkStatus(context.Context, string) (*string, error) {
	return nil, nil
}

func (issuanceTrustMarkRetriever) IssueTrustMark(context.Context, string, model.EntityIdentifier) (*string, error) {
	return nil, nil
}

func (issuanceTrustMarkRetriever) ListTrustMarks(context.Context, string, *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	return nil, nil
}

type issuanceTrustMarkIssuerRetriever struct {
	issuers map[string][]model.EntityIdentifier
}

func (r issuanceTrustMarkIssuerRetriever) ListTrustMarkIssuers(context.Context) (map[string][]model.EntityIdentifier, error) {
	return r.issuers, nil
}

func issuanceSigner(t *testing.T) (model.SignerConfiguration, map[string]any) {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to create public jwk: %v", err)
	}
	(*publicJWK)["alg"] = "ES256"
	return model.SignerConfiguration{
		KeyID:     (*publicJWK)["kid"].(string),
		Algorithm: "ES256",
		Signer:    signer,
	}, *publicJWK
}

func signerPublicJwk(t *testing.T, signerConfiguration model.SignerConfiguration) map[string]any {
	t.Helper()
	publicJWK, err := jwk.PublicJwk(signerConfiguration.Signer.Public())
	if err != nil {
		t.Fatalf("failed to create public jwk: %v", err)
	}
	(*publicJWK)["kid"] = signerConfiguration.KeyID
	(*publicJWK)["alg"] = signerConfiguration.Algorithm
	return *publicJWK
}

func issuedClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS with three parts, got %d", len(parts))
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode issued claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatalf("failed to unmarshal issued claims: %v", err)
	}
	return claims
}

func issuedFederationMetadata(t *testing.T, claims map[string]any) map[string]any {
	t.Helper()
	metadata, ok := claims["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected a metadata claim, got %v", claims["metadata"])
	}
	federationMetadata, ok := metadata["federation_entity"].(map[string]any)
	if !ok {
		t.Fatalf("expected federation_entity metadata, got %v", metadata["federation_entity"])
	}
	return federationMetadata
}

func TestNew_IssuesConformingEntityConfigurations(t *testing.T) {
	const identifier = model.EntityIdentifier("https://ta.example.com")

	tests := []struct {
		name      string
		configure func(t *testing.T, cfg *model.ServerConfiguration)
		expectErr bool
		validate  func(t *testing.T, claims map[string]any)
	}{
		{
			name: "intermediate without federation_entity keeps its other entity types",
			configure: func(_ *testing.T, cfg *model.ServerConfiguration) {
				cfg.IntermediateConfiguration = &model.IntermediateConfiguration{}
				cfg.EntityConfiguration.Metadata = &model.Metadata{
					OpenIDConnectOpenIDProviderMetadata: &model.OpenIDConnectOpenIDProviderMetadata{
						"issuer":                                string(identifier),
						"authorization_endpoint":                "https://leaf.example.com/authorize",
						"jwks_uri":                              "https://leaf.example.com/jwks",
						"response_types_supported":              []string{"id_token"},
						"subject_types_supported":               []string{"public"},
						"id_token_signing_alg_values_supported": []string{"ES256"},
					},
				}
			},
			validate: func(t *testing.T, claims map[string]any) {
				metadata := claims["metadata"].(map[string]any)
				if _, ok := metadata["openid_provider"]; !ok {
					t.Errorf("expected openid_provider metadata to survive, got %v", metadata)
				}
				if _, ok := metadata["federation_entity"]; !ok {
					t.Errorf("expected federation_entity metadata to be added, got %v", metadata)
				}
			},
		},
		{
			name: "trust mark issuer without federation_entity metadata is issued without panicking",
			configure: func(_ *testing.T, cfg *model.ServerConfiguration) {
				cfg.TrustMarkRetriever = issuanceTrustMarkRetriever{}
				cfg.EntityConfiguration.Metadata = nil
			},
			validate: func(t *testing.T, claims map[string]any) {
				federationMetadata := issuedFederationMetadata(t, claims)
				if _, ok := federationMetadata["federation_trust_mark_endpoint"]; !ok {
					t.Errorf("expected the trust mark endpoint to be advertised, got %v", federationMetadata)
				}
			},
		},
		{
			name: "subordinate events endpoint is advertised when enabled",
			configure: func(_ *testing.T, cfg *model.ServerConfiguration) {
				cfg.IntermediateConfiguration = &model.IntermediateConfiguration{}
				cfg.Extensions.SubordinateStatus.Enabled = true
			},
			validate: func(t *testing.T, claims map[string]any) {
				federationMetadata := issuedFederationMetadata(t, claims)
				want := "https://ta.example.com/subordinate-status"
				if got := federationMetadata["federation_subordinate_events_endpoint"]; got != want {
					t.Errorf("expected federation_subordinate_events_endpoint %q, got %v", want, got)
				}
			},
		},
		{
			name: "subordinate statement only claims are not published",
			configure: func(_ *testing.T, cfg *model.ServerConfiguration) {
				cfg.EntityConfiguration.Constraints = &model.Constraints{MaxPathLength: josemodel.Pointer(1)}
				cfg.EntityConfiguration.SourceEndpoint = josemodel.Pointer("https://ta.example.com/fetch")
			},
			validate: func(t *testing.T, claims map[string]any) {
				for _, claim := range []string{"constraints", "metadata_policy_crit", "source_endpoint", "metadata_policy"} {
					if _, present := claims[claim]; present {
						t.Errorf("expected %q not to be published in an entity configuration, got %v", claim, claims[claim])
					}
				}
			},
		},
		{
			name: "duplicate kid values are rejected",
			configure: func(t *testing.T, cfg *model.ServerConfiguration) {
				_, first := issuanceSigner(t)
				_, second := issuanceSigner(t)
				first["kid"] = "dup"
				second["kid"] = "dup"
				cfg.EntityConfiguration.JWKs.Keys = []map[string]any{first, second}
			},
			expectErr: true,
		},
		{
			name: "configured key reusing the signing kid with other key material is rejected",
			configure: func(t *testing.T, cfg *model.ServerConfiguration) {
				_, other := issuanceSigner(t)
				other["kid"] = cfg.SignerConfiguration.KeyID
				cfg.EntityConfiguration.JWKs.Keys = []map[string]any{other}
			},
			expectErr: true,
		},
		{
			name: "configured signing key declaring another algorithm is rejected",
			configure: func(t *testing.T, cfg *model.ServerConfiguration) {
				signing := signerPublicJwk(t, cfg.SignerConfiguration)
				signing["alg"] = "ES512"
				cfg.EntityConfiguration.JWKs.Keys = []map[string]any{signing}
			},
			expectErr: true,
		},
		{
			name: "configured signing key declaring a non-signing use is rejected",
			configure: func(t *testing.T, cfg *model.ServerConfiguration) {
				signing := signerPublicJwk(t, cfg.SignerConfiguration)
				signing["use"] = "enc"
				cfg.EntityConfiguration.JWKs.Keys = []map[string]any{signing}
			},
			expectErr: true,
		},
		{
			name: "configured signing key whose key_ops exclude verify is rejected",
			configure: func(t *testing.T, cfg *model.ServerConfiguration) {
				signing := signerPublicJwk(t, cfg.SignerConfiguration)
				signing["key_ops"] = []any{"encrypt"}
				cfg.EntityConfiguration.JWKs.Keys = []map[string]any{signing}
			},
			expectErr: true,
		},
		{
			name: "configured signing key whose key_ops name only sign is rejected",
			configure: func(t *testing.T, cfg *model.ServerConfiguration) {
				signing := signerPublicJwk(t, cfg.SignerConfiguration)
				signing["key_ops"] = []any{"sign"}
				cfg.EntityConfiguration.JWKs.Keys = []map[string]any{signing}
			},
			expectErr: true,
		},
		{
			name: "configured signing key whose key_ops include verify is accepted",
			configure: func(t *testing.T, cfg *model.ServerConfiguration) {
				signing := signerPublicJwk(t, cfg.SignerConfiguration)
				signing["key_ops"] = []any{"verify"}
				cfg.EntityConfiguration.JWKs.Keys = []map[string]any{signing}
			},
			validate: func(t *testing.T, claims map[string]any) {
				keys := claims["jwks"].(map[string]any)["keys"].([]any)
				if len(keys) != 1 {
					t.Fatalf("expected the signing key not to be published twice, got %d keys", len(keys))
				}
				if _, ok := keys[0].(map[string]any)["key_ops"]; !ok {
					t.Errorf("expected the configured key, with its key_ops, to be the one published, got %v", keys[0])
				}
			},
		},
		{
			name: "a spare key marked for encryption only is published",
			configure: func(t *testing.T, cfg *model.ServerConfiguration) {
				_, spare := issuanceSigner(t)
				spare["kid"] = "spare"
				spare["key_ops"] = []any{"encrypt"}
				cfg.EntityConfiguration.JWKs.Keys = []map[string]any{spare}
			},
			validate: func(t *testing.T, claims map[string]any) {
				keys := claims["jwks"].(map[string]any)["keys"].([]any)
				if len(keys) != 2 {
					t.Errorf("expected the spare key to be published beside the signing key, got %d keys", len(keys))
				}
			},
		},
		{
			name: "a spare key listing an operation twice is rejected",
			configure: func(t *testing.T, cfg *model.ServerConfiguration) {
				_, spare := issuanceSigner(t)
				spare["kid"] = "spare"
				spare["key_ops"] = []any{"verify", "verify"}
				cfg.EntityConfiguration.JWKs.Keys = []map[string]any{spare}
			},
			expectErr: true,
		},
		{
			name: "a spare key whose key_ops is not an array is rejected",
			configure: func(t *testing.T, cfg *model.ServerConfiguration) {
				_, spare := issuanceSigner(t)
				spare["kid"] = "spare"
				spare["key_ops"] = "verify"
				cfg.EntityConfiguration.JWKs.Keys = []map[string]any{spare}
			},
			expectErr: true,
		},
		{
			name: "configured signing key agreeing on algorithm and use is accepted",
			configure: func(t *testing.T, cfg *model.ServerConfiguration) {
				signing := signerPublicJwk(t, cfg.SignerConfiguration)
				signing["use"] = "sig"
				cfg.EntityConfiguration.JWKs.Keys = []map[string]any{signing}
			},
			validate: func(t *testing.T, claims map[string]any) {
				jwks := claims["jwks"].(map[string]any)
				keys := jwks["keys"].([]any)
				if len(keys) != 1 {
					t.Errorf("expected the signing key not to be published twice, got %d keys", len(keys))
				}
			},
		},
		{
			name: "nil trust mark issuer list is published as an empty array",
			configure: func(_ *testing.T, cfg *model.ServerConfiguration) {
				cfg.TrustMarkIssuerRetriever = issuanceTrustMarkIssuerRetriever{
					issuers: map[string][]model.EntityIdentifier{"https://tm.example.com/open": nil},
				}
			},
			validate: func(t *testing.T, claims map[string]any) {
				issuers, ok := claims["trust_mark_issuers"].(map[string]any)
				if !ok {
					t.Fatalf("expected trust_mark_issuers to be an object, got %v", claims["trust_mark_issuers"])
				}
				entry, ok := issuers["https://tm.example.com/open"].([]any)
				if !ok {
					t.Fatalf("expected an empty array for the open trust mark type, got %v", issuers["https://tm.example.com/open"])
				}
				if len(entry) != 0 {
					t.Errorf("expected an empty array, got %v", entry)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signerConfiguration, _ := issuanceSigner(t)
			cfg := model.ServerConfiguration{
				EntityIdentifier:            identifier,
				SignerConfiguration:         signerConfiguration,
				EntityConfigurationLifetime: time.Hour,
			}
			tc.configure(t, &cfg)

			token, err := New(context.Background(), cfg)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected an error, got a signed entity configuration")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			tc.validate(t, issuedClaims(t, *token))
		})
	}
}

func TestNew_DoesNotMutateTheSuppliedConfiguration(t *testing.T) {
	const identifier = model.EntityIdentifier("https://ta.example.com")

	signerConfiguration, _ := issuanceSigner(t)
	federationMetadata := model.FederationMetadata{"organization_name": "Example"}
	_, spareKey := issuanceSigner(t)
	callerKeys := make([]map[string]any, 1, 8)
	callerKeys[0] = spareKey
	cfg := model.ServerConfiguration{
		EntityIdentifier:            identifier,
		SignerConfiguration:         signerConfiguration,
		EntityConfigurationLifetime: time.Hour,
		IntermediateConfiguration:   &model.IntermediateConfiguration{},
		EntityConfiguration: model.EntityStatement{
			Metadata: &model.Metadata{FederationMetadata: &federationMetadata},
			JWKs:     josemodel.Jwks{Keys: callerKeys},
		},
	}

	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := New(context.Background(), cfg); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent issuance failed: %v", err)
	}

	if len(federationMetadata) != 1 {
		t.Errorf("expected the caller's federation metadata to be untouched, got %v", federationMetadata)
	}
	if _, present := federationMetadata["federation_fetch_endpoint"]; present {
		t.Errorf("expected no endpoints written into the caller's map, got %v", federationMetadata)
	}
	if len(cfg.EntityConfiguration.JWKs.Keys) != 1 {
		t.Errorf("expected the caller's jwks to be untouched, got %d keys", len(cfg.EntityConfiguration.JWKs.Keys))
	}
	if extra := callerKeys[:cap(callerKeys)][1]; extra != nil {
		t.Errorf("expected nothing written into the caller's spare slice capacity, got %v", extra)
	}
}
