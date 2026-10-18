package entity_configuration

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func Retrieve(ctx context.Context, cfg model.Configuration, entityIdentifier model.EntityIdentifier, cache *resolvecache.Cache) (*string, *model.EntityStatement, error) {
	if signed, statement, ok := cache.Load(entityIdentifier); ok {
		cfg.LogInfo(ctx, "serving entity configuration from resolve cache", slog.String("subject", string(entityIdentifier)))
		return signed, statement, nil
	}

	signed, statement, err := fetch(ctx, cfg, entityIdentifier)
	if err != nil {
		return nil, nil, err
	}
	cache.Store(entityIdentifier, signed, statement)
	return signed, statement, nil
}

func fetch(ctx context.Context, cfg model.Configuration, entityIdentifier model.EntityIdentifier) (*string, *model.EntityStatement, error) {
	if cfg.HttpClient == nil {
		return nil, nil, fmt.Errorf("no http client present")
	}

	cfg.LogInfo(ctx, "retrieving entity configuration", slog.String("subject", string(entityIdentifier)))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s.well-known/openid-federation", strings.TrimSuffix(string(entityIdentifier), "/")+"/"), nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Accept", "application/entity-statement+jwt")

	response, err := cfg.HttpClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("non-200 response from %q's entity configuration: %s", entityIdentifier, response.Status)
	}
	cfg.LogInfo(ctx, "entity configuration retrieved", slog.String("subject", string(entityIdentifier)))

	if !strings.Contains(response.Header.Get("Content-Type"), "application/entity-statement+jwt") { //todo: check on this - not sure if it has to be an exact match or not...
		return nil, nil, fmt.Errorf("invalid Content-Type response from %q's entity configuration: %s", entityIdentifier, response.Header.Get("Content-Type"))
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %q's entity configuration response body: %s", entityIdentifier, err.Error())
	}

	entityConfiguration, err := Validate(ctx, cfg, entityIdentifier, string(responseBytes))
	if err != nil {
		return nil, nil, err
	}

	return josemodel.Pointer(string(responseBytes)), entityConfiguration, nil
}

func Validate(ctx context.Context, cfg model.Configuration, entityIdentifier model.EntityIdentifier, entityConfigurationJwt string) (*model.EntityStatement, error) {
	parts := strings.Split(entityConfigurationJwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT structure")
	}

	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %s", err.Error())
	}
	var headMap map[string]any
	err = json.Unmarshal(head, &headMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT header: %s", err.Error())
	}

	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT body: %s", err.Error())
	}
	var bodyMap map[string]any
	err = json.Unmarshal(body, &bodyMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT body: %s", err.Error())
	}

	kid, ok := headMap["kid"]
	if !ok {
		return nil, fmt.Errorf("missing required header claim 'kid'")
	}
	sKid, ok := kid.(string)
	if !ok {
		return nil, fmt.Errorf("malformed header claim 'kid'")
	}

	jwks, ok := bodyMap["jwks"]
	if !ok {
		return nil, fmt.Errorf("missing required body claim 'jwks'")
	}

	var jwksMap map[string]any
	jwksMap, ok = jwks.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'jwks' is malformed")
	}

	jwksBytes, err := json.Marshal(jwksMap)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize 'jwks' claim: %s", err.Error())
	}

	var parsedJwks josemodel.Jwks
	err = json.Unmarshal(jwksBytes, &parsedJwks)
	if err != nil {
		return nil, fmt.Errorf("invalid 'jwks' claim format: %s", err.Error())
	}

	if _, _, err = jws.VerifyCompactSerialization(entityConfigurationJwt, func() ([]crypto.PublicKey, error) {
		keys := map[string]map[string]any{}
		for _, key := range parsedJwks.Keys {
			if keyKid, ok := key["kid"]; !ok {
				return nil, fmt.Errorf("one or more entries in the included 'jwks' is missing the mandatory 'kid' claim")
			} else {
				sKeyID, ok := keyKid.(string)
				if !ok {
					return nil, fmt.Errorf("one or more entries in the included 'jwks' has a malformed 'kid' claim")
				} else {
					if keys[sKeyID] != nil {
						return nil, fmt.Errorf("all entries in the included 'jwks' must have unique 'kid' values")
					}
					keys[sKeyID] = key
				}
			}
		}
		selectedKey := keys[sKid]
		if selectedKey == nil {
			return nil, fmt.Errorf("no matching key found in the included 'jwks'")
		}
		pubKey, err := jwk.PublicFromJwk(selectedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse selected public key from 'jwks' as a valid jwk: %s", err.Error())
		}
		return []crypto.PublicKey{pubKey}, nil
	}, nil); err != nil {
		return nil, fmt.Errorf("failed to verify JWT signature: %s", err.Error())
	}
	//todo: validate optional claims

	var entityConfiguration model.EntityStatement
	err = json.Unmarshal(body, &entityConfiguration)
	if err != nil {
		return nil, fmt.Errorf("malformed 'metadata' claim: %w", err)
	}

	if entityConfiguration.Iss != entityConfiguration.Sub {
		return nil, fmt.Errorf("'iss' and 'sub' claims do not match")
	}

	if entityConfiguration.Iss != entityIdentifier {
		return nil, fmt.Errorf("'iss' claim does not match the original entity identifier")
	}

	if entityConfiguration.Sub != entityIdentifier {
		return nil, fmt.Errorf("'sub' claim does not match the original entity identifier")
	}

	if entityConfiguration.Metadata != nil {
		if err = entityConfiguration.Metadata.Verify(cfg.EntityTypes, cfg.DiscardUnrecognisedEntityTypes); err != nil {
			return nil, model.NewInvalidMetadataError(err.Error())
		}
	}

	return &entityConfiguration, nil
}

// New takes a given configuration struct and produces a signed Entity Configuration
func New(ctx context.Context, cfg model.ServerConfiguration) (*string, error) {
	entityConfiguration := cfg.EntityConfiguration
	entityConfiguration.Sub = cfg.EntityIdentifier
	entityConfiguration.Iss = cfg.EntityIdentifier
	entityConfiguration.AuthorityHints = cfg.AuthorityHints
	entityConfiguration.TrustMarks = cfg.TrustMarks
	entityConfiguration.Iat = time.Now().UTC().Unix()
	entityConfiguration.Exp = time.Now().Add(cfg.EntityConfigurationLifetime).UTC().Unix()
	entityConfiguration.MetadataPolicy = nil
	entityConfiguration.Constraints = nil
	entityConfiguration.MetadataPolicyCrit = nil
	entityConfiguration.SourceEndpoint = nil

	metadata := model.Metadata{}
	if cfg.EntityConfiguration.Metadata != nil {
		metadata = *cfg.EntityConfiguration.Metadata
	}

	federationMetadata := model.FederationMetadata{}
	if metadata.FederationMetadata != nil {
		for claim, value := range *metadata.FederationMetadata {
			federationMetadata[claim] = value
		}
	}

	trimmed := strings.TrimSuffix(string(cfg.EntityIdentifier), "/")

	if cfg.IntermediateConfiguration != nil {
		federationMetadata["federation_fetch_endpoint"] = trimmed + "/fetch"
		federationMetadata["federation_list_endpoint"] = trimmed + "/list"
		federationMetadata["federation_resolve_endpoint"] = trimmed + "/resolve"
		if cfg.Extensions.ExtendedListing.Enabled {
			federationMetadata["federation_extended_list_endpoint"] = trimmed + "/extended-list"
		}
		if cfg.Extensions.SubordinateStatus.Enabled {
			federationMetadata["federation_subordinate_events_endpoint"] = trimmed + "/subordinate-status"
		}
	}

	if cfg.TrustMarkRetriever != nil {
		federationMetadata["federation_trust_mark_status_endpoint"] = trimmed + "/trust-mark-status"
		federationMetadata["federation_trust_mark_list_endpoint"] = trimmed + "/trust-mark-list"
		federationMetadata["federation_trust_mark_endpoint"] = trimmed + "/trust-mark"
	}

	if len(federationMetadata) > 0 {
		metadata.FederationMetadata = &federationMetadata
	}
	if cfg.EntityConfiguration.Metadata != nil || len(federationMetadata) > 0 {
		entityConfiguration.Metadata = &metadata
	}

	if cfg.SignerConfiguration.KeyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	publicJWK, err := jwk.PublicJwk(cfg.SignerConfiguration.Signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to convert provided signer public key to a jwk: %s", err.Error())
	}
	(*publicJWK)["kid"] = cfg.SignerConfiguration.KeyID
	(*publicJWK)["alg"] = cfg.SignerConfiguration.Algorithm

	jwks := josemodel.Jwks{}
	jwks.Opts.EnforceUniqueKIDs = true
	seen := map[string]struct{}{}
	for _, key := range cfg.EntityConfiguration.JWKs.Keys {
		kid, ok := key["kid"]
		if !ok {
			return nil, fmt.Errorf("all provided jwk values in entity cfg must have a `kid` claim - missing from one or more")
		}
		sKid, ok := kid.(string)
		if !ok {
			return nil, fmt.Errorf("one or more provided jwk values have a malformed `kid` claim")
		}
		if _, duplicate := seen[sKid]; duplicate {
			return nil, fmt.Errorf("all provided jwk values in entity cfg must have unique `kid` claims - %q appears more than once", sKid)
		}
		seen[sKid] = struct{}{}
		jwks.Keys = append(jwks.Keys, key)
	}

	if existing, _ := jwks.RetrieveByKeyID(cfg.SignerConfiguration.KeyID); existing != nil {
		if !publicParametersMatch(existing, *publicJWK) {
			return nil, fmt.Errorf("a configured jwk uses the signing key ID %q but holds different key material, so the issued statement could not be verified", cfg.SignerConfiguration.KeyID)
		}
	} else {
		jwks.Keys = append(jwks.Keys, *publicJWK)
	}

	if cfg.IntermediateConfiguration != nil {
		subordinateSignerConfigurations, err := cfg.GetSubordinateJWKs(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get subordinate signer configurations: %s", err.Error())
		}
		for _, signerConfiguration := range subordinateSignerConfigurations {
			apkJWK, err := jwk.PublicJwk(signerConfiguration.Signer.Public())
			if err != nil {
				return nil, fmt.Errorf("failed to convert override signer public key to a jwk: %s", err.Error())
			}
			(*apkJWK)["kid"] = signerConfiguration.KeyID
			(*apkJWK)["alg"] = signerConfiguration.Algorithm

			if existing, _ := jwks.RetrieveByKeyID(signerConfiguration.KeyID); existing != nil {
				if !publicParametersMatch(existing, *apkJWK) {
					return nil, fmt.Errorf("subordinate signer key ID %q is already published with different key material, so statements signed with it could not be verified", signerConfiguration.KeyID)
				}
				continue
			}
			if err := jwks.Add(*apkJWK); err != nil {
				return nil, fmt.Errorf("failed to publish subordinate signer key %q: %s", signerConfiguration.KeyID, err.Error())
			}
		}
	}

	entityConfiguration.JWKs = jwks

	if cfg.TrustMarkIssuerRetriever != nil {
		trustMarkIssuerMap, err := cfg.TrustMarkIssuerRetriever.ListTrustMarkIssuers(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list trust mark issuers: %s", err.Error())
		}
		trustMarkIssuers := make(map[string][]model.EntityIdentifier, len(trustMarkIssuerMap))
		for trustMarkType, issuers := range trustMarkIssuerMap {
			if issuers == nil {
				issuers = []model.EntityIdentifier{}
			}
			trustMarkIssuers[trustMarkType] = issuers
		}
		entityConfiguration.TrustMarkIssuers = trustMarkIssuers
	}

	entityConfigurationBytes, err := json.Marshal(entityConfiguration)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize entity cfg: %s", err.Error())
	}

	var entityConfigurationMap map[string]any
	err = json.Unmarshal(entityConfigurationBytes, &entityConfigurationMap)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize entity cfg: %s", err.Error())
	}

	return jwt.New(cfg.SignerConfiguration.Signer, map[string]any{
		"kid": cfg.SignerConfiguration.KeyID,
		"typ": "entity-statement+jwt",
		"alg": cfg.SignerConfiguration.Algorithm,
	}, entityConfigurationMap, jwt.Opts{Algorithm: josemodel.GetAlgorithm(cfg.SignerConfiguration.Algorithm)})
}

func publicParametersMatch(a, b map[string]any) bool {
	for _, claim := range []string{"kty", "crv", "x", "y", "n", "e"} {
		if a[claim] != b[claim] {
			return false
		}
	}
	return true
}
