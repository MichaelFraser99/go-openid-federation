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
	"slices"
	"strings"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func Retrieve(ctx context.Context, cfg model.Configuration, entityIdentifier model.EntityIdentifier) (*string, *model.EntityStatement, error) {
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
	defer response.Body.Close()

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

	entityConfiguration, err := Validate(ctx, entityIdentifier, string(responseBytes))
	if err != nil {
		return nil, nil, err
	}

	return josemodel.Pointer(string(responseBytes)), entityConfiguration, nil
}

func Validate(ctx context.Context, entityIdentifier model.EntityIdentifier, entityConfigurationJwt string) (*model.EntityStatement, error) {
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
		return nil, fmt.Errorf("malformed 'metadata' claim: %s", err.Error())
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

	return &entityConfiguration, nil
}

// New takes a given configuration struct and produces a signed Entity Configuration
func New(ctx context.Context, cfg model.ServerConfiguration) (*string, error) {
	cfg.EntityConfiguration.Sub = cfg.EntityIdentifier
	cfg.EntityConfiguration.Iss = cfg.EntityIdentifier
	cfg.EntityConfiguration.AuthorityHints = cfg.AuthorityHints
	cfg.EntityConfiguration.TrustMarks = cfg.TrustMarks
	cfg.EntityConfiguration.Iat = time.Now().UTC().Unix()
	cfg.EntityConfiguration.Exp = time.Now().Add(cfg.EntityConfigurationLifetime).UTC().Unix()

	trimmed := strings.TrimSuffix(string(cfg.EntityIdentifier), "/")

	if cfg.IntermediateConfiguration != nil { //if the entity can in theory issue subordinate statements, then we need to include the subordinate cfg
		if cfg.EntityConfiguration.Metadata == nil || cfg.EntityConfiguration.Metadata.FederationMetadata == nil {
			cfg.EntityConfiguration.Metadata = &model.Metadata{FederationMetadata: &model.FederationMetadata{}}
		}
		(*cfg.EntityConfiguration.Metadata.FederationMetadata)["federation_fetch_endpoint"] = trimmed + "/fetch"
		(*cfg.EntityConfiguration.Metadata.FederationMetadata)["federation_list_endpoint"] = trimmed + "/list"
		(*cfg.EntityConfiguration.Metadata.FederationMetadata)["federation_resolve_endpoint"] = trimmed + "/resolve"
		if cfg.Extensions.ExtendedListing.Enabled {
			(*cfg.EntityConfiguration.Metadata.FederationMetadata)["federation_extended_list_endpoint"] = trimmed + "/extended-list"
		}
	}

	if cfg.TrustMarkRetriever != nil {
		(*cfg.EntityConfiguration.Metadata.FederationMetadata)["federation_trust_mark_status_endpoint"] = trimmed + "/trust-mark-status"
		(*cfg.EntityConfiguration.Metadata.FederationMetadata)["federation_trust_mark_list_endpoint"] = trimmed + "/trust-mark-list"
		(*cfg.EntityConfiguration.Metadata.FederationMetadata)["federation_trust_mark_endpoint"] = trimmed + "/trust-mark"
	}

	cfg.EntityConfiguration.MetadataPolicy = nil // not permitted on entity statements

	if cfg.SignerConfiguration.KeyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	publicJWK, err := jwk.PublicJwk(cfg.SignerConfiguration.Signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to convert provided signer public key to a jwk: %s", err.Error())
	}
	(*publicJWK)["kid"] = cfg.SignerConfiguration.KeyID
	(*publicJWK)["alg"] = cfg.SignerConfiguration.Algorithm

	cfg.EntityConfiguration.JWKs.Opts.EnforceUniqueKIDs = true
	if cfg.EntityConfiguration.JWKs.Keys == nil {
		cfg.EntityConfiguration.JWKs.Keys = []map[string]any{
			*publicJWK,
		}
	} else {
		var keyIDs []string
		for _, v := range cfg.EntityConfiguration.JWKs.Keys {
			if kid, ok := v["kid"]; !ok {
				return nil, fmt.Errorf("all provided jwk values in entity cfg must have a `kid` claim - missing from one or more")
			} else if sKid, ok := kid.(string); !ok {
				return nil, fmt.Errorf("one or more provided jwk values have a malformed `kid` claim")
			} else {
				keyIDs = append(keyIDs, sKid)
			}
		}
		if !slices.Contains(keyIDs, cfg.SignerConfiguration.KeyID) { //only add if key not already included
			cfg.EntityConfiguration.JWKs.Keys = append(cfg.EntityConfiguration.JWKs.Keys, *publicJWK)
		}
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

			_ = cfg.EntityConfiguration.JWKs.Add(*apkJWK) // just omit if it can't be added
		}
	}

	if cfg.TrustMarkIssuerRetriever != nil {
		trustMarkIssuerMap, err := cfg.TrustMarkIssuerRetriever.ListTrustMarkIssuers(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list trust mark issuers: %s", err.Error())
		}
		cfg.EntityConfiguration.TrustMarkIssuers = trustMarkIssuerMap
	}

	entityConfigurationBytes, err := json.Marshal(cfg.EntityConfiguration)
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
