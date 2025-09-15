package entity_configuration

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

func Retrieve(httpClient *http.Client, entityIdentifier model.EntityIdentifier) (*string, *model.EntityStatement, error) {
	if httpClient == nil {
		return nil, nil, fmt.Errorf("no http client present")
	}

	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s.well-known/openid-federation", strings.TrimSuffix(string(entityIdentifier), "/")+"/"), nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Accept", "application/entity-statement+jwt")

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("non-200 response from %q's entity configuration: %s", entityIdentifier, response.Status)
	}

	if !strings.Contains(response.Header.Get("Content-Type"), "application/entity-statement+jwt") { //todo: check on this - not sure if it has to be an exact match or not...
		return nil, nil, fmt.Errorf("invalid Content-Type response from %q's entity configuration: %s", entityIdentifier, response.Header.Get("Content-Type"))
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %q's entity configuration response body: %s", entityIdentifier, err.Error())
	}

	entityConfiguration, err := Validate(entityIdentifier, string(responseBytes))
	if err != nil {
		return nil, nil, err
	}

	return josemodel.Pointer(string(responseBytes)), entityConfiguration, nil
}

func Validate(entityIdentifier model.EntityIdentifier, entityConfigurationJwt string) (*model.EntityStatement, error) {
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
func New(configuration model.ServerConfiguration) (*string, error) {
	configuration.EntityConfiguration.Sub = configuration.EntityIdentifier
	configuration.EntityConfiguration.Iss = configuration.EntityIdentifier
	configuration.EntityConfiguration.AuthorityHints = configuration.AuthorityHints
	configuration.EntityConfiguration.TrustMarks = configuration.TrustMarks
	configuration.EntityConfiguration.Iat = time.Now().UTC().Unix()
	configuration.EntityConfiguration.Exp = time.Now().Add(configuration.EntityConfigurationLifetime).UTC().Unix()

	if configuration.IntermediateConfiguration != nil { //if the entity can in theory issue subordinate statements, then we need to include the subordinate configuration
		if configuration.EntityConfiguration.Metadata == nil || configuration.EntityConfiguration.Metadata.FederationMetadata == nil {
			configuration.EntityConfiguration.Metadata = &model.Metadata{FederationMetadata: &model.FederationMetadata{}}
		}
		(*configuration.EntityConfiguration.Metadata.FederationMetadata)["federation_fetch_endpoint"] = strings.TrimSuffix(string(configuration.EntityIdentifier), "/") + "/fetch"
		(*configuration.EntityConfiguration.Metadata.FederationMetadata)["federation_list_endpoint"] = strings.TrimSuffix(string(configuration.EntityIdentifier), "/") + "/list"
		(*configuration.EntityConfiguration.Metadata.FederationMetadata)["federation_resolve_endpoint"] = strings.TrimSuffix(string(configuration.EntityIdentifier), "/") + "/resolve"
		if configuration.Extensions.ExtendedListing.Enabled {
			(*configuration.EntityConfiguration.Metadata.FederationMetadata)["federation_extended_list_endpoint"] = strings.TrimSuffix(string(configuration.EntityIdentifier), "/") + "/extended-list"
		}
	}

	if configuration.TrustMarkRetriever != nil {
		(*configuration.EntityConfiguration.Metadata.FederationMetadata)["federation_trust_mark_status_endpoint"] = strings.TrimSuffix(string(configuration.EntityIdentifier), "/") + "/trust-mark-status"
		(*configuration.EntityConfiguration.Metadata.FederationMetadata)["federation_trust_mark_list_endpoint"] = strings.TrimSuffix(string(configuration.EntityIdentifier), "/") + "/trust-mark-list"
		(*configuration.EntityConfiguration.Metadata.FederationMetadata)["federation_trust_mark_endpoint"] = strings.TrimSuffix(string(configuration.EntityIdentifier), "/") + "/trust-mark"
	}

	configuration.EntityConfiguration.MetadataPolicy = nil // not permitted on entity statements

	if configuration.SignerConfiguration.KeyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	publicJWK, err := jwk.PublicJwk(configuration.SignerConfiguration.Signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to convert provided signer public key to a jwk: %s", err.Error())
	}
	(*publicJWK)["kid"] = configuration.SignerConfiguration.KeyID
	(*publicJWK)["alg"] = configuration.SignerConfiguration.Algorithm

	configuration.EntityConfiguration.JWKs.Opts.EnforceUniqueKIDs = true
	if configuration.EntityConfiguration.JWKs.Keys == nil {
		configuration.EntityConfiguration.JWKs.Keys = []map[string]any{
			*publicJWK,
		}
	} else {
		var keyIDs []string
		for _, v := range configuration.EntityConfiguration.JWKs.Keys {
			if kid, ok := v["kid"]; !ok {
				return nil, fmt.Errorf("all provided jwk values in entity configuration must have a `kid` claim - missing from one or more")
			} else if sKid, ok := kid.(string); !ok {
				return nil, fmt.Errorf("one or more provided jwk values have a malformed `kid` claim")
			} else {
				keyIDs = append(keyIDs, sKid)
			}
		}
		if !slices.Contains(keyIDs, configuration.SignerConfiguration.KeyID) { //only add if key not already included
			configuration.EntityConfiguration.JWKs.Keys = append(configuration.EntityConfiguration.JWKs.Keys, *publicJWK)
		}
	}

	if configuration.IntermediateConfiguration != nil {
		subordinateSignerConfigurations, err := configuration.GetSubordinateJWKs()
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

			_ = configuration.EntityConfiguration.JWKs.Add(*apkJWK) // just omit if it can't be added
		}
	}

	if configuration.TrustMarkIssuerRetriever != nil {
		trustMarkIssuerMap, err := configuration.TrustMarkIssuerRetriever.ListTrustMarkIssuers()
		if err != nil {
			return nil, fmt.Errorf("failed to list trust mark issuers: %s", err.Error())
		}
		configuration.EntityConfiguration.TrustMarkIssuers = trustMarkIssuerMap
	}

	entityConfigurationBytes, err := json.Marshal(configuration.EntityConfiguration)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize entity configuration: %s", err.Error())
	}

	var entityConfigurationMap map[string]any
	err = json.Unmarshal(entityConfigurationBytes, &entityConfigurationMap)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize entity configuration: %s", err.Error())
	}

	return jwt.New(configuration.SignerConfiguration.Signer, map[string]any{
		"kid": configuration.SignerConfiguration.KeyID,
		"typ": "entity-statement+jwt",
		"alg": configuration.SignerConfiguration.Algorithm,
	}, entityConfigurationMap, jwt.Opts{Algorithm: josemodel.GetAlgorithm(configuration.SignerConfiguration.Algorithm)})
}
