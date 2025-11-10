package subordinate_statement

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func Retrieve(ctx context.Context, cfg model.Configuration, issuer model.EntityStatement, subject model.EntityIdentifier) (*string, *model.EntityStatement, error) {
	if cfg.HttpClient == nil {
		return nil, nil, fmt.Errorf("no http client present")
	}
	if issuer.Iss != issuer.Sub {
		return nil, nil, fmt.Errorf("the value of 'issuer' must be an entity configuration")
	}
	if issuer.Metadata == nil || issuer.Metadata.FederationMetadata == nil || (*issuer.Metadata.FederationMetadata)["federation_fetch_endpoint"] == nil {
		return nil, nil, fmt.Errorf("issuer entity statement does not list a federation fetch endpoint within it's federation metadata")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%ssub=%s", func() string {
		trimmedString := strings.TrimSuffix((*issuer.Metadata.FederationMetadata)["federation_fetch_endpoint"].(string), "/")
		if strings.Contains(trimmedString, "?") {
			return trimmedString + "&"
		} else {
			return trimmedString + "?"
		}
	}(), url.QueryEscape(string(subject))), nil)
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
		return nil, nil, fmt.Errorf("non-200 response from %q's federation fetch endpoint: %s", issuer.Sub, response.Status)
	}

	if !strings.Contains(response.Header.Get("Content-Type"), "application/entity-statement+jwt") { //todo: check on this - not sure if it has to be an exact match or not...
		return nil, nil, fmt.Errorf("invalid Content-Type response from %q's federation fetch response: %s", issuer.Sub, response.Header.Get("Content-Type"))
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %q's federation fetch response body: %s", issuer.Sub, err.Error())
	}

	subordinateStatement, err := Validate(issuer, string(responseBytes))
	if err != nil {
		return nil, nil, err
	}

	if subordinateStatement.Sub != subject {
		return nil, nil, fmt.Errorf("'sub' claim does not match the requested subject entity identifier")
	}

	return josemodel.Pointer(string(responseBytes)), subordinateStatement, nil
}

func Validate(issuer model.EntityStatement, subordinateStatementJwt string) (*model.EntityStatement, error) {
	parts := strings.Split(subordinateStatementJwt, ".")
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

	if _, _, err = jws.VerifyCompactSerialization(subordinateStatementJwt, func() ([]crypto.PublicKey, error) {
		keys := map[string]map[string]any{}
		for _, key := range issuer.JWKs.Keys {
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

	var subordinateStatement model.EntityStatement
	err = json.Unmarshal(body, &subordinateStatement)
	if err != nil {
		return nil, fmt.Errorf("malformed 'metadata' claim: %s", err.Error())
	}

	if subordinateStatement.Iss != issuer.Sub {
		return nil, fmt.Errorf("'iss' claim does not match issuer 'sub' claim")
	}

	return &subordinateStatement, nil
}

// todo: check this conforms to the errors listed in openid federation (spoiler alert - it doesn't)
// New takes a given subject Entity Identifier, set of authority hint Entity Identifiers, populated Entity Statement, and key material (with associated key ID and algorithm) and produces a signed Entity Configuration
func New(ctx context.Context, subjectIdentifier model.EntityIdentifier, subordinateRetriever func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error), configuration model.ServerConfiguration) (*string, error) {
	if configuration.IntermediateConfiguration == nil {
		return nil, fmt.Errorf("no intermediate configuration provided")
	}

	subjectSubordinateConfiguration, signerConfiguration, err := subordinateRetriever()
	if err != nil {
		return nil, err
	}
	if subjectSubordinateConfiguration == nil {
		return nil, model.NewNotFoundError("unknown entity identifier")
	}

	if len(subjectSubordinateConfiguration.JWKs.Keys) == 0 {
		return nil, fmt.Errorf("no jwk values provided for subject subordinate entity identifier")
	}

	for _, k := range subjectSubordinateConfiguration.JWKs.Keys {
		if kid, ok := k["kid"]; !ok {
			return nil, fmt.Errorf("one or more of the provided subordinate configuration JWKs is missing the mandatory field 'kid'")
		} else if _, ok := kid.(string); !ok {
			return nil, fmt.Errorf("one or more of the provided subordinate configuration JWKs has a malformed 'kid' value")
		}
	}

	subordinateStatement := model.EntityStatement{
		Sub:            subjectIdentifier,
		Iss:            configuration.EntityIdentifier,
		Iat:            time.Now().UTC().Unix(),
		Exp:            time.Now().Add(configuration.IntermediateConfiguration.SubordinateStatementLifetime).UTC().Unix(),
		JWKs:           subjectSubordinateConfiguration.JWKs,
		MetadataPolicy: &subjectSubordinateConfiguration.Policies,
	}

	if signerConfiguration.KeyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	subordinateStatementBytes, err := json.Marshal(subordinateStatement)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize entity configuration: %s", err.Error())
	}

	var subordinateStatementMap map[string]any
	err = json.Unmarshal(subordinateStatementBytes, &subordinateStatementMap)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize entity configuration: %s", err.Error())
	}

	return jwt.New(signerConfiguration.Signer, map[string]any{
		"kid": signerConfiguration.KeyID,
		"typ": "entity-statement+jwt",
		"alg": signerConfiguration.Algorithm,
	}, subordinateStatementMap, jwt.Opts{Algorithm: josemodel.GetAlgorithm(signerConfiguration.Algorithm)})
}
