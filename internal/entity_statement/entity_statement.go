package entity_statement

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
)

func ValidateStatementHeader(headMap map[string]any) error {
	typ, ok := headMap["typ"]
	if !ok {
		return fmt.Errorf("missing required header claim 'typ'")
	}
	sTyp, ok := typ.(string)
	if !ok {
		return fmt.Errorf("malformed header claim 'typ'")
	}
	if !strings.EqualFold(sTyp, "entity-statement+jwt") && !strings.EqualFold(sTyp, "application/entity-statement+jwt") {
		return fmt.Errorf("entity statements must set the 'typ' header to 'entity-statement+jwt', got %q", sTyp)
	}

	alg, ok := headMap["alg"]
	if !ok {
		return fmt.Errorf("missing required header claim 'alg'")
	}
	sAlg, ok := alg.(string)
	if !ok {
		return fmt.Errorf("malformed header claim 'alg'")
	}
	if strings.EqualFold(sAlg, "none") {
		return fmt.Errorf("entity statements must be signed, the 'alg' header must not be 'none'")
	}

	if crit, present := headMap["crit"]; present {
		entries, ok := crit.([]any)
		if !ok {
			return fmt.Errorf("the 'crit' header must be an array of strings")
		}
		if len(entries) == 0 {
			return fmt.Errorf("the 'crit' header must not be the empty array")
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			name, ok := entry.(string)
			if !ok {
				return fmt.Errorf("the 'crit' header must be an array of strings")
			}
			names = append(names, name)
		}
		return fmt.Errorf("the 'crit' header lists %v, which this implementation does not understand", names)
	}

	return nil
}

func SelectKey(jwks josemodel.Jwks, kid string) (map[string]any, error) {
	if kid == "" {
		return nil, fmt.Errorf("header claim 'kid' must be a non-empty string")
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("the included 'jwks' contains no keys")
	}
	keys := map[string]map[string]any{}
	for _, key := range jwks.Keys {
		keyKid, ok := key["kid"]
		if !ok {
			return nil, fmt.Errorf("one or more entries in the included 'jwks' is missing the mandatory 'kid' claim")
		}
		sKeyID, ok := keyKid.(string)
		if !ok {
			return nil, fmt.Errorf("one or more entries in the included 'jwks' has a malformed 'kid' claim")
		}
		if keys[sKeyID] != nil {
			return nil, fmt.Errorf("all entries in the included 'jwks' must have unique 'kid' values")
		}
		keys[sKeyID] = key
	}
	selectedKey := keys[kid]
	if selectedKey == nil {
		return nil, fmt.Errorf("no matching key found in the included 'jwks'")
	}
	return selectedKey, nil
}

func VerifyAgainstJwks(token, kid string, jwks josemodel.Jwks) error {
	if _, _, err := jws.VerifyCompactSerialization(token, func() ([]crypto.PublicKey, error) {
		selectedKey, err := SelectKey(jwks, kid)
		if err != nil {
			return nil, err
		}
		pubKey, err := jwk.PublicFromJwk(selectedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse selected public key from 'jwks' as a valid jwk: %s", err.Error())
		}
		return []crypto.PublicKey{pubKey}, nil
	}, &josemodel.JoseOptions{UseTokenProvidedKeys: false}); err != nil {
		return fmt.Errorf("failed to verify JWT signature: %s", err.Error())
	}
	return nil
}

func ExtractDetails(token string) (keyID, subject, issuer *string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("invalid JWT structure")
	}

	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode JWT head: %s", err.Error())
	}

	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode JWT body: %s", err.Error())
	}

	var headMap, bodyMap map[string]any
	if err := json.Unmarshal(head, &headMap); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal JWT head to json: %s", err.Error())
	}

	if err := json.Unmarshal(body, &bodyMap); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal JWT body to json: %s", err.Error())
	}

	if headMap["kid"] == nil {
		return nil, nil, nil, fmt.Errorf("missing 'kid' claim")
	}

	if bodyMap["iss"] == nil {
		return nil, nil, nil, fmt.Errorf("missing 'iss' claim")
	}

	if bodyMap["sub"] == nil {
		return nil, nil, nil, fmt.Errorf("missing 'sub' claim")
	}

	return josemodel.Pointer(headMap["kid"].(string)), josemodel.Pointer(bodyMap["sub"].(string)), josemodel.Pointer(bodyMap["iss"].(string)), nil
}
