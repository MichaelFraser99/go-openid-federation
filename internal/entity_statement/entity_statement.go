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
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const maxQuotedHeaderBytes = 64

func truncateHeaderValue(value string) string {
	if len(value) <= maxQuotedHeaderBytes {
		return value
	}
	return value[:maxQuotedHeaderBytes] + "..."
}

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
		return fmt.Errorf("entity statements must set the 'typ' header to 'entity-statement+jwt', got %q", truncateHeaderValue(sTyp))
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

func VerifyIssuedSignature(token, kid, alg string, signer crypto.Signer) error {
	if err := ValidateStatementHeader(map[string]any{"typ": "entity-statement+jwt", "alg": alg}); err != nil {
		return err
	}
	if josemodel.GetAlgorithm(alg) == josemodel.Unknown {
		return fmt.Errorf("%q is not a supported signing algorithm", truncateHeaderValue(alg))
	}
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		return fmt.Errorf("failed to derive the public key of the signing key: %s", err.Error())
	}
	(*publicJWK)["kid"] = kid
	return VerifyAgainstJwks(token, kid, josemodel.Jwks{Keys: []map[string]any{*publicJWK}})
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
	if err := model.ValidateJWKShape(selectedKey); err != nil {
		return nil, fmt.Errorf("the selected key in the included 'jwks' %s", err.Error())
	}
	return selectedKey, nil
}

func verifyKeyAlgorithm(token string, key map[string]any) error {
	declared, present := key["alg"]
	if !present || declared == nil {
		return nil
	}
	sDeclared, ok := declared.(string)
	if !ok || sDeclared == "" {
		return fmt.Errorf("the selected key in the included 'jwks' has a malformed 'alg' member")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT structure")
	}
	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWT head: %s", err.Error())
	}
	var headMap map[string]any
	if err = json.Unmarshal(head, &headMap); err != nil {
		return fmt.Errorf("failed to unmarshal JWT head to json: %s", err.Error())
	}
	header, ok := headMap["alg"].(string)
	if !ok {
		return fmt.Errorf("missing or malformed header claim 'alg'")
	}
	if header != sDeclared {
		return fmt.Errorf("the 'alg' header does not match the 'alg' the selected key in the included 'jwks' is published for")
	}
	return nil
}

func VerifyAgainstJwks(token, kid string, jwks josemodel.Jwks) error {
	if _, _, err := jws.VerifyCompactSerialization(token, func() ([]crypto.PublicKey, error) {
		selectedKey, err := SelectKey(jwks, kid)
		if err != nil {
			return nil, err
		}
		if err = verifyKeyAlgorithm(token, selectedKey); err != nil {
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

	kid, ok := headMap["kid"].(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("missing or malformed 'kid' claim")
	}

	sIss, ok := bodyMap["iss"].(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("missing or malformed 'iss' claim")
	}

	sSub, ok := bodyMap["sub"].(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("missing or malformed 'sub' claim")
	}

	return josemodel.Pointer(kid), josemodel.Pointer(sSub), josemodel.Pointer(sIss), nil
}
