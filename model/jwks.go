package model

import (
	"fmt"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

func ValidateJWKShape(key map[string]any) error {
	kty, ok := key["kty"].(string)
	if !ok || kty == "" {
		return fmt.Errorf("has a missing or malformed 'kty' member, which RFC 7517 section 4.1 requires")
	}
	if kty == "EC" {
		if crv, ok := key["crv"].(string); !ok || crv == "" {
			return fmt.Errorf("has a missing or malformed 'crv' member, which RFC 7518 requires for an EC key")
		}
	}
	return nil
}

func ParseFederationEntityKeys(value any) (josemodel.Jwks, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return josemodel.Jwks{}, fmt.Errorf("must be a JSON object")
	}
	if entries, ok := object["keys"].([]any); ok {
		seen := make(map[string]struct{}, len(entries))
		for i, entry := range entries {
			key, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			kid, present := key["kid"]
			if !present {
				return josemodel.Jwks{}, fmt.Errorf("has an entry at position %d of 'keys' with no 'kid' member, which section 3.1.1 requires of every key in the set", i)
			}
			sKid, ok := kid.(string)
			if !ok || sKid == "" {
				return josemodel.Jwks{}, fmt.Errorf("has an entry at position %d of 'keys' with a malformed 'kid' member", i)
			}
			if _, duplicate := seen[sKid]; duplicate {
				return josemodel.Jwks{}, fmt.Errorf("has more than one entry in 'keys' with the same 'kid', which section 3.1.1 forbids")
			}
			seen[sKid] = struct{}{}
		}
	}
	return ParseJWKSet(value)
}

func ParseJWKSet(value any) (josemodel.Jwks, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return josemodel.Jwks{}, fmt.Errorf("must be a JSON object")
	}
	raw, present := object["keys"]
	if !present {
		return josemodel.Jwks{}, fmt.Errorf("is missing the required 'keys' member")
	}
	entries, ok := raw.([]any)
	if !ok {
		return josemodel.Jwks{}, fmt.Errorf("has a 'keys' member that is not an array")
	}
	keys := make([]map[string]any, 0, len(entries))
	for i, entry := range entries {
		key, ok := entry.(map[string]any)
		if !ok {
			return josemodel.Jwks{}, fmt.Errorf("has an entry at position %d of 'keys' that is not a JSON object", i)
		}
		if ValidateJWKShape(key) != nil {
			continue
		}
		keys = append(keys, key)
	}
	return josemodel.Jwks{Keys: keys}, nil
}
