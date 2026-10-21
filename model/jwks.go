package model

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

const MinimumRSAKeyBits = 2048

var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

func PrivateJWKMembers(key map[string]any) []string {
	members := make([]string, 0, len(privateJWKMembers))
	for _, member := range privateJWKMembers {
		if _, present := key[member]; present {
			members = append(members, member)
		}
	}
	return members
}

func VerifyPublishableJWK(key map[string]any) error {
	if members := PrivateJWKMembers(key); len(members) > 0 {
		return fmt.Errorf("carries the private key members %v that RFC 7518 sections 6.2.2, 6.3.2 and 6.4 define, and a published key set must carry public key material only", members)
	}
	return nil
}

func rsaSignatureAlgorithm(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return true
	default:
		return false
	}
}

func VerifyKeyStrength(key map[string]any, alg string) error {
	if kty, _ := key["kty"].(string); kty != "RSA" {
		return nil
	}
	if !rsaSignatureAlgorithm(alg) {
		return nil
	}
	modulus, ok := key["n"].(string)
	if !ok {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		return nil
	}
	if bits := new(big.Int).SetBytes(raw).BitLen(); bits < MinimumRSAKeyBits {
		return fmt.Errorf("has a %d bit RSA modulus, and RFC 7518 sections 3.3 and 3.5 require a key of size %d bits or larger with %q", bits, MinimumRSAKeyBits, alg)
	}
	return nil
}

func LogPrivateKeyMembers(ctx context.Context, cfg *Configuration, subject EntityIdentifier, jwks josemodel.Jwks) {
	for _, key := range jwks.Keys {
		members := PrivateJWKMembers(key)
		if len(members) == 0 {
			continue
		}
		kid, _ := key["kid"].(string)
		cfg.LogError(ctx, "a received key set carries private key material", slog.String("subject", string(subject)), slog.String("kid", TruncateForResponse(kid)), slog.Any("members", members))
	}
}

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
