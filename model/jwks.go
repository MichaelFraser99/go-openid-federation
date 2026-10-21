package model

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"slices"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

const MinimumRSAKeyBits = 2048

var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"}

func PrivateJWKMembers(key map[string]any) []string {
	var members []string
	for _, member := range privateJWKMembers {
		if _, present := key[member]; present {
			members = append(members, member)
		}
	}
	return members
}

func VerifyPublishableTrustMarkOwnerKeys(owners map[string]TrustMarkOwner) error {
	for trustMarkType, owner := range owners {
		for _, key := range owner.JWKs.Keys {
			if err := VerifyPublishableJWK(key); err != nil {
				kid, _ := key["kid"].(string)
				return fmt.Errorf("the 'trust_mark_owners' entry for %q holds a key with key ID %q that %s", TruncateForResponse(trustMarkType), TruncateForResponse(kid), err.Error())
			}
		}
	}
	return nil
}

func rawJWKSetEntries(raw any) []map[string]any {
	set, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	entries, ok := set["keys"].([]any)
	if !ok {
		return nil
	}
	keys := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		key, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		keys = append(keys, key)
	}
	return keys
}

func VerifyPublishableMetadataKeys(m *Metadata) error {
	if m == nil {
		return nil
	}
	for entityType, entityMetadata := range m.byEntityType() {
		raw, present := entityMetadata["jwks"]
		if !present || raw == nil {
			continue
		}
		for _, key := range rawJWKSetEntries(raw) {
			if err := VerifyPublishableJWK(key); err != nil {
				kid, _ := key["kid"].(string)
				return fmt.Errorf("the %q metadata 'jwks' holds a key with key ID %q that %s", entityType, TruncateForResponse(kid), err.Error())
			}
		}
	}
	return nil
}

func VerifyPublishableJWK(key map[string]any) error {
	if members := PrivateJWKMembers(key); len(members) > 0 {
		return fmt.Errorf("carries the private key members %v that RFC 7518 sections 6.2.2, 6.3.2 and 6.4, RFC 8037 section 2.3 and the AKP key type define, and a published key set must carry public key material only", members)
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
	if !ok || modulus == "" {
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

func LogPrivateKeyMembersInRawSet(ctx context.Context, cfg *Configuration, subject EntityIdentifier, raw any) {
	LogPrivateKeyMembers(ctx, cfg, subject, josemodel.Jwks{Keys: rawJWKSetEntries(raw)})
}

const maxLoggedPrivateKeys = 8

func LogPrivateKeyMembers(ctx context.Context, cfg *Configuration, subject EntityIdentifier, jwks josemodel.Jwks) {
	if cfg == nil {
		return
	}
	affected := 0
	named := make([]string, 0, maxLoggedPrivateKeys)
	members := map[string]struct{}{}
	for _, key := range jwks.Keys {
		present := PrivateJWKMembers(key)
		if len(present) == 0 {
			continue
		}
		affected++
		for _, member := range present {
			members[member] = struct{}{}
		}
		if len(named) < maxLoggedPrivateKeys {
			kid, _ := key["kid"].(string)
			named = append(named, TruncateForResponse(kid))
		}
	}
	if affected == 0 {
		return
	}
	cfg.LogError(ctx, "a received key set carries private key material", slog.String("subject", TruncateForResponse(string(subject))), slog.Int("affected_keys", affected), slog.Any("first_key_ids", named), slog.Any("members", slices.Sorted(maps.Keys(members))))
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
