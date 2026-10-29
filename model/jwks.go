package model

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"slices"
	"strings"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

const MinimumRSAKeyBits = 2048

const MaximumRSAKeyBits = 8192

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

const maxPublishableScanDepth = 32

func statementNestsDeeperThan(value any, depth int) bool {
	if depth > maxPublishableScanDepth {
		return true
	}
	switch typed := value.(type) {
	case map[string]any:
		for _, held := range typed {
			if statementNestsDeeperThan(held, depth+1) {
				return true
			}
		}
	case []any:
		for _, held := range typed {
			if statementNestsDeeperThan(held, depth+1) {
				return true
			}
		}
	}
	return false
}

type locatedJWK struct {
	key  map[string]any
	path string
}

func collectJWKSetEntries(value any, path string, depth int, into *[]locatedJWK) {
	if depth > maxPublishableScanDepth {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		if entries, ok := typed["keys"].([]any); ok {
			for _, entry := range entries {
				if key, ok := entry.(map[string]any); ok {
					*into = append(*into, locatedJWK{key: key, path: path})
				}
			}
		}
		for member, held := range typed {
			collectJWKSetEntries(held, path+"."+member, depth+1, into)
		}
	case []any:
		for _, member := range typed {
			collectJWKSetEntries(member, path, depth+1, into)
		}
	}
}

func findPublishableKeySets(value any, path string, depth int, found *[]locatedJWK) {
	if depth > maxPublishableScanDepth {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		for member, held := range typed {
			if member == "jwks" {
				collectJWKSetEntries(held, strings.TrimPrefix(path+".jwks", "."), 0, found)
				continue
			}
			findPublishableKeySets(held, path+"."+member, depth+1, found)
		}
	case []any:
		for _, member := range typed {
			findPublishableKeySets(member, path, depth+1, found)
		}
	}
}

func stripJWKSetEntries(value any, depth int, dropped *[]string) any {
	if depth > maxPublishableScanDepth {
		return value
	}
	switch typed := value.(type) {
	case map[string]any:
		if entries, ok := typed["keys"].([]any); ok {
			kept := make([]any, 0, len(entries))
			for _, entry := range entries {
				key, ok := entry.(map[string]any)
				if ok && VerifyPublishableJWK(key) != nil {
					kid, _ := key["kid"].(string)
					*dropped = append(*dropped, TruncateForResponse(kid))
					continue
				}
				kept = append(kept, entry)
			}
			if len(kept) != len(entries) {
				typed["keys"] = kept
			}
		}
		for member, held := range typed {
			if member == "keys" {
				continue
			}
			typed[member] = stripJWKSetEntries(held, depth+1, dropped)
		}
		return typed
	case []any:
		for i, member := range typed {
			typed[i] = stripJWKSetEntries(member, depth+1, dropped)
		}
		return typed
	}
	return value
}

func StripUnpublishableKeys(statement map[string]any, depth int, dropped *[]string) {
	if depth > maxPublishableScanDepth {
		return
	}
	for member, held := range statement {
		if member == "jwks" {
			statement[member] = stripJWKSetEntries(held, 0, dropped)
			continue
		}
		switch typed := held.(type) {
		case map[string]any:
			StripUnpublishableKeys(typed, depth+1, dropped)
		case []any:
			for _, entry := range typed {
				if nested, ok := entry.(map[string]any); ok {
					StripUnpublishableKeys(nested, depth+1, dropped)
				}
			}
		}
	}
}

func NestsDeeperThanTheKeyScan(statement map[string]any) bool {
	return statementNestsDeeperThan(statement, 0)
}

func VerifyPublishableStatementKeys(statement map[string]any) error {
	if statementNestsDeeperThan(statement, 0) {
		return fmt.Errorf("the statement nests deeper than %d levels, so it cannot be scanned for private key material", maxPublishableScanDepth)
	}

	var keys []locatedJWK
	findPublishableKeySets(statement, "", 0, &keys)
	for _, located := range keys {
		if err := VerifyPublishableJWK(located.key); err != nil {
			kid, _ := located.key["kid"].(string)
			return fmt.Errorf("the %q key set holds a key with key ID %q that %s", located.path, TruncateForResponse(kid), err.Error())
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
	bits := new(big.Int).SetBytes(raw).BitLen()
	if bits < MinimumRSAKeyBits {
		return fmt.Errorf("has a %d bit RSA modulus, and RFC 7518 sections 3.3 and 3.5 require a key of size %d bits or larger with %q", bits, MinimumRSAKeyBits, alg)
	}
	if bits > MaximumRSAKeyBits {
		return fmt.Errorf("has a %d bit RSA modulus, more than the %d bits this library will verify with %q", bits, MaximumRSAKeyBits, alg)
	}
	return nil
}

func VerifyKeyStrengthForAnySignatureAlgorithm(key map[string]any) error {
	if kty, _ := key["kty"].(string); kty != "RSA" {
		return nil
	}
	if use, present := key["use"]; present && use != nil && use != "sig" {
		return nil
	}
	if !KeyOpsPermitVerify(key) {
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
		return fmt.Errorf("has a %d bit RSA modulus and names no 'alg', so it can be selected to verify a signature, and RFC 7518 sections 3.3 and 3.5 require a key of size %d bits or larger with every RSA signature algorithm", bits, MinimumRSAKeyBits)
	}
	return nil
}

func ValidateKeyOps(key map[string]any) error {
	member, present := key["key_ops"]
	if !present {
		return nil
	}
	ops, ok := member.([]any)
	if !ok {
		return fmt.Errorf("has a 'key_ops' member that is not an array")
	}
	seen := make(map[string]struct{}, len(ops))
	for _, op := range ops {
		named, ok := op.(string)
		if !ok {
			return fmt.Errorf("has a 'key_ops' member holding a value that is not a string")
		}
		if _, duplicate := seen[named]; duplicate {
			return fmt.Errorf("lists %q more than once in 'key_ops', which RFC 7517 section 4.3 forbids", TruncateForResponse(named))
		}
		seen[named] = struct{}{}
	}
	return nil
}

func KeyOpsPermitVerify(key map[string]any) bool {
	member, present := key["key_ops"]
	if !present {
		return true
	}
	ops, _ := member.([]any)
	return slices.Contains(ops, any("verify"))
}

func LogPrivateKeyMembersInRawSet(ctx context.Context, cfg *Configuration, issuer, subject EntityIdentifier, raw any) {
	LogPrivateKeyMembers(ctx, cfg, issuer, subject, josemodel.Jwks{Keys: rawJWKSetEntries(raw)})
}

const maxLoggedPrivateKeys = 8

func LogPrivateKeyMembers(ctx context.Context, cfg *Configuration, issuer, subject EntityIdentifier, jwks josemodel.Jwks) {
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
	cfg.LogError(ctx, "a received key set carries private key material", slog.String("issuer", TruncateForResponse(string(issuer))), slog.String("subject", TruncateForResponse(string(subject))), slog.Int("affected_keys", affected), slog.Any("first_key_ids", named), slog.Any("members", slices.Sorted(maps.Keys(members))))
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
