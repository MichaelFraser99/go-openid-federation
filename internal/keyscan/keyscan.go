package keyscan

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
	"github.com/MichaelFraser99/go-openid-federation/internal/truncate"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

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
		*into = append(*into, locatedJWK{key: typed, path: path})
		for member, held := range typed {
			if member == "keys" {
				collectJWKSetEntries(held, path, depth+1, into)
				continue
			}
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

func stripJWKSetEntries(value any, depth int, dropped *[]string) (any, bool) {
	if depth > maxPublishableScanDepth {
		return value, true
	}
	switch typed := value.(type) {
	case map[string]any:
		if model.VerifyPublishableJWK(typed) != nil {
			kid, _ := typed["kid"].(string)
			*dropped = append(*dropped, truncate.TruncateForResponse(kid))
			return nil, false
		}
		for member, held := range typed {
			if kept, keep := stripJWKSetEntries(held, depth+1, dropped); keep {
				typed[member] = kept
			} else {
				delete(typed, member)
			}
		}
		return typed, true
	case []any:
		kept := make([]any, 0, len(typed))
		for _, member := range typed {
			if held, keep := stripJWKSetEntries(member, depth+1, dropped); keep {
				kept = append(kept, held)
			}
		}
		return kept, true
	}
	return value, true
}

func StripUnpublishableKeys(statement map[string]any, depth int, dropped *[]string) {
	stripKeySets(statement, depth, dropped)
}

func stripKeySets(value any, depth int, dropped *[]string) {
	if depth > maxPublishableScanDepth {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		for member, held := range typed {
			if member != "jwks" {
				stripKeySets(held, depth+1, dropped)
				continue
			}
			if kept, keep := stripJWKSetEntries(held, 0, dropped); keep {
				typed[member] = kept
			} else {
				delete(typed, member)
			}
		}
	case []any:
		for _, entry := range typed {
			stripKeySets(entry, depth+1, dropped)
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
		if err := model.VerifyPublishableJWK(located.key); err != nil {
			kid, _ := located.key["kid"].(string)
			return fmt.Errorf("the %q key set holds a key with key ID %q that %s", located.path, truncate.TruncateForResponse(kid), err.Error())
		}
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
	if bits := new(big.Int).SetBytes(raw).BitLen(); bits < model.MinimumRSAKeyBits {
		return fmt.Errorf("has a %d bit RSA modulus and names no 'alg', so it can be selected to verify a signature, and RFC 7518 sections 3.3 and 3.5 require a key of size %d bits or larger with every RSA signature algorithm", bits, model.MinimumRSAKeyBits)
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
			return fmt.Errorf("lists %q more than once in 'key_ops', which RFC 7517 section 4.3 forbids", truncate.TruncateForResponse(named))
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

func LogPrivateKeyMembersInRawSet(ctx context.Context, cfg *model.Configuration, issuer, subject model.EntityIdentifier, raw any) {
	logPrivateKeyMembers(ctx, cfg, issuer, subject, josemodel.Jwks{Keys: rawJWKSetEntries(raw)})
}

const maxLoggedPrivateKeys = 8

func logPrivateKeyMembers(ctx context.Context, cfg *model.Configuration, issuer, subject model.EntityIdentifier, jwks josemodel.Jwks) {
	if cfg == nil {
		return
	}
	affected := 0
	named := make([]string, 0, maxLoggedPrivateKeys)
	members := map[string]struct{}{}
	for _, key := range jwks.Keys {
		present := model.PrivateJWKMembers(key)
		if len(present) == 0 {
			continue
		}
		affected++
		for _, member := range present {
			members[member] = struct{}{}
		}
		if len(named) < maxLoggedPrivateKeys {
			kid, _ := key["kid"].(string)
			named = append(named, truncate.TruncateForResponse(kid))
		}
	}
	if affected == 0 {
		return
	}
	cfg.LogError(ctx, "a received key set carries private key material", slog.String("issuer", truncate.TruncateForResponse(string(issuer))), slog.String("subject", truncate.TruncateForResponse(string(subject))), slog.Int("affected_keys", affected), slog.Any("first_key_ids", named), slog.Any("members", slices.Sorted(maps.Keys(members))))
}
