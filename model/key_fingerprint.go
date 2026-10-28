package model

import (
	"encoding/base64"
	"math/big"
	"slices"
)

func PublicKeyFingerprint(key map[string]any) (string, bool) {
	text := func(name string) (string, bool) {
		value, ok := key[name].(string)
		return value, ok && value != ""
	}
	octets := func(name string) ([]byte, bool) {
		value, ok := text(name)
		if !ok {
			return nil, false
		}
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		return decoded, err == nil && len(decoded) > 0
	}
	integer := func(name string) (string, bool) {
		decoded, ok := octets(name)
		if !ok {
			return "", false
		}
		return new(big.Int).SetBytes(decoded).Text(16), true
	}

	kty, _ := text("kty")
	switch kty {
	case "RSA":
		n, nOK := integer("n")
		e, eOK := integer("e")
		return "RSA|" + n + "|" + e, nOK && eOK
	case "EC":
		crv, crvOK := text("crv")
		x, xOK := integer("x")
		y, yOK := integer("y")
		return "EC|" + crv + "|" + x + "|" + y, crvOK && xOK && yOK
	case "OKP":
		crv, crvOK := text("crv")
		x, xOK := octets("x")
		return "OKP|" + crv + "|" + base64.RawURLEncoding.EncodeToString(x), crvOK && xOK
	}
	return "", false
}

func SharesAPublicKey(keys, others []map[string]any) bool {
	fingerprints := make([]string, 0, len(others))
	for _, other := range others {
		if fingerprint, ok := PublicKeyFingerprint(other); ok {
			fingerprints = append(fingerprints, fingerprint)
		}
	}
	for _, key := range keys {
		if fingerprint, ok := PublicKeyFingerprint(key); ok && slices.Contains(fingerprints, fingerprint) {
			return true
		}
	}
	return false
}
