package entity_configuration

import (
	"strings"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_HoldsTrustMarkOwnerKeysToWhatTheRFCsRequireOfEveryImplementation(t *testing.T) {
	ec := func(members map[string]any) map[string]any {
		key := map[string]any{"kid": "owner", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}
		for member, value := range members {
			key[member] = value
		}
		return key
	}
	rsa := func(bits int, members map[string]any) map[string]any {
		key := map[string]any{"kid": "owner-rsa", "kty": "RSA", "n": allOnesModulus(bits), "e": "AQAB"}
		for member, value := range members {
			key[member] = value
		}
		return key
	}

	tests := []struct {
		name      string
		reference string
		keys      []map[string]any
		expectErr string
	}{
		{name: "a key with no key_ops", reference: "RFC 7517 4.3", keys: []map[string]any{ec(nil)}},
		{name: "a key whose key_ops list verify", reference: "RFC 7517 4.3", keys: []map[string]any{ec(map[string]any{"key_ops": []any{"verify"}})}},
		{name: "an Ed25519 key, valid though this library does not verify with it", reference: "RFC 8037 2", keys: []map[string]any{{"kid": "owner", "kty": "OKP", "crv": "Ed25519", "x": "AQAB"}}},
		{name: "an encryption-only key beside a key that can verify", reference: "RFC 7517 4.3", keys: []map[string]any{ec(map[string]any{"kid": "spare", "key_ops": []any{"encrypt"}}), ec(nil)}},
		{name: "a 1024 bit RSA key marked for encryption beside a key that can verify", reference: "RFC 7517 4.2", keys: []map[string]any{rsa(1024, map[string]any{"use": "enc"}), ec(nil)}},
		{name: "an RSA key above this library's maximum that names no algorithm", reference: "RFC 7517 4.4", keys: []map[string]any{rsa(8193, nil)}},
		{name: "an RSA key above this library's maximum published for RS256 beside a key that can verify", reference: "RFC 7518 3.3", keys: []map[string]any{rsa(8200, map[string]any{"alg": "RS256"}), ec(nil)}},
		{name: "an RSA key above this library's maximum published for RS256, alone", reference: "RFC 7518 3.3", keys: []map[string]any{rsa(8200, map[string]any{"alg": "RS256"})}},
		{name: "only a key whose key_ops name sign", reference: "RFC 7517 4.3", keys: []map[string]any{ec(map[string]any{"key_ops": []any{"sign"}})}, expectErr: "holds no usable key"},
		{name: "only a key whose key_ops name encrypt", reference: "RFC 7517 4.3", keys: []map[string]any{ec(map[string]any{"key_ops": []any{"encrypt"}})}, expectErr: "holds no usable key"},
		{name: "only a key published for encryption", reference: "RFC 7517 4.2", keys: []map[string]any{ec(map[string]any{"use": "enc"})}, expectErr: "holds no usable key"},
		{name: "a key listing verify twice", reference: "RFC 7517 4.3", keys: []map[string]any{ec(map[string]any{"key_ops": []any{"verify", "verify"}})}, expectErr: "lists \"verify\" more than once"},
		{name: "a key whose key_ops is a string", reference: "RFC 7517 4.3", keys: []map[string]any{ec(map[string]any{"key_ops": "verify"})}, expectErr: "not an array"},
		{name: "a malformed key_ops beside a key that can verify", reference: "RFC 7517 4.3", keys: []map[string]any{ec(map[string]any{"kid": "spare", "key_ops": []any{"verify", "verify"}}), ec(nil)}, expectErr: "more than once"},
		{name: "a 1024 bit RSA key published for RS256", reference: "RFC 7518 3.3", keys: []map[string]any{rsa(1024, map[string]any{"alg": "RS256"}), ec(nil)}, expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit RSA key that names no algorithm", reference: "RFC 7518 3.3 and 3.5", keys: []map[string]any{rsa(1024, nil), ec(nil)}, expectErr: "1024 bit RSA modulus"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := publishableConfiguration(t)
			cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{
				"https://tm.example.com/a": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: tc.keys}},
			}

			signed, err := New(t.Context(), cfg)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the owner's keys to be published, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the entity configuration to be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
			if !strings.Contains(err.Error(), "trust_mark_owners") {
				t.Errorf("[%s] expected the refusal to name the claim, got %v", tc.reference, err)
			}
			if signed != nil {
				t.Errorf("[%s] expected no statement to be published", tc.reference)
			}
		})
	}
}
