package model

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

func TestSubordinateConfiguration_UnmarshalJSON_RoundTripsWhatTheEncoderWrites(t *testing.T) {
	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(`{"openid_relying_party":{"contacts":{"add":["ops@example.com"]}}}`), &policy); err != nil {
		t.Fatal(err)
	}
	original := SubordinateConfiguration{
		CachedAt:            42,
		Policies:            policy,
		JWKs:                josemodel.Jwks{Keys: []map[string]any{{"kty": "EC", "crv": "P-256", "kid": "a", "x": "x", "y": "y"}}},
		SignerConfiguration: &SignerConfiguration{KeyID: "signer", Algorithm: "ES256"},
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	var decoded SubordinateConfiguration
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("expected what the encoder wrote to decode, got %v", err)
	}
	if decoded.CachedAt != 42 || !reflect.DeepEqual(decoded.JWKs.Keys, original.JWKs.Keys) || *decoded.SignerConfiguration != *original.SignerConfiguration {
		t.Errorf("expected the round trip to keep every field, got %+v", decoded)
	}
	if got := decoded.Policies.OpenIDRelyingPartyMetadata["contacts"].Metadata; len(got) != 1 || got[0].String() != "add" {
		t.Errorf("expected the policy to survive the round trip, got %+v", decoded.Policies)
	}
}

func TestSubordinateConfiguration_UnmarshalJSON_TakesMembersByTheirExactName(t *testing.T) {
	tests := map[string]struct {
		json  string
		check func(t *testing.T, decoded SubordinateConfiguration, err error)
	}{
		"a folded JWKs and CachedAt are ignored": {
			json: `{"jwkſ":{"keys":[{"kty":"oct","k":"AAAA","kid":"folded"}]},"cachedat":5}`,
			check: func(t *testing.T, decoded SubordinateConfiguration, err error) {
				if err != nil || len(decoded.JWKs.Keys) != 0 || decoded.CachedAt != 0 {
					t.Errorf("[#178] expected folded member names to fill nothing, got %+v, %v", decoded, err)
				}
			},
		},
		"the key set goes through ParseJWKSet": {
			json: `{"JWKs":{"keys":[{"kid":"no-kty"},{"kty":"EC","crv":"P-256","kid":"kept","x":"x","y":"y"}]}}`,
			check: func(t *testing.T, decoded SubordinateConfiguration, err error) {
				if err != nil || len(decoded.JWKs.Keys) != 1 || decoded.JWKs.Keys[0]["kid"] != "kept" {
					t.Errorf("expected the key with no kty to be dropped as ParseJWKSet drops it, got %+v, %v", decoded.JWKs, err)
				}
			},
		},
		"a key set with a folded keys member": {
			json: `{"JWKs":{"keyſ":[]}}`,
			check: func(t *testing.T, _ SubordinateConfiguration, err error) {
				if err == nil || !strings.Contains(err.Error(), "'keys'") {
					t.Errorf("expected a key set without an exact 'keys' member to be refused, got %v", err)
				}
			},
		},
		"a repeated member name": {
			json: `{"CachedAt":1,"CachedAt":2}`,
			check: func(t *testing.T, _ SubordinateConfiguration, err error) {
				if err == nil || !strings.Contains(err.Error(), "repeats a member name") {
					t.Errorf("expected a repeated member to be refused, got %v", err)
				}
			},
		},
		"a repeated member name in the signer configuration": {
			json: `{"SignerConfiguration":{"KeyID":"a","KeyID":"b"}}`,
			check: func(t *testing.T, _ SubordinateConfiguration, err error) {
				if err == nil || !strings.Contains(err.Error(), "repeats a member name") {
					t.Errorf("expected a repeated member to be refused, got %v", err)
				}
			},
		},
		"a signer, which JSON cannot hold": {
			json: `{"SignerConfiguration":{"Signer":{},"KeyID":"a"}}`,
			check: func(t *testing.T, _ SubordinateConfiguration, err error) {
				if err == nil || !strings.Contains(err.Error(), "cannot be decoded") {
					t.Errorf("expected a signer to be refused, got %v", err)
				}
			},
		},
		"a policy with a repeated operator": {
			json: `{"Policies":{"openid_relying_party":{"contacts":{"add":["a"],"add":["b"]}}}}`,
			check: func(t *testing.T, _ SubordinateConfiguration, err error) {
				if !errors.Is(err, ErrInvalidMetadata) {
					t.Errorf("expected the policy's own rules to apply, got %v", err)
				}
			},
		},
		"a value that is not an object": {
			json: `["not","an","object"]`,
			check: func(t *testing.T, _ SubordinateConfiguration, err error) {
				if err == nil || !strings.Contains(err.Error(), "must be a JSON object") {
					t.Errorf("expected a non-object to be refused, got %v", err)
				}
			},
		},
		"null members": {
			json: `{"CachedAt":0,"Policies":null,"JWKs":null,"SignerConfiguration":null}`,
			check: func(t *testing.T, decoded SubordinateConfiguration, err error) {
				if err != nil || decoded.SignerConfiguration != nil || len(decoded.JWKs.Keys) != 0 {
					t.Errorf("expected null members to leave their fields empty, got %+v, %v", decoded, err)
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var decoded SubordinateConfiguration
			err := json.Unmarshal([]byte(tc.json), &decoded)
			tc.check(t, decoded, err)
		})
	}
}
