package entity_configuration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_TheVerificationKeyComesFromTheExactKeysMember(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")

	realKey := headerJwkKey(t)
	attackerKey := headerJwkKey(t)
	realJwk := headerJwkPublicJwk(t, realKey.Public(), "leaf")
	attackerJwk := headerJwkPublicJwk(t, attackerKey.Public(), "leaf")

	tests := []struct {
		name      string
		reference string
		jwks      map[string]any
		expectErr string
	}{
		{
			name:      "the exact member carries the signing key",
			reference: "3.2 step 9",
			jwks:      map[string]any{"keys": []any{realJwk}},
		},
		{
			name:      "a folded member alongside the exact one does not supply the keys",
			reference: "RFC 7517 6",
			jwks:      map[string]any{"keys": []any{realJwk}, "keyſ": []any{attackerJwk}},
		},
		{
			name:      "a folded member alone supplies no keys",
			reference: "RFC 7517 6",
			jwks:      map[string]any{"keyſ": []any{realJwk}},
			expectErr: "missing the required 'keys' member",
		},
		{
			name:      "a spare key missing kty is ignored, the signing key still verifies",
			reference: "RFC 7517 5",
			jwks:      map[string]any{"keys": []any{realJwk, map[string]any{"kid": "retired", "x5c": []any{"AQAB"}}}},
		},
		{
			name:      "a spare EC key missing crv is ignored, the signing key still verifies",
			reference: "RFC 7517 5",
			jwks:      map[string]any{"keys": []any{realJwk, map[string]any{"kid": "retired", "kty": "EC", "x": "AQAB", "y": "AQAB"}}},
		},
		{
			name:      "a key set holding only an unusable key cannot verify",
			reference: "RFC 7517 5",
			jwks:      map[string]any{"keys": []any{map[string]any{"kid": "leaf"}}},
			expectErr: "contains no usable keys",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"iss":      string(leaf),
				"sub":      string(leaf),
				"iat":      time.Now().Unix(),
				"exp":      time.Now().Add(time.Hour).Unix(),
				"jwks":     tc.jwks,
				"metadata": map[string]any{},
			}
			token, err := jwt.New(realKey, map[string]any{"kid": "leaf", "alg": "RS256", "typ": "entity-statement+jwt"}, body, jwt.Opts{Algorithm: josemodel.RS256})
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			statement, err := Validate(context.Background(), model.Configuration{}, leaf, *token)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the configuration to be accepted, got %v", tc.reference, err)
				}
				if len(statement.JWKs.Keys) == 0 || statement.JWKs.Keys[0]["kid"] != "leaf" {
					t.Errorf("[%s] expected the keys of the exact member, got %v", tc.reference, statement.JWKs.Keys)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the configuration to be refused, got keys %v", tc.reference, statement.JWKs.Keys)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error naming %s, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func TestValidate_RefusesAStatementSignedWithAKeyPublishedForAnotherAlgorithm(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")

	key := headerJwkKey(t)

	tests := []struct {
		name      string
		reference string
		keyAlg    any
		expectErr string
	}{
		{name: "the algorithm the key is published for", reference: "RFC 7517 4.4", keyAlg: "RS256"},
		{name: "no published algorithm leaves the key unconstrained", reference: "RFC 7517 4.4", keyAlg: nil},
		{name: "another algorithm", reference: "RFC 7517 4.4", keyAlg: "PS256", expectErr: "does not match the 'alg' the selected key"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			published := headerJwkPublicJwk(t, key.Public(), "leaf")
			if tc.keyAlg == nil {
				delete(published, "alg")
			} else {
				published["alg"] = tc.keyAlg
			}

			body := map[string]any{
				"iss":      string(leaf),
				"sub":      string(leaf),
				"iat":      time.Now().Unix(),
				"exp":      time.Now().Add(time.Hour).Unix(),
				"jwks":     map[string]any{"keys": []any{published}},
				"metadata": map[string]any{},
			}
			token, err := jwt.New(key, map[string]any{"kid": "leaf", "alg": "RS256", "typ": "entity-statement+jwt"}, body, jwt.Opts{Algorithm: josemodel.RS256})
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			_, err = Validate(context.Background(), model.Configuration{}, leaf, *token)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the configuration to be accepted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the configuration to be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error naming %s, got %v", tc.reference, tc.expectErr, err)
			}
			if strings.Contains(err.Error(), "failed to verify JWT signature") {
				t.Errorf("[%s] a key published for another algorithm must not be reported as a signature failure, got %v", tc.reference, err)
			}
		})
	}
}

func TestNew_RefusesToPublishAKeyThatIsNotAUsableJWK(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		key       map[string]any
		expectErr string
	}{
		{name: "a key with no kty", reference: "RFC 7517 4.1", key: map[string]any{"kid": "retired", "x5c": []any{"AQAB"}}, expectErr: "'kty' member"},
		{name: "an EC key with no crv", reference: "RFC 7518 6.2.1.1", key: map[string]any{"kid": "retired", "kty": "EC", "x": "AQAB", "y": "AQAB"}, expectErr: "'crv' member"},
		{name: "a usable spare key", reference: "RFC 7517 4.1", key: map[string]any{"kid": "retired", "kty": "RSA", "n": "AQAB", "e": "AQAB"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signerConfiguration, _ := issuanceSigner(t)
			cfg := model.ServerConfiguration{
				EntityIdentifier:            "https://leaf.example.com",
				SignerConfiguration:         signerConfiguration,
				EntityConfigurationLifetime: time.Hour,
				EntityConfiguration: model.EntityStatement{
					JWKs: josemodel.Jwks{Keys: []map[string]any{tc.key}},
				},
			}

			_, issueErr := New(t.Context(), cfg)
			if tc.expectErr == "" {
				if issueErr != nil {
					t.Fatalf("[%s] expected the configuration to be published, got %v", tc.reference, issueErr)
				}
				return
			}
			if issueErr == nil {
				t.Fatalf("[%s] expected publication to be refused", tc.reference)
			}
			if !strings.Contains(issueErr.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error naming %s, got %v", tc.reference, tc.expectErr, issueErr)
			}
		})
	}
}
