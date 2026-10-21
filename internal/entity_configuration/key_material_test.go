package entity_configuration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func publishableConfiguration(t *testing.T, keys ...map[string]any) model.ServerConfiguration {
	t.Helper()
	signerConfiguration, _ := issuanceSigner(t)
	cfg := model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		SignerConfiguration:         signerConfiguration,
		EntityConfigurationLifetime: time.Hour,
	}
	if len(keys) > 0 {
		cfg.EntityConfiguration = model.EntityStatement{JWKs: josemodel.Jwks{Keys: keys}}
	}
	return cfg
}

func privateHalfOf(t *testing.T, kty string) map[string]any {
	t.Helper()
	switch kty {
	case "RSA":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		published, err := jwk.PrivateJwk(key)
		if err != nil {
			t.Fatal(err)
		}
		(*published)["kid"] = "configured"
		return *published
	case "EC":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		published, err := jwk.PrivateJwk(key)
		if err != nil {
			t.Fatal(err)
		}
		(*published)["kid"] = "configured"
		return *published
	}
	t.Fatalf("unsupported kty %q", kty)
	return nil
}

func TestNew_RefusesToPublishAKeyCarryingPrivateMembers(t *testing.T) {
	publicRSA, err := jwk.PublicJwk(func() *rsa.PublicKey {
		key, genErr := rsa.GenerateKey(rand.Reader, 2048)
		if genErr != nil {
			t.Fatal(genErr)
		}
		return &key.PublicKey
	}())
	if err != nil {
		t.Fatal(err)
	}
	(*publicRSA)["kid"] = "configured"

	tests := []struct {
		name      string
		reference string
		key       map[string]any
		expectErr string
	}{
		{name: "the public half of an RSA key", reference: "RFC 7518 6.3.1", key: *publicRSA},
		{name: "the private half of an RSA key", reference: "RFC 7518 6.3.2", key: privateHalfOf(t, "RSA"), expectErr: "private key members"},
		{name: "the private half of an EC key", reference: "RFC 7518 6.2.2", key: privateHalfOf(t, "EC"), expectErr: "private key members"},
		{
			name:      "a symmetric key",
			reference: "RFC 7518 6.4.1",
			key:       map[string]any{"kid": "configured", "kty": "oct", "k": "AQAB"},
			expectErr: "private key members",
		},
		{
			name:      "an OKP key carrying its private exponent",
			reference: "RFC 8037 2",
			key:       map[string]any{"kid": "configured", "kty": "OKP", "crv": "Ed25519", "x": "AQAB", "d": "AQAB"},
			expectErr: "private key members",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := New(t.Context(), publishableConfiguration(t, tc.key))
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the public key to be published, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the configuration to be refused, got a published statement", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
			for _, member := range model.PrivateJWKMembers(tc.key) {
				if value, ok := tc.key[member].(string); ok && signed != nil && strings.Contains(*signed, value) {
					t.Errorf("[%s] the private member %q reached the published statement", tc.reference, member)
				}
			}
		})
	}
}

func TestNew_RefusesToPublishAnRSAKeyBelowItsAlgorithmsMinimumSize(t *testing.T) {
	sized := func(t *testing.T, bits int, alg any) map[string]any {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		published := map[string]any{
			"kid": "configured",
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}
		if alg != nil {
			published["alg"] = alg
		}
		return published
	}

	tests := []struct {
		name      string
		reference string
		key       map[string]any
		expectErr string
	}{
		{name: "a 2048 bit key published for RS256", reference: "RFC 7518 3.3", key: sized(t, 2048, "RS256")},
		{name: "a 1024 bit key published for RS256", reference: "RFC 7518 3.3", key: sized(t, 1024, "RS256"), expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit key published for PS512", reference: "RFC 7518 3.5", key: sized(t, 1024, "PS512"), expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit key published for no algorithm", reference: "RFC 7517 4.4", key: sized(t, 1024, nil)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(t.Context(), publishableConfiguration(t, tc.key))
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the key to be published, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the configuration to be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func TestValidate_APeerPublishingPrivateMembersIsLoggedAndStillVerified(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")

	tests := []struct {
		name       string
		reference  string
		extra      map[string]any
		expectLog  bool
		expectName string
	}{
		{name: "a peer publishing only its public key", reference: "RFC 7518 6.3.1", extra: nil},
		{
			name:       "a peer publishing its signing key's private exponent",
			reference:  "RFC 7518 6.3.2",
			extra:      map[string]any{"d": "AQAB", "p": "AQAB"},
			expectLog:  true,
			expectName: "d",
		},
		{
			name:       "a peer publishing a retired symmetric key alongside it",
			reference:  "RFC 7518 6.4.1",
			extra:      map[string]any{"k": "AQAB"},
			expectLog:  true,
			expectName: "k",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := headerJwkKey(t)
			published := headerJwkPublicJwk(t, key.Public(), "leaf")
			for member, value := range tc.extra {
				published[member] = value
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

			var logs bytes.Buffer
			cfg := model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}

			if _, err = Validate(t.Context(), cfg, leaf, *token); err != nil {
				t.Fatalf("[%s] a peer's own mistake must not deny service over its statement, got %v", tc.reference, err)
			}

			logged := strings.Contains(logs.String(), "private key material")
			if logged != tc.expectLog {
				t.Fatalf("[%s] expected the private material to be logged: %v, got logs %s", tc.reference, tc.expectLog, logs.String())
			}
			if tc.expectLog && !strings.Contains(logs.String(), tc.expectName) {
				t.Errorf("[%s] expected the log to name the member %q, got %s", tc.reference, tc.expectName, logs.String())
			}
		})
	}
}
