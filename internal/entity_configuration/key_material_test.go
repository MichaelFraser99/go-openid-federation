package entity_configuration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
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
			token, err := jwt.New(key, map[string]any{"kid": "leaf", "alg": "RS256", "typ": "entity-statement+jwt"}, body, jwt.Opts{Algorithm: jwa.RS256})
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

func TestNew_RefusesToPublishMetadataKeysCarryingPrivateMembers(t *testing.T) {
	privateRSA := privateHalfOf(t, "RSA")
	privateEC := privateHalfOf(t, "EC")
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
	(*publicRSA)["kid"] = "rp-signing"

	privateJwksShapes := map[string]func(key map[string]any) any{
		"a decoded JSON key set":    func(key map[string]any) any { return map[string]any{"keys": []any{key}} },
		"a typed slice of key maps": func(key map[string]any) any { return map[string]any{"keys": []map[string]any{key}} },
		"a josemodel.Jwks value":    func(key map[string]any) any { return josemodel.Jwks{Keys: []map[string]any{key}} },
		"a josemodel.Jwks pointer":  func(key map[string]any) any { return &josemodel.Jwks{Keys: []map[string]any{key}} },
	}

	for shape, build := range privateJwksShapes {
		t.Run("a relying party publishing its private RSA key as "+shape, func(t *testing.T) {
			cfg := publishableConfiguration(t)
			rp := model.OpenIDRelyingPartyMetadata{
				"redirect_uris": []any{"https://rp.example.com/cb"},
				"jwks":          build(privateRSA),
			}
			cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &rp}

			signed, err := New(t.Context(), cfg)
			if err == nil {
				t.Fatalf("[RFC 7518 6.3.2] a key set written as %s is serialised the same way, so it must be refused the same way, got a published statement", shape)
			}
			if !strings.Contains(err.Error(), "private key members") {
				t.Errorf("[RFC 7518 6.3.2] expected the refusal to name the private members, got %v", err)
			}
			if signed != nil {
				t.Errorf("[RFC 7518 6.3.2] expected no statement to be published")
			}
		})
	}

	tests := []struct {
		name       string
		reference  string
		metadata   func() *model.Metadata
		expectErr  string
		expectType string
	}{
		{
			name:      "a relying party publishing only its public key",
			reference: "5.2.1",
			metadata: func() *model.Metadata {
				return &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
					"redirect_uris": []any{"https://rp.example.com/cb"},
					"jwks":          map[string]any{"keys": []any{*publicRSA}},
				}}
			},
		},
		{
			name:      "a relying party publishing its private RSA key",
			reference: "RFC 7518 6.3.2",
			metadata: func() *model.Metadata {
				return &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
					"redirect_uris": []any{"https://rp.example.com/cb"},
					"jwks":          map[string]any{"keys": []any{privateRSA}},
				}}
			},
			expectErr:  "private key members",
			expectType: "openid_relying_party",
		},
		{
			name:      "a provider publishing its private EC key",
			reference: "RFC 7518 6.2.2",
			metadata: func() *model.Metadata {
				return &model.Metadata{OpenIDConnectOpenIDProviderMetadata: &model.OpenIDConnectOpenIDProviderMetadata{
					"issuer":                                "https://op.example.com",
					"authorization_endpoint":                "https://op.example.com/authorize",
					"response_types_supported":              []any{"id_token"},
					"subject_types_supported":               []any{"public"},
					"id_token_signing_alg_values_supported": []any{"ES256"},
					"jwks":                                  map[string]any{"keys": []any{privateEC}},
				}}
			},
			expectErr:  "private key members",
			expectType: "openid_provider",
		},
		{
			name:      "a private key the lenient parse would drop for having no kty",
			reference: "RFC 7517 5",
			metadata: func() *model.Metadata {
				return &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
					"redirect_uris": []any{"https://rp.example.com/cb"},
					"jwks":          map[string]any{"keys": []any{map[string]any{"kid": "no-kty", "d": "SECRETEXPONENT"}}},
				}}
			},
			expectErr:  "private key members",
			expectType: "openid_relying_party",
		},
		{
			name:      "a private key the lenient parse would drop for a non-string kty",
			reference: "RFC 7517 4.1",
			metadata: func() *model.Metadata {
				return &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
					"redirect_uris": []any{"https://rp.example.com/cb"},
					"jwks":          map[string]any{"keys": []any{map[string]any{"kid": "numeric-kty", "kty": 1, "d": "SECRETEXPONENT"}}},
				}}
			},
			expectErr:  "private key members",
			expectType: "openid_relying_party",
		},
		{
			name:      "a private EC key the lenient parse would drop for having no crv",
			reference: "RFC 7518 6.2.1.1",
			metadata: func() *model.Metadata {
				return &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
					"redirect_uris": []any{"https://rp.example.com/cb"},
					"jwks":          map[string]any{"keys": []any{map[string]any{"kid": "no-crv", "kty": "EC", "x": "AQAB", "y": "AQAB", "d": "SECRETEXPONENT"}}},
				}}
			},
			expectErr:  "private key members",
			expectType: "openid_relying_party",
		},
		{
			name:      "a private key held beside the public one",
			reference: "RFC 7518 6.3.2",
			metadata: func() *model.Metadata {
				return &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
					"redirect_uris": []any{"https://rp.example.com/cb"},
					"jwks":          map[string]any{"keys": []any{*publicRSA, privateRSA}},
				}}
			},
			expectErr:  "private key members",
			expectType: "openid_relying_party",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := publishableConfiguration(t)
			cfg.EntityConfiguration.Metadata = tc.metadata()

			signed, err := New(t.Context(), cfg)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the public key to be published, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] a metadata 'jwks' is served at the same well-known URL as the claim, so it must be held to the same rule", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
			if !strings.Contains(err.Error(), tc.expectType) {
				t.Errorf("[%s] expected the refusal to name the entity type %q, got %v", tc.reference, tc.expectType, err)
			}
			if signed != nil {
				t.Errorf("[%s] expected no statement to be published", tc.reference)
			}
		})
	}
}

func TestValidate_APeerPublishingPrivateMembersIsLoggedEvenWhenTheKeyIsUnusable(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")

	tests := []struct {
		name      string
		reference string
		spare     map[string]any
		expectLog string
	}{
		{
			name:      "a dropped entry with no kty carrying a private exponent",
			reference: "RFC 7517 5",
			spare:     map[string]any{"kid": "retired", "d": "AQAB", "p": "AQAB"},
			expectLog: "d",
		},
		{
			name:      "a dropped EC entry with no crv carrying a private exponent",
			reference: "RFC 7517 5",
			spare:     map[string]any{"kid": "retired-ec", "kty": "EC", "x": "AQAB", "y": "AQAB", "d": "AQAB"},
			expectLog: "d",
		},
		{
			name:      "a dropped entry carrying a symmetric key",
			reference: "RFC 7518 6.4.1",
			spare:     map[string]any{"kid": "retired-oct", "k": "AQAB"},
			expectLog: "k",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := headerJwkKey(t)
			published := headerJwkPublicJwk(t, key.Public(), "leaf")

			body := map[string]any{
				"iss":      string(leaf),
				"sub":      string(leaf),
				"iat":      time.Now().Unix(),
				"exp":      time.Now().Add(time.Hour).Unix(),
				"jwks":     map[string]any{"keys": []any{published, tc.spare}},
				"metadata": map[string]any{},
			}
			token, err := jwt.New(key, map[string]any{"kid": "leaf", "alg": "RS256", "typ": "entity-statement+jwt"}, body, jwt.Opts{Algorithm: jwa.RS256})
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			var logs bytes.Buffer
			cfg := model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}

			if _, err = Validate(t.Context(), cfg, leaf, *token); err != nil {
				t.Fatalf("[%s] a dropped entry must not deny service over the peer's statement, got %v", tc.reference, err)
			}
			if !strings.Contains(logs.String(), "private key material") {
				t.Fatalf("[%s] an entry the lenient parse drops is the realistic shape of an accidental key dump, so the log must see it before the filter: %s", tc.reference, logs.String())
			}
			if !loggedMember(t, logs.String(), tc.expectLog) {
				t.Errorf("[%s] expected the log's own members attribute to name %q, got %s", tc.reference, tc.expectLog, logs.String())
			}
		})
	}
}

func TestNew_RefusesToPublishTrustMarkOwnerKeysCarryingPrivateMembers(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		owners    map[string]model.TrustMarkOwner
		expectErr string
	}{
		{
			name:      "an owner publishing only its public key",
			reference: "3.1.1",
			owners: map[string]model.TrustMarkOwner{
				"https://tm.example.com/a": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: []map[string]any{{"kid": "owner", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}}}},
			},
		},
		{
			name:      "an owner publishing its private exponent",
			reference: "RFC 7518 6.2.2",
			owners: map[string]model.TrustMarkOwner{
				"https://tm.example.com/a": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: []map[string]any{{"kid": "owner", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "d": "SECRETEXPONENT"}}}},
			},
			expectErr: "private key members",
		},
		{
			name:      "an owner publishing a symmetric key",
			reference: "RFC 7518 6.4.1",
			owners: map[string]model.TrustMarkOwner{
				"https://tm.example.com/b": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: []map[string]any{{"kid": "owner", "kty": "oct", "k": "SECRETSYMMETRIC"}}}},
			},
			expectErr: "private key members",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := publishableConfiguration(t)
			cfg.EntityConfiguration.TrustMarkOwners = tc.owners

			signed, err := New(t.Context(), cfg)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the public key to be published, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] a trust mark owner's key is published in this entity configuration, so it must be held to the same rule", tc.reference)
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

func TestNew_DoesNotPublishASubordinateSignerKeyBelowItsAlgorithmsMinimumModulus(t *testing.T) {
	tests := []struct {
		name        string
		reference   string
		bits        int
		algorithm   string
		expectInSet bool
	}{
		{name: "a 2048 bit subordinate signer for RS256", reference: "RFC 7518 3.3", bits: 2048, algorithm: "RS256", expectInSet: true},
		{name: "a 1024 bit subordinate signer for RS256", reference: "RFC 7518 3.3", bits: 1024, algorithm: "RS256", expectInSet: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			override, err := rsa.GenerateKey(rand.Reader, tc.bits)
			if err != nil {
				t.Fatal(err)
			}

			signerConfiguration, _ := issuanceSigner(t)
			var logs bytes.Buffer
			cfg := model.ServerConfiguration{
				EntityIdentifier:            "https://ta.example.com",
				SignerConfiguration:         signerConfiguration,
				EntityConfigurationLifetime: time.Hour,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
			}
			cfg.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			cfg.IntermediateConfiguration.AddSubordinate("https://leaf.example.com", &model.SubordinateConfiguration{
				SignerConfiguration: &model.SignerConfiguration{Signer: override, KeyID: "subordinate-signer", Algorithm: tc.algorithm},
			})

			signed, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("[%s] one undersized subordinate signer must not take down this entity's own configuration, got %v", tc.reference, err)
			}

			parts := strings.Split(*signed, ".")
			if len(parts) != 3 {
				t.Fatalf("[%s] expected a compact JWS", tc.reference)
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("[%s] failed to decode the published payload: %v", tc.reference, err)
			}

			inSet := strings.Contains(string(payload), "subordinate-signer")
			if inSet != tc.expectInSet {
				t.Errorf("[%s] expected the subordinate signer key published: %v, got %v", tc.reference, tc.expectInSet, inSet)
			}
			if !tc.expectInSet && !strings.Contains(logs.String(), "not publishing a subordinate signer key") {
				t.Errorf("[%s] an operator must be told the key was left out, got logs %s", tc.reference, logs.String())
			}
		})
	}
}

func TestValidate_AStatementThatFailsAnIdentityCheckIsNotLoggedAsALeak(t *testing.T) {
	const (
		victim   = model.EntityIdentifier("https://victim.example.com")
		attacker = model.EntityIdentifier("https://attacker.example.com")
	)

	tests := []struct {
		name      string
		reference string
		iss       model.EntityIdentifier
		sub       model.EntityIdentifier
		signWith  string
		expectLog bool
	}{
		{name: "the victim's own configuration", reference: "RFC 7518 6.2.2", iss: victim, sub: victim, signWith: "victim", expectLog: true},
		{name: "a configuration signed by another key", reference: "3.2", iss: victim, sub: victim, signWith: "forger"},
		{name: "a configuration whose iss is another entity", reference: "3.2", iss: attacker, sub: victim, signWith: "victim"},
		{name: "a configuration whose sub is another entity", reference: "3.2", iss: victim, sub: attacker, signWith: "victim"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			victimKey := headerJwkKey(t)
			forgerKey := headerJwkKey(t)

			published := headerJwkPublicJwk(t, victimKey.Public(), "leaf")
			published["d"] = "AQAB"

			signer := victimKey
			if tc.signWith == "forger" {
				signer = forgerKey
			}

			token, err := jwt.New(signer, map[string]any{"kid": "leaf", "alg": "RS256", "typ": "entity-statement+jwt"}, map[string]any{
				"iss":      string(tc.iss),
				"sub":      string(tc.sub),
				"iat":      time.Now().Unix(),
				"exp":      time.Now().Add(time.Hour).Unix(),
				"jwks":     map[string]any{"keys": []any{published}},
				"metadata": map[string]any{},
			}, jwt.Opts{Algorithm: jwa.RS256})
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			var logs bytes.Buffer
			cfg := model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}

			_, err = Validate(t.Context(), cfg, victim, *token)
			if tc.expectLog && err != nil {
				t.Fatalf("[%s] expected the victim's own configuration to validate, got %v", tc.reference, err)
			}
			if !tc.expectLog && err == nil {
				t.Fatalf("[%s] expected the configuration to be refused", tc.reference)
			}

			logged := strings.Contains(logs.String(), "private key material")
			if logged != tc.expectLog {
				t.Fatalf("[%s] anyone able to answer a fetch for an entity can serve a statement, so a leak must be attributed only once every identity check passes: logged %v, logs %s", tc.reference, logged, logs.String())
			}
		})
	}
}

func loggedMember(t *testing.T, raw, member string) bool {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil {
			continue
		}
		if record["msg"] != "a received key set carries private key material" {
			continue
		}
		members, _ := record["members"].([]any)
		if slices.Contains(members, any(member)) {
			return true
		}
	}
	return false
}
