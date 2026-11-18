package server

import (
	"crypto"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func validServerConfiguration(t *testing.T) model.ServerConfiguration {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	return model.ServerConfiguration{
		EntityIdentifier:            "https://entity.example.com",
		AuthorityHints:              []model.EntityIdentifier{"https://ta.example.com"},
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "own"},
		EntityConfigurationLifetime: time.Hour,
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
	}
}

func TestNewServer_RefusesAConfigurationThatCannotServe(t *testing.T) {
	ownerKey := map[string]any{"kty": "EC", "crv": "P-256", "kid": "owner", "x": "x", "y": "y"}
	privateKey := map[string]any{"kty": "EC", "crv": "P-256", "kid": "leaked", "x": "x", "y": "y", "d": "PRIVATE-MEMBER-VALUE"}

	tests := map[string]struct {
		change func(cfg *model.ServerConfiguration)
		says   string
	}{
		"a valid configuration": {change: func(*model.ServerConfiguration) {}},
		"an entity identifier that is not set yet": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityIdentifier = ""
		}},
		"a malformed entity identifier": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityIdentifier = "http://entity.example.com"
		}, says: "EntityIdentifier is not valid"},
		"no signer": {change: func(cfg *model.ServerConfiguration) {
			cfg.SignerConfiguration.Signer = nil
		}, says: "SignerConfiguration.Signer is nil"},
		"no key ID": {change: func(cfg *model.ServerConfiguration) {
			cfg.SignerConfiguration.KeyID = ""
		}, says: "SignerConfiguration.KeyID is empty"},
		"an algorithm this library cannot sign with": {change: func(cfg *model.ServerConfiguration) {
			cfg.SignerConfiguration.Algorithm = "HS256"
		}, says: "SignerConfiguration.Algorithm cannot be used"},
		"an empty accepted algorithm list": {change: func(cfg *model.ServerConfiguration) {
			cfg.SigningAlgorithms = []jwa.Algorithm{}
		}, says: "Configuration.SigningAlgorithms cannot be used"},
		"an entity configuration lifetime under a second": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfigurationLifetime = 500 * time.Millisecond
		}, says: "EntityConfigurationLifetime"},
		"a subordinate statement lifetime under a second": {change: func(cfg *model.ServerConfiguration) {
			cfg.IntermediateConfiguration.SubordinateStatementLifetime = 500 * time.Millisecond
		}, says: "IntermediateConfiguration.SubordinateStatementLifetime"},
		"an authority hint that is not an entity identifier": {change: func(cfg *model.ServerConfiguration) {
			cfg.AuthorityHints = []model.EntityIdentifier{"https://ta.example.com", "ta.example.com"}
		}, says: "AuthorityHints[1] is not an entity identifier"},
		"an authority hint naming this server": {change: func(cfg *model.ServerConfiguration) {
			cfg.AuthorityHints = []model.EntityIdentifier{"https://ta.example.com", "https://entity.example.com"}
		}, says: "AuthorityHints[1] names this server's own EntityIdentifier"},
		"an authority hint naming this server with a trailing slash": {change: func(cfg *model.ServerConfiguration) {
			cfg.AuthorityHints = []model.EntityIdentifier{"https://entity.example.com/"}
		}, says: "AuthorityHints[0] names this server's own EntityIdentifier"},
		"an authority hint naming another entity on the same host": {change: func(cfg *model.ServerConfiguration) {
			cfg.AuthorityHints = []model.EntityIdentifier{"https://entity.example.com/ta"}
		}},
		"a private key in published metadata": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
				"redirect_uris": []any{"https://entity.example.com/cb"},
				"jwks":          map[string]any{"keys": []any{privateKey}},
			}}
		}, says: "EntityConfiguration would publish private key material"},
		"a private key as a bare jwks in an extension type": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = &model.Metadata{Extensions: map[string]map[string]any{"x_custom": {"jwks": privateKey}}}
		}, says: "EntityConfiguration would publish private key material"},
		"a private key held by a trust mark owner": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{"https://tm.example.com/a": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: []map[string]any{ownerKey, privateKey}}}}
		}, says: "EntityConfiguration would publish private key material"},
		"a public key in published metadata": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
				"redirect_uris": []any{"https://entity.example.com/cb"},
				"jwks":          map[string]any{"keys": []any{ownerKey}},
			}}
		}},
		"a trust mark owner with no sub": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{"https://tm.example.com/a": {JWKs: josemodel.Jwks{Keys: []map[string]any{ownerKey}}}}
		}, says: `EntityConfiguration.TrustMarkOwners["https://tm.example.com/a"].Sub is empty`},
		"a trust mark owner whose sub is not an entity identifier": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{"https://tm.example.com/a": {Sub: "owner", JWKs: josemodel.Jwks{Keys: []map[string]any{ownerKey}}}}
		}, says: `EntityConfiguration.TrustMarkOwners["https://tm.example.com/a"].Sub is not an entity identifier`},
		"a trust mark owner with no keys": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{"https://tm.example.com/a": {Sub: "https://owner.example.com"}}
		}, says: `EntityConfiguration.TrustMarkOwners["https://tm.example.com/a"].JWKs holds no usable key`},
		"a trust mark owner whose only key is for encryption": {change: func(cfg *model.ServerConfiguration) {
			encryption := map[string]any{"kty": "EC", "crv": "P-256", "kid": "owner", "x": "x", "y": "y", "use": "enc"}
			cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{"https://tm.example.com/a": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: []map[string]any{encryption}}}}
		}, says: "JWKs holds no usable key"},
		"a trust mark owner with a usable key": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{"https://tm.example.com/a": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: []map[string]any{ownerKey}}}}
		}},
		"a trust mark issuer that is not an entity identifier": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.TrustMarkIssuers = map[string][]model.EntityIdentifier{"https://tm.example.com/a": {"issuer"}}
		}, says: `EntityConfiguration.TrustMarkIssuers["https://tm.example.com/a"][0] is not an entity identifier`},
		"metadata that sets a built-in type through Extensions": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = &model.Metadata{Extensions: map[string]map[string]any{"federation_entity": {"organization_name": "x"}}}
		}, says: "EntityConfiguration.Metadata cannot be written"},
		"metadata with a malformed parameter": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = &model.Metadata{OAuthClientMetadata: &model.OAuthClientMetadata{"jwks_uri": "http://insecure.example.com"}}
		}, says: "EntityConfiguration.Metadata is not valid"},
		"metadata whose jwks is a josemodel.Jwks, which is published as a JWK Set": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{"jwks": josemodel.Jwks{Keys: []map[string]any{ownerKey}}}}
		}},
		"metadata whose jwks holds its keys as a []map[string]any": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{"jwks": map[string]any{"keys": []map[string]any{ownerKey}}}}
		}},
		"metadata whose array parameter is a []string": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{"redirect_uris": []string{"https://entity.example.com/cb"}}}
		}},
		"metadata whose Go-typed value publishes as a malformed parameter": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = &model.Metadata{OAuthClientMetadata: &model.OAuthClientMetadata{"jwks_uri": model.EntityIdentifier("http://insecure.example.com")}}
		}, says: "EntityConfiguration.Metadata is not valid"},
		"incomplete metadata on an entity with a superior": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{"client_name": "Leaf RP"}}
		}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validServerConfiguration(t)
			tc.change(&cfg)
			server, err := NewServer(cfg)
			if tc.says == "" {
				if err != nil || server == nil {
					t.Fatalf("[#145] expected the configuration to be accepted, got %v", err)
				}
				return
			}
			if err == nil || server != nil {
				t.Fatalf("[#145] expected NewServer to refuse the configuration, got a server")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("[#145] expected the error to name %q, got %v", tc.says, err)
			}
			if strings.Contains(err.Error(), "PRIVATE-MEMBER-VALUE") {
				t.Errorf("expected the refusal not to repeat a private key value, got %v", err)
			}
		})
	}
}

func TestNewServer_ReportsEveryFaultAtOnce(t *testing.T) {
	cfg := validServerConfiguration(t)
	cfg.SignerConfiguration.Signer = nil
	cfg.SignerConfiguration.KeyID = ""
	cfg.AuthorityHints = []model.EntityIdentifier{"not-an-identifier"}

	_, err := NewServer(cfg)
	for _, fault := range []string{"SignerConfiguration.Signer is nil", "SignerConfiguration.KeyID is empty", "AuthorityHints[0]"} {
		if err == nil || !strings.Contains(err.Error(), fault) {
			t.Errorf("expected the error to name %q among every fault, got %v", fault, err)
		}
	}
}

func TestNewServer_ReportsAnIncompleteTrustAnchorWithoutRefusingIt(t *testing.T) {
	const message = "this trust anchor's own metadata does not pass the checks applied to resolved metadata"
	incomplete := &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{"client_name": "Anchor RP"}}

	tests := map[string]struct {
		change func(cfg *model.ServerConfiguration)
		logged bool
	}{
		"a trust anchor with incomplete metadata": {change: func(cfg *model.ServerConfiguration) {
			cfg.AuthorityHints = nil
			cfg.EntityConfiguration.Metadata = incomplete
		}, logged: true},
		"an entity with a superior and the same metadata": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = incomplete
		}},
		"a trust anchor with complete metadata": {change: func(cfg *model.ServerConfiguration) {
			cfg.AuthorityHints = nil
			cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://entity.example.com/cb"}}}
		}},
		"a trust anchor with complete metadata held in Go types": {change: func(cfg *model.ServerConfiguration) {
			cfg.AuthorityHints = nil
			cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
				"redirect_uris": []string{"https://entity.example.com/cb"},
				"jwks":          josemodel.Jwks{Keys: []map[string]any{{"kty": "EC", "crv": "P-256", "kid": "rp", "x": "x", "y": "y"}}},
			}}
		}},
		"a trust anchor whose identifier is not set yet": {change: func(cfg *model.ServerConfiguration) {
			cfg.AuthorityHints = nil
			cfg.EntityIdentifier = ""
			cfg.EntityConfiguration.Metadata = incomplete
		}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			logs := &lockedBuffer{}
			cfg := validServerConfiguration(t)
			cfg.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
			tc.change(&cfg)

			if _, err := NewServer(cfg); err != nil {
				t.Fatalf("[#145] expected incomplete metadata not to refuse the server, got %v", err)
			}
			if got := strings.Contains(logs.String(), message); got != tc.logged {
				t.Errorf("expected logged=%v, got %v: %s", tc.logged, got, logs.String())
			}
		})
	}
}

type signOnlyAtRequest struct {
	crypto.Signer
	t *testing.T
}

func (s signOnlyAtRequest) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	s.t.Errorf("expected NewServer not to sign, because a remote signer may not be reachable at startup")
	return nil, errors.New("not reachable")
}

func TestNewServer_RefusesASignerWhoseKeyCannotSignWithItsAlgorithm(t *testing.T) {
	signerFor := func(t *testing.T, algorithm jwa.Algorithm) crypto.Signer {
		t.Helper()
		signer, err := jws.GetSigner(algorithm, nil)
		if err != nil {
			t.Fatalf("failed to build the %s signer: %v", algorithm, err)
		}
		return signOnlyAtRequest{Signer: signer, t: t}
	}

	tests := []struct {
		name      string
		key       jwa.Algorithm
		algorithm string
		refused   bool
	}{
		{name: "an EC P-256 key declared ES256", key: jwa.ES256, algorithm: "ES256"},
		{name: "an EC P-384 key declared ES384", key: jwa.ES384, algorithm: "ES384"},
		{name: "an EC P-521 key declared ES512", key: jwa.ES512, algorithm: "ES512"},
		{name: "an RSA key declared RS256", key: jwa.RS256, algorithm: "RS256"},
		{name: "an RSA key declared PS512", key: jwa.RS256, algorithm: "PS512"},
		{name: "an Ed25519 key declared Ed25519", key: jwa.Ed25519, algorithm: "Ed25519"},
		{name: "an ML-DSA-65 key declared ML-DSA-65", key: jwa.MLDSA65, algorithm: "ML-DSA-65"},
		{name: "an EC P-256 key declared RS256", key: jwa.ES256, algorithm: "RS256", refused: true},
		{name: "an EC P-256 key declared PS256", key: jwa.ES256, algorithm: "PS256", refused: true},
		{name: "an EC P-256 key declared ES384", key: jwa.ES256, algorithm: "ES384", refused: true},
		{name: "an EC P-384 key declared ES256", key: jwa.ES384, algorithm: "ES256", refused: true},
		{name: "an RSA key declared ES256", key: jwa.RS256, algorithm: "ES256", refused: true},
		{name: "an Ed25519 key declared ES256", key: jwa.Ed25519, algorithm: "ES256", refused: true},
		{name: "an EC P-256 key declared Ed25519", key: jwa.ES256, algorithm: "Ed25519", refused: true},
		{name: "an ML-DSA-44 key declared ML-DSA-65", key: jwa.MLDSA44, algorithm: "ML-DSA-65", refused: true},
		{name: "an Ed25519 key declared ML-DSA-44", key: jwa.Ed25519, algorithm: "ML-DSA-44", refused: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validServerConfiguration(t)
			cfg.SignerConfiguration.Signer = signerFor(t, tc.key)
			cfg.SignerConfiguration.Algorithm = tc.algorithm

			server, err := NewServer(cfg)
			if !tc.refused {
				if err != nil || server == nil {
					t.Fatalf("[#145] expected the signer to be accepted, got %v", err)
				}
				return
			}
			if err == nil || server != nil {
				t.Fatalf("[#145] expected NewServer to refuse a signer whose key cannot sign with %s, got a server", tc.algorithm)
			}
			if !strings.Contains(err.Error(), "SignerConfiguration.Signer") || !strings.Contains(err.Error(), "SignerConfiguration.Algorithm") {
				t.Errorf("[#145] expected the error to name both fields, got %v", err)
			}
		})
	}
}

func TestNewServer_DoesNotJudgeTheSignerAgainstAnAlgorithmItAlreadyRefused(t *testing.T) {
	cfg := validServerConfiguration(t)
	cfg.SignerConfiguration.Algorithm = "HS256"

	_, err := NewServer(cfg)
	if err == nil {
		t.Fatalf("[#145] expected HS256 to be refused")
	}
	if strings.Contains(err.Error(), "SignerConfiguration.Signer") {
		t.Errorf("expected only the algorithm to be named, since the key cannot be judged against an algorithm this library never signs with, got %v", err)
	}
}
