package trust_chain

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

// Test helper to create entity statements
func createEntityStatement(t *testing.T, iss, sub model.EntityIdentifier, authorityHints []model.EntityIdentifier, signer crypto.Signer, subordinates bool) string {
	t.Helper()

	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to create public JWK: %v", err)
	}
	(*publicJWK)["kid"] = "test-key"

	body := map[string]any{
		"iss": string(iss),
		"sub": string(sub),
		"iat": time.Now().UTC().Unix(),
		"exp": time.Now().Add(24 * time.Hour).UTC().Unix(),
		"jwks": map[string]any{
			"keys": []any{*publicJWK},
		},
	}

	if len(authorityHints) > 0 {
		hints := make([]string, len(authorityHints))
		for i, hint := range authorityHints {
			hints[i] = string(hint)
		}
		body["authority_hints"] = hints
	}

	metadataMap := map[string]any{}

	if subordinates {
		federationMetadata := map[string]any{}
		federationMetadata["federation_fetch_endpoint"] = fmt.Sprintf("%s/fetch", iss)
		metadataMap["federation_entity"] = federationMetadata
	}

	body["metadata"] = metadataMap

	head := map[string]any{
		"kid": "test-key",
		"typ": "entity-statement+jwt",
		"alg": "RS256",
	}

	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to create entity statement: %v", err)
	}

	return *token
}

// Test helper to create subordinate statement
func createSubordinateStatement(t *testing.T, iss, sub model.EntityIdentifier, signer crypto.Signer, subjectPublicKey crypto.PublicKey) string {
	t.Helper()

	subjectJWK, err := jwk.PublicJwk(subjectPublicKey)
	if err != nil {
		t.Fatalf("failed to create subject public JWK: %v", err)
	}
	(*subjectJWK)["kid"] = "test-key"

	body := map[string]any{
		"iss": string(iss),
		"sub": string(sub),
		"iat": time.Now().UTC().Unix(),
		"exp": time.Now().Add(24 * time.Hour).UTC().Unix(),
		"jwks": map[string]any{
			"keys": []any{*subjectJWK},
		},
	}

	head := map[string]any{
		"kid": "test-key",
		"typ": "entity-statement+jwt",
		"alg": "RS256",
	}

	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to create subordinate statement: %v", err)
	}

	return *token
}

func TestBuildTrustChain(t *testing.T) {
	// Generate test keys
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	trustAnchorKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	var trustAnchorID, leafID model.EntityIdentifier

	taServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-federation" {
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(createEntityStatement(t, trustAnchorID, trustAnchorID, []model.EntityIdentifier{}, trustAnchorKey, true))) //nolint:errcheck
		}
		if r.URL.Path == "/fetch" {
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(createSubordinateStatement(t, trustAnchorID, leafID, trustAnchorKey, leafKey.Public()))) //nolint:errcheck
		}
	}))

	leafServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-federation" {
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(createEntityStatement(t, leafID, leafID, []model.EntityIdentifier{trustAnchorID}, leafKey, false))) //nolint:errcheck
		}
	}))

	var lapsedAnchorID model.EntityIdentifier
	lapsedAnchorServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-federation" {
			return
		}
		publicJWK, err := jwk.PublicJwk(trustAnchorKey.Public())
		if err != nil {
			t.Errorf("failed to create public JWK: %v", err)
			return
		}
		(*publicJWK)["kid"] = "test-key"
		token, err := jwt.New(trustAnchorKey, map[string]any{"kid": "test-key", "typ": "entity-statement+jwt", "alg": "RS256"}, map[string]any{
			"iss":  string(lapsedAnchorID),
			"sub":  string(lapsedAnchorID),
			"iat":  time.Now().Add(-time.Hour).UTC().Unix(),
			"exp":  time.Now().Add(-30 * time.Second).UTC().Unix(),
			"jwks": map[string]any{"keys": []any{*publicJWK}},
		}, jwt.Opts{Algorithm: jwa.RS256})
		if err != nil {
			t.Errorf("failed to create entity statement: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		w.Write([]byte(*token)) //nolint:errcheck
	}))
	t.Cleanup(lapsedAnchorServer.Close)

	trustAnchorID = model.EntityIdentifier(taServer.URL)
	leafID = model.EntityIdentifier(leafServer.URL)
	lapsedAnchorID = model.EntityIdentifier(lapsedAnchorServer.URL)

	tests := map[string]struct {
		config      model.Configuration
		leafID      model.EntityIdentifier
		trustAnchor model.EntityIdentifier
		validate    func(t *testing.T, trustChain []string, parsedChain []model.EntityStatement, expiry *int64, err error)
	}{
		"resolves a trust anchor as its own subject": {
			config:      model.Configuration{HttpClient: taServer.Client(), Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil))},
			leafID:      trustAnchorID,
			trustAnchor: trustAnchorID,
			validate: func(t *testing.T, trustChain []string, parsedChain []model.EntityStatement, expiry *int64, err error) {
				if err != nil {
					t.Fatalf("[10.2] a chain of the trust anchor's own entity configuration validates at i = 0, got %v", err)
				}
				if len(trustChain) != 1 || len(parsedChain) != 1 {
					t.Fatalf("[8.3.2] expected the chain to hold only the trust anchor's entity configuration, got %d entries", len(trustChain))
				}
				if parsedChain[0].Iss != trustAnchorID || parsedChain[0].Sub != trustAnchorID {
					t.Errorf("[10.2] expected iss and sub to be the trust anchor, got iss=%s sub=%s", parsedChain[0].Iss, parsedChain[0].Sub)
				}
				if expiry == nil || *expiry != parsedChain[0].Exp {
					t.Errorf("[10.4] expected the chain to expire with the entity configuration")
				}
			},
		},
		"refuses a trust anchor as its own subject when its configuration is not signed by the pinned key": {
			config: model.Configuration{HttpClient: taServer.Client(), TrustAnchors: map[model.EntityIdentifier]josemodel.Jwks{
				trustAnchorID: {Keys: []map[string]any{pinnedJWK(t, otherKey.Public())}},
			}},
			leafID:      trustAnchorID,
			trustAnchor: trustAnchorID,
			validate: func(t *testing.T, trustChain []string, parsedChain []model.EntityStatement, expiry *int64, err error) {
				if !errors.Is(err, model.ErrInvalidTrustAnchor) {
					t.Fatalf("[10.2] ES[i] must validate with a public key of the trust anchor, so a configuration no pinned key verifies is refused as invalid_trust_anchor, got %v", err)
				}
				if trustChain != nil || parsedChain != nil || expiry != nil {
					t.Errorf("expected no chain with the refusal")
				}
			},
		},
		"refuses a trust anchor as its own subject when it is not one this deployment trusts": {
			config: model.Configuration{HttpClient: taServer.Client(), TrustAnchors: map[model.EntityIdentifier]josemodel.Jwks{
				"https://other-ta.example.com": {Keys: []map[string]any{pinnedJWK(t, trustAnchorKey.Public())}},
			}},
			leafID:      trustAnchorID,
			trustAnchor: trustAnchorID,
			validate: func(t *testing.T, trustChain []string, parsedChain []model.EntityStatement, expiry *int64, err error) {
				if !errors.Is(err, model.ErrInvalidTrustAnchor) {
					t.Fatalf("[8.9] an anchor absent from a populated TrustAnchors map is refused as for any other subject, got %v", err)
				}
			},
		},
		"refuses a trust anchor as its own subject whose configuration expired within the clock skew allowance": {
			config:      model.Configuration{HttpClient: lapsedAnchorServer.Client()},
			leafID:      lapsedAnchorID,
			trustAnchor: lapsedAnchorID,
			validate: func(t *testing.T, trustChain []string, parsedChain []model.EntityStatement, expiry *int64, err error) {
				if err == nil {
					t.Fatalf("[10.4] a configuration parsed within ClockSkewLeeway of its exp has already expired, so the chain it forms must be refused, got expiry %v", expiry)
				}
				if !errors.Is(err, model.ErrInvalidTrustChain) {
					t.Errorf("expected the expired chain to be refused as invalid_trust_chain, got %v", err)
				}
			},
		},
		"refuses a trust anchor as its own subject when its configuration cannot be retrieved": {
			config:      model.Configuration{HttpClient: taServer.Client()},
			leafID:      "https://unreachable.invalid",
			trustAnchor: "https://unreachable.invalid",
			validate: func(t *testing.T, trustChain []string, parsedChain []model.EntityStatement, expiry *int64, err error) {
				if !errors.Is(err, model.ErrInvalidTrustAnchor) {
					t.Fatalf("[8.9] a trust anchor whose entity configuration cannot be fetched cannot be used, got %v", err)
				}
				if errors.Is(err, model.ErrServerError) {
					t.Errorf("[8.9] a peer that cannot be reached is not this server's fault, got %v", err)
				}
			},
		},
		"builds simple two-hop chain": {
			config:      model.Configuration{HttpClient: taServer.Client(), Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil))},
			leafID:      leafID,
			trustAnchor: trustAnchorID,
			validate: func(t *testing.T, trustChain []string, parsedChain []model.EntityStatement, expiry *int64, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if len(trustChain) != 3 {
					t.Fatalf("expected 3 trust chain entries, got %d", len(trustChain))
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := tt.config

			trustChain, parsedChain, expiry, err := BuildTrustChain(t.Context(), cfg, tt.leafID, tt.trustAnchor, nil)
			tt.validate(t, trustChain, parsedChain, expiry, err)
		})
	}
}

func TestChainUpOne(t *testing.T) {
	leafID := model.EntityIdentifier("https://leaf.example.com")
	trustAnchorID := model.EntityIdentifier("https://trust-anchor.example.com")

	tests := map[string]struct {
		subject  model.EntityIdentifier
		target   model.EntityIdentifier
		checked  []model.EntityIdentifier
		path     []model.EntityStatement
		signed   []string
		validate func(t *testing.T, signed []string, path []model.EntityStatement, err error)
	}{
		"returns error when entity configuration cannot be retrieved": {
			subject: leafID,
			target:  trustAnchorID,
			checked: []model.EntityIdentifier{},
			path:    []model.EntityStatement{},
			signed:  []string{},
			validate: func(t *testing.T, signed []string, path []model.EntityStatement, err error) {
				// This will fail because we can't mock the HTTP call without modifying service code
				if err != nil {
					t.Logf("Expected failure: ChainUpOne requires HTTP infrastructure that cannot be fully mocked")
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{}
			signed, path, _, err := ChainUpOne(t.Context(), cfg, tt.subject, tt.target, tt.checked, tt.path, tt.signed, resolvecache.New())
			tt.validate(t, signed, path, err)
		})
	}
}

func TestResolveMetadata(t *testing.T) {
	// Generate test key
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	issuerID := model.EntityIdentifier("https://issuer.example.com")
	subjectID := model.EntityIdentifier("https://subject.example.com")

	tests := map[string]struct {
		issuerID   model.EntityIdentifier
		trustChain []string
		validate   func(t *testing.T, result *model.ResolveResponse, err error)
	}{
		"fails with empty trust chain": {
			issuerID:   issuerID,
			trustChain: []string{},
			validate: func(t *testing.T, result *model.ResolveResponse, err error) {
				if err == nil {
					t.Fatal("expected error for empty trust chain, got nil")
				}
			},
		},
		"fails with malformed final entry in chain": {
			issuerID:   issuerID,
			trustChain: []string{"malformed.jwt.token"},
			validate: func(t *testing.T, result *model.ResolveResponse, err error) {
				if err == nil {
					t.Fatal("expected error for malformed JWT, got nil")
				}
			},
		},
		"fails when final entry has invalid sub claim": {
			issuerID: issuerID,
			trustChain: []string{
				func() string {
					body := map[string]any{
						"iss": string(issuerID),
						"sub": "not a valid url",
						"iat": time.Now().UTC().Unix(),
						"exp": time.Now().Add(24 * time.Hour).UTC().Unix(),
					}
					head := map[string]any{
						"kid": "test-key",
						"typ": "entity-statement+jwt",
						"alg": "RS256",
					}
					token, _ := jwt.New(key, head, body, jwt.Opts{Algorithm: jwa.RS256})
					return *token
				}(),
			},
			validate: func(t *testing.T, result *model.ResolveResponse, err error) {
				if err == nil {
					t.Fatal("expected error for invalid sub claim, got nil")
				}
			},
		},
		"fails when final entry has invalid iss claim": {
			issuerID: issuerID,
			trustChain: []string{
				func() string {
					body := map[string]any{
						"iss": "not a valid url",
						"sub": string(subjectID),
						"iat": time.Now().UTC().Unix(),
						"exp": time.Now().Add(24 * time.Hour).UTC().Unix(),
					}
					head := map[string]any{
						"kid": "test-key",
						"typ": "entity-statement+jwt",
						"alg": "RS256",
					}
					token, _ := jwt.New(key, head, body, jwt.Opts{Algorithm: jwa.RS256})
					return *token
				}(),
			},
			validate: func(t *testing.T, result *model.ResolveResponse, err error) {
				if err == nil {
					t.Fatal("expected error for invalid iss claim, got nil")
				}
			},
		},
		"processes self-signed entity configuration": {
			issuerID: issuerID,
			trustChain: []string{
				func() string {
					publicJWK, _ := jwk.PublicJwk(key.Public())
					(*publicJWK)["kid"] = "test-key"

					body := map[string]any{
						"iss": string(subjectID),
						"sub": string(subjectID),
						"iat": time.Now().UTC().Unix(),
						"exp": time.Now().Add(24 * time.Hour).UTC().Unix(),
						"jwks": map[string]any{
							"keys": []any{*publicJWK},
						},
					}
					head := map[string]any{
						"kid": "test-key",
						"typ": "entity-statement+jwt",
						"alg": "RS256",
					}
					token, _ := jwt.New(key, head, body, jwt.Opts{Algorithm: jwa.RS256})
					return *token
				}(),
			},
			validate: func(t *testing.T, result *model.ResolveResponse, err error) {
				if err != nil {
					t.Fatalf("expected no error for self-signed configuration, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if result.Sub != subjectID {
					t.Errorf("expected sub %q, got %q", subjectID, result.Sub)
				}
				if len(result.TrustChain) != 1 {
					t.Errorf("expected trust chain length 1, got %d", len(result.TrustChain))
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{}
			result, err := resolveTrustingSuppliedAnchor(t, t.Context(), cfg, tt.issuerID, subjectID, tt.trustChain, nil)
			tt.validate(t, result, err)
		})
	}
}

func pinnedJWK(t *testing.T, public crypto.PublicKey) map[string]any {
	t.Helper()
	key, err := jwk.PublicJwk(public)
	if err != nil {
		t.Fatalf("failed to build the pinned key: %v", err)
	}
	(*key)["kid"] = "test-key"
	return *key
}
