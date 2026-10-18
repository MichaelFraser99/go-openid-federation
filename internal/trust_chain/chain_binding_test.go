package trust_chain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func bindingKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

func TestResolveMetadata_BindsSubjectToTheKeyRegisteredByItsSuperior(t *testing.T) {
	const (
		leafID  = model.EntityIdentifier("https://leaf.example.com")
		taID    = model.EntityIdentifier("https://ta.example.com")
		otherID = model.EntityIdentifier("https://other.example.com")
	)

	leafKey := bindingKey(t)
	attackerKey := bindingKey(t)
	taKey := bindingKey(t)

	taEC := createEntityStatement(t, taID, taID, nil, taKey, true)
	subordinateStatement := createSubordinateStatement(t, taID, leafID, taKey, leafKey.Public())

	tests := []struct {
		name           string
		authorityHints []model.EntityIdentifier
		leafSigner     *rsa.PrivateKey
		expectErr      bool
	}{
		{
			name:           "subject signed by the key its superior registered is accepted",
			authorityHints: []model.EntityIdentifier{taID},
			leafSigner:     leafKey,
			expectErr:      false,
		},
		{
			name:           "subject signed by another key under the registered kid is rejected",
			authorityHints: []model.EntityIdentifier{taID},
			leafSigner:     attackerKey,
			expectErr:      true,
		},
		{
			name:           "subordinate statement issuer absent from the subject's authority_hints is rejected",
			authorityHints: []model.EntityIdentifier{otherID},
			leafSigner:     leafKey,
			expectErr:      true,
		},
		{
			name:           "subject with no authority_hints is rejected",
			authorityHints: nil,
			leafSigner:     leafKey,
			expectErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leafEC := createEntityStatement(t, leafID, leafID, tc.authorityHints, tc.leafSigner, false)
			chain := []string{leafEC, subordinateStatement, taEC}

			result, err := ResolveMetadata(context.Background(), model.Configuration{}, leafID, chain, resolvecache.New())
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected chain to be rejected, got resolved metadata for sub %q", result.Sub)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected chain to resolve, got error: %v", err)
			}
			if result.Sub != leafID {
				t.Fatalf("expected sub %q, got %q", leafID, result.Sub)
			}
		})
	}
}

func TestResolveMetadata_FetchesOmittedTrustAnchorConfiguration(t *testing.T) {
	tp := newTopo(t, map[string][]string{
		"leaf": {"ta"},
		"ta":   {},
	})

	cfg := model.Configuration{HttpClient: tp.server.Client()}

	leafEC := createEntityStatement(t, tp.id["leaf"], tp.id["leaf"], []model.EntityIdentifier{tp.id["ta"]}, tp.keys["leaf"], false)
	subordinateStatement := createSubordinateStatement(t, tp.id["ta"], tp.id["leaf"], tp.keys["ta"], tp.keys["leaf"].Public())

	result, err := ResolveMetadata(context.Background(), cfg, tp.id["leaf"], []string{leafEC, subordinateStatement}, resolvecache.New())
	if err != nil {
		t.Fatalf("expected chain with omitted trust anchor configuration to resolve, got error: %v", err)
	}
	if result.Sub != tp.id["leaf"] {
		t.Fatalf("expected sub %q, got %q", tp.id["leaf"], result.Sub)
	}

	tp.mu.Lock()
	leafHits, taHits := tp.hits["leaf"], tp.hits["ta"]
	tp.mu.Unlock()

	if taHits != 1 {
		t.Errorf("expected the trust anchor's entity configuration to be fetched once, got %d fetches", taHits)
	}
	if leafHits != 0 {
		t.Errorf("expected the subject's entity configuration not to be fetched, got %d fetches", leafHits)
	}
}

func TestBuildTrustChain_BindsSubjectToTheKeyRegisteredByItsSuperior(t *testing.T) {
	leafKey := bindingKey(t)
	attackerKey := bindingKey(t)
	taKey := bindingKey(t)

	var leafID, taID model.EntityIdentifier
	var leafSigner *rsa.PrivateKey

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/leaf/.well-known/openid-federation":
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(createEntityStatement(t, leafID, leafID, []model.EntityIdentifier{taID}, leafSigner, false))) //nolint:errcheck
		case "/ta/.well-known/openid-federation":
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(createEntityStatement(t, taID, taID, nil, taKey, true))) //nolint:errcheck
		case "/ta/fetch":
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(createSubordinateStatement(t, taID, leafID, taKey, leafKey.Public()))) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	leafID = model.EntityIdentifier(server.URL + "/leaf")
	taID = model.EntityIdentifier(server.URL + "/ta")
	cfg := model.Configuration{HttpClient: server.Client()}

	tests := []struct {
		name      string
		signer    *rsa.PrivateKey
		expectErr bool
	}{
		{name: "leaf signed by the key its superior registered is accepted", signer: leafKey, expectErr: false},
		{name: "leaf signed by another key under the registered kid is rejected", signer: attackerKey, expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leafSigner = tc.signer
			_, parsed, _, err := BuildTrustChain(context.Background(), cfg, leafID, taID, resolvecache.New())
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected the chain build to be rejected, got %d statements", len(parsed))
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the chain to build, got %v", err)
			}
		})
	}
}

func TestResolveMetadata_RejectionsAreTypedAsInvalidTrustChain(t *testing.T) {
	const (
		leafID = model.EntityIdentifier("https://leaf.example.com")
		taID   = model.EntityIdentifier("https://ta.example.com")
	)

	leafKey := bindingKey(t)
	attackerKey := bindingKey(t)
	taKey := bindingKey(t)

	taEC := createEntityStatement(t, taID, taID, nil, taKey, true)
	leafEC := createEntityStatement(t, leafID, leafID, []model.EntityIdentifier{taID}, leafKey, false)

	tests := []struct {
		name  string
		chain []string
	}{
		{
			name:  "a subordinate statement signed by the wrong key",
			chain: []string{leafEC, createSubordinateStatement(t, taID, leafID, attackerKey, leafKey.Public()), taEC},
		},
		{
			name:  "a subject entity configuration signed by the wrong key",
			chain: []string{createEntityStatement(t, leafID, leafID, []model.EntityIdentifier{taID}, attackerKey, false), createSubordinateStatement(t, taID, leafID, taKey, leafKey.Public()), taEC},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveMetadata(context.Background(), model.Configuration{}, leafID, tc.chain, resolvecache.New())
			if err == nil {
				t.Fatal("expected the chain to be rejected")
			}
			if !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("expected an invalid_trust_chain error so /resolve answers 400, got %v", err)
			}
		})
	}
}
