package trust_chain

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func chainSignStatementAs(t *testing.T, signer crypto.Signer, alg jwa.Algorithm, body map[string]any) string {
	t.Helper()
	token, err := jwt.New(signer, map[string]any{"kid": "chain-key", "typ": "entity-statement+jwt", "alg": alg.String()}, body, jwt.Opts{Algorithm: alg})
	if err != nil {
		t.Fatalf("failed to sign statement: %v", err)
	}
	return *token
}

func ed25519AnchoredChain(t *testing.T, anchorKey ed25519.PrivateKey, subjectKey *rsa.PrivateKey) []string {
	t.Helper()
	now := time.Now().UTC()
	return []string{
		chainSignStatementAs(t, subjectKey, jwa.RS256, map[string]any{
			"iss":             string(chainSubject),
			"sub":             string(chainSubject),
			"iat":             now.Unix(),
			"exp":             now.Add(time.Hour).Unix(),
			"jwks":            chainJwks(t, subjectKey),
			"authority_hints": []any{string(chainAnchor)},
			"metadata":        map[string]any{"federation_entity": map[string]any{"contacts": []any{"leaf@leaf.example.com"}}},
		}),
		chainSignStatementAs(t, anchorKey, jwa.Ed25519, map[string]any{
			"iss":  string(chainAnchor),
			"sub":  string(chainSubject),
			"iat":  now.Unix(),
			"exp":  now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, subjectKey),
		}),
		chainSignStatementAs(t, anchorKey, jwa.Ed25519, map[string]any{
			"iss":      string(chainAnchor),
			"sub":      string(chainAnchor),
			"iat":      now.Unix(),
			"exp":      now.Add(time.Hour).Unix(),
			"jwks":     chainJwks(t, anchorKey),
			"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": string(chainAnchor) + "/fetch"}},
		}),
	}
}

func TestResolveMetadata_TheSigningAlgorithmsAreTheConsumersToChoose(t *testing.T) {
	_, anchorKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	subjectKey := chainSigningKey(t)
	chain := ed25519AnchoredChain(t, anchorKey, subjectKey)
	anchors := map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: anchorKeySet(t, anchorKey.Public(), nil)}

	tests := []struct {
		name       string
		reference  string
		algorithms []jwa.Algorithm
		expectErr  error
	}{
		{name: "the default accepts an Ed25519 anchor and an RS256 subject", reference: "RFC 8725 3.1"},
		{name: "a list naming both", reference: "RFC 8725 3.1", algorithms: []jwa.Algorithm{jwa.Ed25519, jwa.RS256}},
		{name: "a list leaving out the subject's algorithm refuses the subject's statement", reference: "3.2", algorithms: []jwa.Algorithm{jwa.Ed25519}, expectErr: model.ErrInvalidTrustChain},
		{name: "a list leaving out the configured anchor key's algorithm is this deployment's own fault", reference: "8.9", algorithms: []jwa.Algorithm{jwa.RS256}, expectErr: model.ErrServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.Configuration{TrustAnchors: anchors, SigningAlgorithms: tc.algorithms}
			_, err := ResolveMetadata(t.Context(), cfg, chainAnchor, chainAnchor, chain, nil)
			if tc.expectErr == nil {
				if err != nil {
					t.Fatalf("[%s] expected the chain to resolve, got %v", tc.reference, err)
				}
				return
			}
			if !errors.Is(err, tc.expectErr) {
				t.Errorf("[%s] expected %v, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func TestBuildTrustChain_AnUnusableAlgorithmListIsRefusedBeforeAnyRequest(t *testing.T) {
	tests := []struct {
		name       string
		algorithms []jwa.Algorithm
	}{
		{name: "an empty list", algorithms: []jwa.Algorithm{}},
		{name: "HS256", algorithms: []jwa.Algorithm{jwa.ES256, jwa.HS256}},
		{name: "HS384", algorithms: []jwa.Algorithm{jwa.HS384}},
		{name: "HS512", algorithms: []jwa.Algorithm{jwa.HS512}},
		{name: "an algorithm go-jose does not define", algorithms: []jwa.Algorithm{jwa.Unknown}},
		{name: "ML-DSA, which this library does not yet accept", algorithms: []jwa.Algorithm{jwa.MLDSA65}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				http.NotFound(w, nil)
			}))
			defer server.Close()
			cfg := model.Configuration{HttpClient: server.Client(), SigningAlgorithms: tc.algorithms}

			_, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(server.URL+"/leaf"), model.EntityIdentifier(server.URL+"/ta"), nil)
			if !errors.Is(err, model.ErrServerError) {
				t.Errorf("[8.9] a signing algorithm list this deployment cannot use is its own fault, got %v", err)
			}
			if n := requests.Load(); n != 0 {
				t.Errorf("[8.9] the list is judged with no I/O, yet %d requests were made", n)
			}

			_, err = ResolveMetadata(t.Context(), cfg, chainAnchor, chainAnchor, []string{"a.b.c"}, nil)
			if !errors.Is(err, model.ErrServerError) {
				t.Errorf("[8.9] ResolveMetadata must apply the same entry check, got %v", err)
			}
		})
	}
}

func TestResolveMetadata_AnAnchorSigningWithAnExcludedAlgorithmIsRefusedThoughAnotherOfItsKeysIsAccepted(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	rsaKey, subjectKey := chainSigningKey(t), chainSigningKey(t)
	edJwks := anchorKeySet(t, edKey.Public(), map[string]any{"kid": "anchor-ed"})
	rsaJwks := anchorKeySet(t, rsaKey.Public(), map[string]any{"kid": "anchor-rsa"})
	anchorKeys := josemodel.Jwks{Keys: []map[string]any{edJwks.Keys[0], rsaJwks.Keys[0]}}
	published := map[string]any{"keys": []any{edJwks.Keys[0], rsaJwks.Keys[0]}}

	now := time.Now().UTC()
	sign := func(signer crypto.Signer, alg jwa.Algorithm, kid string, body map[string]any) string {
		token, err := jwt.New(signer, map[string]any{"kid": kid, "typ": "entity-statement+jwt", "alg": alg.String()}, body, jwt.Opts{Algorithm: alg})
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}
		return *token
	}
	chain := []string{
		chainSignStatementAs(t, subjectKey, jwa.RS256, map[string]any{
			"iss": string(chainSubject), "sub": string(chainSubject), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, subjectKey), "authority_hints": []any{string(chainAnchor)},
		}),
		sign(rsaKey, jwa.RS256, "anchor-rsa", map[string]any{
			"iss": string(chainAnchor), "sub": string(chainSubject), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, subjectKey),
		}),
		sign(edKey, jwa.Ed25519, "anchor-ed", map[string]any{
			"iss": string(chainAnchor), "sub": string(chainAnchor), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jwks": published,
		}),
	}
	anchors := map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: anchorKeys}

	if _, err := ResolveMetadata(t.Context(), model.Configuration{TrustAnchors: anchors}, chainAnchor, chainAnchor, chain, nil); err != nil {
		t.Fatalf("the fixture is wrong: under the default the chain must resolve, got %v", err)
	}
	_, err = ResolveMetadata(t.Context(), model.Configuration{TrustAnchors: anchors, SigningAlgorithms: []jwa.Algorithm{jwa.RS256}}, chainAnchor, chainAnchor, chain, nil)
	if err == nil {
		t.Fatal("[10.2] the anchor's own configuration is signed with an algorithm the deployment does not accept, so the chain must be refused")
	}
	if errors.Is(err, model.ErrServerError) {
		t.Errorf("[8.9] the deployment's list is usable, since one configured key is accepted, so this is the anchor's fault, got %v", err)
	}
}

func TestVerifyTrustAnchor_HoldsTheAnchorsSignatureToTheConfiguredAlgorithms(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	rsaKey := chainSigningKey(t)
	edJwks := anchorKeySet(t, edKey.Public(), map[string]any{"kid": "anchor-ed"})
	rsaJwks := anchorKeySet(t, rsaKey.Public(), map[string]any{"kid": "anchor-rsa"})
	anchors := map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: {Keys: []map[string]any{edJwks.Keys[0], rsaJwks.Keys[0]}}}
	now := time.Now().UTC()
	token, err := jwt.New(edKey, map[string]any{"kid": "anchor-ed", "typ": "entity-statement+jwt", "alg": "Ed25519"}, map[string]any{
		"iss": string(chainAnchor), "sub": string(chainAnchor), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": map[string]any{"keys": []any{edJwks.Keys[0], rsaJwks.Keys[0]}},
	}, jwt.Opts{Algorithm: jwa.Ed25519})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	anchor := model.EntityStatement{Iss: chainAnchor, Sub: chainAnchor}

	if err := verifyTrustAnchor(t.Context(), model.Configuration{TrustAnchors: anchors}, chainAnchor, *token, anchor); err != nil {
		t.Fatalf("the fixture is wrong: under the default the anchor's signature must verify, got %v", err)
	}
	err = verifyTrustAnchor(t.Context(), model.Configuration{TrustAnchors: anchors, SigningAlgorithms: []jwa.Algorithm{jwa.RS256}}, chainAnchor, *token, anchor)
	if !errors.Is(err, model.ErrInvalidTrustAnchor) {
		t.Fatalf("[10.2] an anchor signing with an algorithm the deployment does not accept is refused, though another configured key is accepted, got %v", err)
	}
}
