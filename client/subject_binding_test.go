package client

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
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

func bindingJwk(t *testing.T, pub crypto.PublicKey) map[string]any {
	t.Helper()
	publicJWK, err := jwk.PublicJwk(pub)
	if err != nil {
		t.Fatalf("failed to build public jwk: %v", err)
	}
	(*publicJWK)["kid"] = "test-key"
	(*publicJWK)["alg"] = "RS256"
	return *publicJWK
}

func bindingSign(t *testing.T, signer crypto.Signer, body map[string]any) string {
	t.Helper()
	head := map[string]any{"kid": "test-key", "typ": "entity-statement+jwt", "alg": "RS256"}
	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: josemodel.RS256})
	if err != nil {
		t.Fatalf("failed to sign statement: %v", err)
	}
	return *token
}

func bindingChain(t *testing.T, subject, trustAnchor model.EntityIdentifier) []string {
	t.Helper()

	subjectKey := bindingKey(t)
	taKey := bindingKey(t)

	subjectEC := bindingSign(t, subjectKey, map[string]any{
		"iss":             string(subject),
		"sub":             string(subject),
		"iat":             time.Now().UTC().Unix(),
		"exp":             time.Now().Add(time.Hour).UTC().Unix(),
		"jwks":            map[string]any{"keys": []any{bindingJwk(t, subjectKey.Public())}},
		"authority_hints": []string{string(trustAnchor)},
		"metadata":        map[string]any{},
	})

	subordinateStatement := bindingSign(t, taKey, map[string]any{
		"iss":  string(trustAnchor),
		"sub":  string(subject),
		"iat":  time.Now().UTC().Unix(),
		"exp":  time.Now().Add(time.Hour).UTC().Unix(),
		"jwks": map[string]any{"keys": []any{bindingJwk(t, subjectKey.Public())}},
	})

	trustAnchorEC := bindingSign(t, taKey, map[string]any{
		"iss":  string(trustAnchor),
		"sub":  string(trustAnchor),
		"iat":  time.Now().UTC().Unix(),
		"exp":  time.Now().Add(time.Hour).UTC().Unix(),
		"jwks": map[string]any{"keys": []any{bindingJwk(t, taKey.Public())}},
		"metadata": map[string]any{
			"federation_entity": map[string]any{"federation_fetch_endpoint": fmt.Sprintf("%s/fetch", trustAnchor)},
		},
	})

	return []string{subjectEC, subordinateStatement, trustAnchorEC}
}

func TestClient_ResolveMetadata_RejectsChainForAnotherSubject(t *testing.T) {
	const (
		chainSubject = model.EntityIdentifier("https://other.example.com")
		trustAnchor  = model.EntityIdentifier("https://ta.example.com")
		requested    = model.EntityIdentifier("https://requested.example.com")
	)

	chain := bindingChain(t, chainSubject, trustAnchor)
	c := New(model.ClientConfiguration{})

	tests := []struct {
		name      string
		subject   model.EntityIdentifier
		expectErr bool
	}{
		{
			name:      "chain resolves for the subject it is about",
			subject:   chainSubject,
			expectErr: false,
		},
		{
			name:      "chain for another subject is rejected",
			subject:   requested,
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := c.ResolveMetadata(context.Background(), string(tc.subject), chain)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected chain about %q to be rejected when %q was requested, got metadata %+v", chainSubject, tc.subject, metadata)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected chain to resolve, got error: %v", err)
			}
		})
	}
}
