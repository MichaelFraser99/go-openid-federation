package entity_configuration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_StatementFailuresAreChainFailures(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")

	key := headerJwkKey(t)
	published := headerJwkPublicJwk(t, key.Public(), "leaf")
	other := headerJwkKey(t)

	body := func(extra map[string]any) map[string]any {
		claims := map[string]any{
			"iss":      string(leaf),
			"sub":      string(leaf),
			"iat":      time.Now().Add(-time.Minute).UTC().Unix(),
			"exp":      time.Now().Add(time.Hour).UTC().Unix(),
			"jwks":     map[string]any{"keys": []any{published}},
			"metadata": map[string]any{},
		}
		for k, v := range extra {
			claims[k] = v
		}
		return claims
	}

	validHead := map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"}

	tests := []struct {
		name       string
		kind       string
		head       map[string]any
		extra      map[string]any
		signWith   any
		expectKind error
	}{
		{name: "a bad typ header", kind: "header", head: map[string]any{"kid": "leaf", "typ": "JWT", "alg": "RS256"}, expectKind: model.ErrInvalidTrustChain},
		{name: "a missing kid header", kind: "header", head: map[string]any{"typ": "entity-statement+jwt", "alg": "RS256"}, expectKind: model.ErrInvalidTrustChain},
		{name: "an expired body", kind: "body", head: validHead, extra: map[string]any{"exp": time.Now().Add(-2 * time.Hour).UTC().Unix()}, expectKind: model.ErrInvalidTrustChain},
		{name: "a future dated body", kind: "body", head: validHead, extra: map[string]any{"iat": time.Now().Add(2 * time.Hour).UTC().Unix()}, expectKind: model.ErrInvalidTrustChain},
		{name: "a misplaced claim", kind: "placement", head: validHead, extra: map[string]any{"source_endpoint": "https://ta.example.com/fetch"}, expectKind: model.ErrInvalidTrustChain},
		{name: "an iss that does not match sub", kind: "relationship", head: validHead, extra: map[string]any{"sub": "https://other.example.com"}, expectKind: model.ErrInvalidTrustChain},
		{name: "a signature by another key", kind: "signature", head: validHead, signWith: other, expectKind: model.ErrInvalidTrustChain},
		{name: "invalid metadata", kind: "metadata", head: validHead, extra: map[string]any{"metadata": map[string]any{"openid_relying_party": map[string]any{"redirect_uris": "not-an-array"}}}, expectKind: model.ErrInvalidMetadata},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer := key
			if tc.signWith != nil {
				signer = other
			}
			token := signStatementRaw(t, signer, tc.head, body(tc.extra))

			_, err := Validate(context.Background(), model.Configuration{}, leaf, token)
			if err == nil {
				t.Fatalf("[%s] expected the configuration to be rejected", tc.kind)
			}
			if !errors.Is(err, tc.expectKind) {
				t.Fatalf("[%s] expected the failure to be classified as %T, got %v", tc.kind, tc.expectKind, err)
			}
			if errors.Is(err, model.ErrNotFound) {
				t.Fatalf("[%s] a statement that was retrieved must not be reported as not found, got %v", tc.kind, err)
			}
		})
	}
}
