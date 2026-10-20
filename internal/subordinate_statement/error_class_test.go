package subordinate_statement

import (
	"errors"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_StatementFailuresAreChainFailures(t *testing.T) {
	const (
		trustAnchor = model.EntityIdentifier("https://ta.example.com")
		leaf        = model.EntityIdentifier("https://leaf.example.com")
	)

	issuerKey := testKey(t)
	subjectKey := testKey(t)
	otherKey := testKey(t)
	issuerJwk := testPublicJwk(t, issuerKey.Public(), "ta")
	subjectJwk := testPublicJwk(t, subjectKey.Public(), "leaf")

	body := func(extra map[string]any) map[string]any {
		claims := map[string]any{
			"iss":  string(trustAnchor),
			"sub":  string(leaf),
			"iat":  time.Now().Add(-time.Minute).UTC().Unix(),
			"exp":  time.Now().Add(time.Hour).UTC().Unix(),
			"jwks": map[string]any{"keys": []any{subjectJwk}},
		}
		for k, v := range extra {
			claims[k] = v
		}
		return claims
	}

	validHead := map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"}

	tests := []struct {
		name       string
		kind       string
		head       map[string]any
		extra      map[string]any
		signWith   bool
		expectKind error
	}{
		{name: "a bad typ header", kind: "header", head: map[string]any{"kid": "ta", "typ": "JWT", "alg": "RS256"}, expectKind: model.ErrInvalidTrustChain},
		{name: "an alg of none", kind: "header", head: map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "none"}, expectKind: model.ErrInvalidTrustChain},
		{name: "a missing kid header", kind: "header", head: map[string]any{"typ": "entity-statement+jwt", "alg": "RS256"}, expectKind: model.ErrInvalidTrustChain},
		{name: "an expired body", kind: "body", head: validHead, extra: map[string]any{"exp": time.Now().Add(-2 * time.Hour).UTC().Unix()}, expectKind: model.ErrInvalidTrustChain},
		{name: "a misplaced claim", kind: "placement", head: validHead, extra: map[string]any{"authority_hints": []any{"https://other.example.com"}}, expectKind: model.ErrInvalidTrustChain},
		{name: "a self-signed statement", kind: "relationship", head: validHead, extra: map[string]any{"sub": string(trustAnchor)}, expectKind: model.ErrInvalidTrustChain},
		{name: "a signature by another key", kind: "signature", head: validHead, signWith: true, expectKind: model.ErrInvalidTrustChain},
		{name: "invalid metadata", kind: "metadata", head: validHead, extra: map[string]any{"metadata": map[string]any{"openid_relying_party": map[string]any{"redirect_uris": "not-an-array"}}}, expectKind: model.ErrInvalidMetadata},
		{name: "a malformed policy operator", kind: "body", head: validHead, extra: map[string]any{"metadata_policy": map[string]any{"openid_relying_party": map[string]any{"scope": map[string]any{"subset_of": "not a list"}}}}, expectKind: model.ErrInvalidTrustChain},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer := issuerKey
			if tc.signWith {
				signer = otherKey
			}
			issuer := testIssuerStatement(t, trustAnchor, issuerJwk)
			statement := testSign(t, signer, tc.head, body(tc.extra))

			_, err := Validate(model.Configuration{}, issuer, statement)
			if err == nil {
				t.Fatalf("[%s] expected the statement to be rejected", tc.kind)
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
