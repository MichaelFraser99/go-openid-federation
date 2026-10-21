package trust_chain

import (
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func anchoredChain(t *testing.T, anchorKey, subjectKey *rsa.PrivateKey) []string {
	t.Helper()
	now := time.Now().UTC()
	return []string{
		chainSignStatement(t, subjectKey, map[string]any{
			"iss":             string(chainSubject),
			"sub":             string(chainSubject),
			"iat":             now.Unix(),
			"exp":             now.Add(time.Hour).Unix(),
			"jwks":            chainJwks(t, subjectKey),
			"authority_hints": []any{string(chainAnchor)},
			"metadata":        map[string]any{"federation_entity": map[string]any{"contacts": []any{"leaf@leaf.example.com"}}},
		}),
		chainSignStatement(t, anchorKey, map[string]any{
			"iss":  string(chainAnchor),
			"sub":  string(chainSubject),
			"iat":  now.Unix(),
			"exp":  now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, subjectKey),
		}),
		chainSignStatement(t, anchorKey, map[string]any{
			"iss":      string(chainAnchor),
			"sub":      string(chainAnchor),
			"iat":      now.Unix(),
			"exp":      now.Add(time.Hour).Unix(),
			"jwks":     chainJwks(t, anchorKey),
			"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": string(chainAnchor) + "/fetch"}},
		}),
	}
}

func TestResolveMetadata_AChainMustEndInTheRequestedTrustAnchor(t *testing.T) {
	const impostor = model.EntityIdentifier("https://impostor.example.com")

	tests := []struct {
		name      string
		reference string
		requested model.EntityIdentifier
		expectErr bool
	}{
		{name: "the anchor the chain ends in", reference: "10.2", requested: chainAnchor},
		{name: "an anchor the chain does not reach", reference: "10.2", requested: impostor, expectErr: true},
		{name: "the subject itself", reference: "10.2", requested: chainSubject, expectErr: true},
		{name: "no anchor at all", reference: "10.2", requested: "", expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain := chainWithClaims(t, nil, nil)

			_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, tc.requested, chain, nil)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("[%s] section 10.2 requires the last statement to be the entity configuration of the trust anchor the verifier asked for", tc.reference)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected the chain to resolve against the anchor it ends in, got %v", tc.reference, err)
			}
		})
	}
}

func TestResolveMetadata_AnAttackerSuppliedChainCannotAnchorItself(t *testing.T) {
	attackerKey := chainSigningKey(t)
	now := time.Now().UTC()

	selfSigned := chainSignStatement(t, attackerKey, map[string]any{
		"iss":      string(chainSubject),
		"sub":      string(chainSubject),
		"iat":      now.Unix(),
		"exp":      now.Add(time.Hour).Unix(),
		"jwks":     chainJwks(t, attackerKey),
		"metadata": map[string]any{"federation_entity": map[string]any{"contacts": []any{"attacker@impostor.example.com"}}},
	})

	_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chainAnchor, []string{selfSigned}, nil)
	if err == nil {
		t.Fatal("[10.2] a chain made only of the attacker's own self-signed entity configuration must not resolve against another entity's trust anchor")
	}
	if !errors.Is(err, model.ErrInvalidTrustAnchor) {
		t.Errorf("[10.2] expected the refusal to name the trust anchor, got %v", err)
	}
}

func TestResolveMetadata_ConfiguredTrustAnchorKeys(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		configure func(t *testing.T, anchorKey *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks
		expectErr string
	}{
		{
			name:      "no anchors configured, so the chain is trusted on its own signature",
			reference: "4",
			configure: func(*testing.T, *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks { return nil },
		},
		{
			name:      "the anchor's own key configured",
			reference: "10.2",
			configure: func(t *testing.T, anchorKey *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				keys := chainJwks(t, anchorKey)
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: {Keys: []map[string]any{keys["keys"].([]any)[0].(map[string]any)}}}
			},
		},
		{
			name:      "another entity's key configured for the anchor",
			reference: "10.2",
			configure: func(t *testing.T, _ *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				other := chainSigningKey(t)
				keys := chainJwks(t, other)
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: {Keys: []map[string]any{keys["keys"].([]any)[0].(map[string]any)}}}
			},
			expectErr: "not signed by a key configured for it",
		},
		{
			name:      "anchors configured but not this one",
			reference: "10.2",
			configure: func(t *testing.T, anchorKey *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				keys := chainJwks(t, anchorKey)
				return map[model.EntityIdentifier]josemodel.Jwks{"https://other-anchor.example.com": {Keys: []map[string]any{keys["keys"].([]any)[0].(map[string]any)}}}
			},
			expectErr: "not one this deployment is configured to trust",
		},
		{
			name:      "an anchor configured with an empty key set is not configured",
			reference: "4",
			configure: func(*testing.T, *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: {}}
			},
			expectErr: "not one this deployment is configured to trust",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			anchorKey := chainSigningKey(t)
			subjectKey := chainSigningKey(t)
			chain := anchoredChain(t, anchorKey, subjectKey)

			cfg := model.Configuration{TrustAnchors: tc.configure(t, anchorKey)}
			_, err := ResolveMetadata(t.Context(), cfg, chainAnchor, chainAnchor, chain, nil)

			if tc.expectErr != "" {
				if err == nil {
					t.Fatalf("[%s] expected the trust anchor to be refused", tc.reference)
				}
				if !errors.Is(err, model.ErrInvalidTrustAnchor) {
					t.Errorf("[%s] expected the refusal to name the trust anchor, got %v", tc.reference, err)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected the chain to resolve, got %v", tc.reference, err)
			}
		})
	}
}
