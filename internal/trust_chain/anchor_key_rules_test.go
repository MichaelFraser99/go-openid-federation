package trust_chain

import (
	"errors"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_AConfiguredAnchorKeyIsHeldToTheSameRulesAsAnyOther(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		members   map[string]any
		expectErr error
	}{
		{
			name:      "a key the anchor published for signing",
			reference: "RFC 7517 4.2",
			members:   map[string]any{"use": "sig"},
		},
		{
			name:      "a key with no declared use",
			reference: "RFC 7517 4.2",
			members:   nil,
		},
		{
			name:      "a key the anchor published for encryption",
			reference: "RFC 7517 4.2",
			members:   map[string]any{"use": "enc"},
			expectErr: model.ErrServerError,
		},
		{
			name:      "a key whose key_ops include verify",
			reference: "RFC 7517 4.3",
			members:   map[string]any{"key_ops": []any{"verify"}},
		},
		{
			name:      "a key whose key_ops exclude verify",
			reference: "RFC 7517 4.3",
			members:   map[string]any{"key_ops": []any{"encrypt"}},
			expectErr: model.ErrServerError,
		},
		{
			name:      "a key whose key_ops list verify twice",
			reference: "RFC 7517 4.3",
			members:   map[string]any{"key_ops": []any{"verify", "verify"}},
			expectErr: model.ErrServerError,
		},
		{
			name:      "a key published for an algorithm this library cannot verify with",
			reference: "RFC 7518 3.1",
			members:   map[string]any{"alg": "EdDSA"},
			expectErr: model.ErrServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp := newTopo(t, map[string][]string{"leaf": {"ta"}, "ta": {}})

			configured := anchorKeySet(t, tp.keys["ta"].Public(), tc.members)
			cfg := model.Configuration{
				HttpClient:   tp.server.Client(),
				TrustAnchors: map[model.EntityIdentifier]josemodel.Jwks{tp.id["ta"]: configured},
			}

			tp.mu.Lock()
			tp.hits["leaf"], tp.hits["ta"] = 0, 0
			tp.mu.Unlock()

			_, _, _, err := BuildTrustChain(t.Context(), cfg, tp.id["leaf"], tp.id["ta"], resolvecache.New())

			tp.mu.Lock()
			walked := tp.hits["leaf"] + tp.hits["ta"]
			tp.mu.Unlock()

			if tc.expectErr == nil {
				if err != nil {
					t.Fatalf("[%s] expected the chain to build, got %v", tc.reference, err)
				}
				return
			}
			if !errors.Is(err, tc.expectErr) {
				t.Errorf("[%s] a configured key this deployment can never verify with is its own fault, not the anchor's, got %v", tc.reference, err)
			}
			if errors.Is(err, model.ErrInvalidTrustAnchor) {
				t.Errorf("[%s] must not blame the anchor, got %v", tc.reference, err)
			}
			if walked != 0 {
				t.Errorf("[%s] this is decidable before any request, yet %d were made", tc.reference, walked)
			}
		})
	}
}

func TestResolveMetadata_AConfiguredAnchorKeyBelowItsAlgorithmsModulusIsRefused(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"ta"}, "ta": {}})

	weak := map[string]any{"kid": "weak", "kty": "RSA", "alg": "RS256", "n": "AQAB", "e": "AQAB"}
	cfg := model.Configuration{
		HttpClient:   tp.server.Client(),
		TrustAnchors: map[model.EntityIdentifier]josemodel.Jwks{tp.id["ta"]: {Keys: []map[string]any{weak}}},
	}

	tp.mu.Lock()
	tp.hits["leaf"], tp.hits["ta"] = 0, 0
	tp.mu.Unlock()

	_, _, _, err := BuildTrustChain(t.Context(), cfg, tp.id["leaf"], tp.id["ta"], resolvecache.New())

	tp.mu.Lock()
	walked := tp.hits["leaf"] + tp.hits["ta"]
	tp.mu.Unlock()

	if !errors.Is(err, model.ErrServerError) {
		t.Fatalf("[RFC 7518 3.3] an anchor key below its algorithm's minimum modulus can never verify, so it is this deployment's own fault, got %v", err)
	}
	if walked != 0 {
		t.Errorf("[RFC 7518 3.3] this is decidable before any request, yet %d were made", walked)
	}
}
