package trust_chain

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func anchorKeySet(t *testing.T, pub crypto.PublicKey, members map[string]any) josemodel.Jwks {
	t.Helper()
	published, err := jwk.PublicJwk(pub)
	if err != nil {
		t.Fatalf("failed to build public jwk: %v", err)
	}
	for member, value := range members {
		if value == nil {
			delete(*published, member)
			continue
		}
		(*published)[member] = value
	}
	return josemodel.Jwks{Keys: []map[string]any{*published}}
}

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
		expectErr error
	}{
		{name: "the anchor the chain ends in", reference: "10.2", requested: chainAnchor},
		{name: "an anchor the chain does not reach", reference: "10.2", requested: impostor, expectErr: model.ErrInvalidTrustAnchor},
		{name: "the subject itself", reference: "10.2", requested: chainSubject, expectErr: model.ErrInvalidTrustAnchor},
		{name: "no anchor at all", reference: "8.3", requested: "", expectErr: model.ErrInvalidRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain := chainWithClaims(t, nil, nil)

			_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, tc.requested, chain, nil)
			if tc.expectErr != nil {
				if err == nil {
					t.Fatalf("[%s] section 10.2 requires the last statement to be the entity configuration of the trust anchor the verifier asked for", tc.reference)
				}
				if !errors.Is(err, tc.expectErr) {
					t.Errorf("[%s] expected %v, got %v", tc.reference, tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected the chain to resolve against the anchor it ends in, got %v", tc.reference, err)
			}
		})
	}
}

func TestResolveMetadata_AForgedAnchorIsRefusedOnlyWhenKeysAreHeldForIt(t *testing.T) {
	attackerKey := chainSigningKey(t)
	anchorKey := chainSigningKey(t)
	now := time.Now().UTC()

	forged := []string{
		chainSignStatement(t, attackerKey, map[string]any{
			"iss":             string(chainSubject),
			"sub":             string(chainSubject),
			"iat":             now.Unix(),
			"exp":             now.Add(time.Hour).Unix(),
			"jwks":            chainJwks(t, attackerKey),
			"authority_hints": []any{string(chainAnchor)},
			"metadata":        map[string]any{"federation_entity": map[string]any{"contacts": []any{"attacker@impostor.example.com"}}},
		}),
		chainSignStatement(t, attackerKey, map[string]any{
			"iss":  string(chainAnchor),
			"sub":  string(chainSubject),
			"iat":  now.Unix(),
			"exp":  now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, attackerKey),
		}),
		chainSignStatement(t, attackerKey, map[string]any{
			"iss":      string(chainAnchor),
			"sub":      string(chainAnchor),
			"iat":      now.Unix(),
			"exp":      now.Add(time.Hour).Unix(),
			"jwks":     chainJwks(t, attackerKey),
			"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": string(chainAnchor) + "/fetch"}},
		}),
	}

	tests := []struct {
		name      string
		reference string
		anchors   map[model.EntityIdentifier]josemodel.Jwks
		expectErr string
	}{
		{
			name:      "no keys held for any anchor, so the forgery is accepted on its own signature",
			reference: "4",
			anchors:   nil,
		},
		{
			name:      "the real anchor's key held, so the forgery is refused",
			reference: "10.2",
			anchors:   map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: anchorKeySet(t, anchorKey.Public(), nil)},
			expectErr: "not signed by any key configured for it",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.Configuration{TrustAnchors: tc.anchors}
			resolved, err := ResolveMetadata(t.Context(), cfg, chainAnchor, chainAnchor, forged, nil)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] with no keys held the identifier check is all there is, so this chain resolves; the test exists to pin that, got %v", tc.reference, err)
				}
				if resolved.Sub != chainSubject {
					t.Errorf("[%s] expected the forged chain to resolve for the subject it names, got %q", tc.reference, resolved.Sub)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] a chain signed throughout by the attacker's own key must not anchor in an entity whose keys this deployment holds", tc.reference)
			}
			if !errors.Is(err, model.ErrInvalidTrustAnchor) {
				t.Errorf("[%s] expected the refusal to name the trust anchor, got %v", tc.reference, err)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
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
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: anchorKeySet(t, anchorKey.Public(), nil)}
			},
		},
		{
			name:      "the anchor's own key configured with no kid, which RFC 7517 leaves optional",
			reference: "RFC 7517 4.5",
			configure: func(t *testing.T, anchorKey *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: anchorKeySet(t, anchorKey.Public(), map[string]any{"kid": nil})}
			},
		},
		{
			name:      "the anchor's own key configured under a label of the operator's own",
			reference: "RFC 7517 4.5",
			configure: func(t *testing.T, anchorKey *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: anchorKeySet(t, anchorKey.Public(), map[string]any{"kid": "operator-local-label"})}
			},
		},
		{
			name:      "the anchor's own key held beside a retired key with no kid",
			reference: "RFC 7517 5",
			configure: func(t *testing.T, anchorKey *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				set := anchorKeySet(t, anchorKey.Public(), nil)
				set.Keys = append([]map[string]any{{"kty": "RSA", "n": "AQAB", "e": "AQAB"}}, set.Keys...)
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: set}
			},
		},
		{
			name:      "the anchor's own key held beside a key of a type this library cannot use",
			reference: "RFC 7517 5",
			configure: func(t *testing.T, anchorKey *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				set := anchorKeySet(t, anchorKey.Public(), nil)
				set.Keys = append([]map[string]any{{"kid": "pq", "kty": "ML-DSA-44", "pk": "AQAB"}}, set.Keys...)
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: set}
			},
		},
		{
			name:      "another entity's key configured for the anchor",
			reference: "10.2",
			configure: func(t *testing.T, _ *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: anchorKeySet(t, chainSigningKey(t).Public(), nil)}
			},
			expectErr: "not signed by any key configured for it",
		},
		{
			name:      "anchors configured but not this one",
			reference: "10.2",
			configure: func(t *testing.T, anchorKey *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{"https://other-anchor.example.com": anchorKeySet(t, anchorKey.Public(), nil)}
			},
			expectErr: "not one this deployment is configured to trust",
		},
		{
			name:      "an anchor list that parsed to no anchors at all refuses everything",
			reference: "4",
			configure: func(*testing.T, *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{}
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
		{
			name:      "an anchor whose every configured key is unusable is this deployment's own fault",
			reference: "8.9",
			configure: func(*testing.T, *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: {Keys: []map[string]any{{"kid": "broken"}}}}
			},
			expectErr: "hold no usable key",
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
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
				}
				if strings.Contains(tc.expectErr, "usable") {
					if !errors.Is(err, model.ErrServerError) {
						t.Errorf("[%s] a key set this deployment configured and cannot use is a server fault, got %v", tc.reference, err)
					}
					return
				}
				if !errors.Is(err, model.ErrInvalidTrustAnchor) {
					t.Errorf("[%s] expected the refusal to name the trust anchor, got %v", tc.reference, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected the chain to resolve, got %v", tc.reference, err)
			}
		})
	}
}

func TestResolveMetadata_AnOmittedAnchorIsCheckedBeforeItIsFetched(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"ta"}, "ta": {}})
	cfg := model.Configuration{HttpClient: tp.server.Client()}

	leafEC := createEntityStatement(t, tp.id["leaf"], tp.id["leaf"], []model.EntityIdentifier{tp.id["ta"]}, tp.keys["leaf"], false)
	subordinateStatement := createSubordinateStatement(t, tp.id["ta"], tp.id["leaf"], tp.keys["ta"], tp.keys["leaf"].Public())

	tests := []struct {
		name       string
		reference  string
		requested  model.EntityIdentifier
		anchors    func(t *testing.T) map[model.EntityIdentifier]josemodel.Jwks
		expectErr  bool
		expectHits int
	}{
		{name: "the anchor the chain's last statement was issued by", reference: "10.2", requested: tp.id["ta"], expectHits: 1},
		{name: "an anchor the chain's last statement was not issued by", reference: "10.2", requested: "https://impostor.example.com", expectErr: true, expectHits: 0},
		{
			name:      "the fetched anchor configuration verifies against the key held for it",
			reference: "10.2",
			requested: tp.id["ta"],
			anchors: func(t *testing.T) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{tp.id["ta"]: anchorKeySet(t, tp.keys["ta"].Public(), nil)}
			},
			expectHits: 1,
		},
		{
			name:      "the fetched anchor configuration verifies against no key held for it",
			reference: "10.2",
			requested: tp.id["ta"],
			anchors: func(t *testing.T) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{tp.id["ta"]: anchorKeySet(t, chainSigningKey(t).Public(), nil)}
			},
			expectErr:  true,
			expectHits: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp.mu.Lock()
			tp.hits["ta"] = 0
			tp.mu.Unlock()

			anchored := cfg
			if tc.anchors != nil {
				anchored.TrustAnchors = tc.anchors(t)
			}
			_, err := ResolveMetadata(t.Context(), anchored, tp.id["leaf"], tc.requested, []string{leafEC, subordinateStatement}, resolvecache.New())

			tp.mu.Lock()
			hits := tp.hits["ta"]
			tp.mu.Unlock()

			if tc.expectErr {
				if err == nil {
					t.Fatalf("[%s] a chain whose last statement was issued by another entity must not anchor in the requested one", tc.reference)
				}
				if !errors.Is(err, model.ErrInvalidTrustAnchor) {
					t.Errorf("[%s] expected the refusal to name the trust anchor, got %v", tc.reference, err)
				}
			} else if err != nil {
				t.Fatalf("[%s] expected the chain to resolve, got %v", tc.reference, err)
			}
			if hits != tc.expectHits {
				t.Errorf("[%s] expected %d fetches of the omitted anchor's entity configuration, got %d: the identifier check needs no network", tc.reference, tc.expectHits, hits)
			}
		})
	}
}

func TestBuildTrustChain_TheAnchorItWalkedToIsCheckedAgainstTheConfiguredKeys(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"ta"}, "ta": {}})

	tests := []struct {
		name            string
		reference       string
		configure       func(t *testing.T) map[model.EntityIdentifier]josemodel.Jwks
		expectErr       string
		expectNoNetwork bool
	}{
		{
			name:      "no anchors configured",
			reference: "4",
			configure: func(*testing.T) map[model.EntityIdentifier]josemodel.Jwks { return nil },
		},
		{
			name:      "the anchor's own key configured",
			reference: "10.2",
			configure: func(t *testing.T) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{tp.id["ta"]: anchorKeySet(t, tp.keys["ta"].Public(), nil)}
			},
		},
		{
			name:      "another entity's key configured for the anchor",
			reference: "10.2",
			configure: func(t *testing.T) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{tp.id["ta"]: anchorKeySet(t, chainSigningKey(t).Public(), nil)}
			},
			expectErr: "not signed by any key configured for it",
		},
		{
			name:      "anchors configured but not the one requested",
			reference: "10.2",
			configure: func(t *testing.T) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{"https://other-anchor.example.com": anchorKeySet(t, tp.keys["ta"].Public(), nil)}
			},
			expectErr:       "not one this deployment is configured to trust",
			expectNoNetwork: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp.mu.Lock()
			tp.hits["leaf"], tp.hits["ta"] = 0, 0
			tp.mu.Unlock()

			cfg := model.Configuration{HttpClient: tp.server.Client(), TrustAnchors: tc.configure(t)}
			_, _, _, err := BuildTrustChain(t.Context(), cfg, tp.id["leaf"], tp.id["ta"], resolvecache.New())

			tp.mu.Lock()
			walked := tp.hits["leaf"] + tp.hits["ta"]
			tp.mu.Unlock()

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the chain to build, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the built chain's anchor to be refused", tc.reference)
			}
			if !errors.Is(err, model.ErrInvalidTrustAnchor) {
				t.Errorf("[%s] expected the refusal to name the trust anchor, got %v", tc.reference, err)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
			if tc.expectNoNetwork && walked != 0 {
				t.Errorf("[%s] an anchor this deployment does not trust is decidable with no network, yet %d entity configurations were fetched", tc.reference, walked)
			}
		})
	}
}

func TestVerifyTrustAnchor_TheLastEntryMustBeTheAnchorsOwnEntityConfiguration(t *testing.T) {
	const other = model.EntityIdentifier("https://other.example.com")

	anchorKey := chainSigningKey(t)
	now := time.Now().UTC()

	signedWith := func(t *testing.T, iss, sub model.EntityIdentifier) (string, model.EntityStatement) {
		t.Helper()
		claims := map[string]any{
			"iss":  string(iss),
			"sub":  string(sub),
			"iat":  now.Unix(),
			"exp":  now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, anchorKey),
		}
		signed := chainSignStatement(t, anchorKey, claims)
		return signed, model.EntityStatement{Iss: iss, Sub: sub}
	}

	tests := []struct {
		name      string
		reference string
		iss       model.EntityIdentifier
		sub       model.EntityIdentifier
		expectErr bool
	}{
		{name: "the anchor's own entity configuration", reference: "10.2", iss: chainAnchor, sub: chainAnchor},
		{name: "a statement the anchor issued about another entity", reference: "10.2", iss: chainAnchor, sub: other, expectErr: true},
		{name: "a statement another entity issued about the anchor", reference: "10.2", iss: other, sub: chainAnchor, expectErr: true},
		{name: "a statement about neither", reference: "10.2", iss: other, sub: other, expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signed, parsed := signedWith(t, tc.iss, tc.sub)
			cfg := model.Configuration{TrustAnchors: map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: anchorKeySet(t, anchorKey.Public(), nil)}}

			err := verifyTrustAnchor(t.Context(), cfg, chainAnchor, signed, parsed)
			if !tc.expectErr {
				if err != nil {
					t.Fatalf("[%s] expected the anchor's own entity configuration to be accepted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] section 10.2 names ES[i] as the trust anchor's entity configuration, so iss and sub must both be the anchor", tc.reference)
			}
			if !errors.Is(err, model.ErrInvalidTrustAnchor) {
				t.Errorf("[%s] expected the refusal to name the trust anchor, got %v", tc.reference, err)
			}
			if !strings.Contains(err.Error(), "entity configuration of the requested trust anchor") {
				t.Errorf("[%s] expected the refusal to say the chain does not end in the anchor's entity configuration, got %v", tc.reference, err)
			}
		})
	}
}
