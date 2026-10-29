package trust_chain

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
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

func chainSignStatementWithKid(t *testing.T, signer crypto.Signer, kid string, body map[string]any) string {
	t.Helper()
	token, err := jwt.New(signer, map[string]any{"kid": kid, "typ": "entity-statement+jwt", "alg": "RS256"}, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to sign statement: %v", err)
	}
	return *token
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

			_, err := resolveTrustingSuppliedAnchor(t, t.Context(), model.Configuration{}, chainAnchor, tc.requested, chain, nil)
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

func forgedChain(t *testing.T, attackerKey *rsa.PrivateKey, subject, anchor model.EntityIdentifier) []string {
	t.Helper()
	now := time.Now().UTC()
	return []string{
		chainSignStatement(t, attackerKey, map[string]any{
			"iss":             string(subject),
			"sub":             string(subject),
			"iat":             now.Unix(),
			"exp":             now.Add(time.Hour).Unix(),
			"jwks":            chainJwks(t, attackerKey),
			"authority_hints": []any{string(anchor)},
			"metadata":        map[string]any{"federation_entity": map[string]any{"contacts": []any{"attacker@impostor.example.com"}}},
		}),
		chainSignStatement(t, attackerKey, map[string]any{
			"iss":  string(anchor),
			"sub":  string(subject),
			"iat":  now.Unix(),
			"exp":  now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, attackerKey),
		}),
		chainSignStatement(t, attackerKey, map[string]any{
			"iss":      string(anchor),
			"sub":      string(anchor),
			"iat":      now.Unix(),
			"exp":      now.Add(time.Hour).Unix(),
			"jwks":     chainJwks(t, attackerKey),
			"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": string(anchor) + "/fetch"}},
		}),
	}
}

func TestResolveMetadata_AForgedAnchorIsRefusedWhetherOrNotKeysAreHeld(t *testing.T) {
	attackerKey := chainSigningKey(t)
	anchorKey := chainSigningKey(t)

	tests := []struct {
		name      string
		reference string
		anchors   map[model.EntityIdentifier]josemodel.Jwks
		expectErr error
		expectMsg string
	}{
		{
			name:      "no keys held and no client to fetch the real anchor with",
			reference: "10.2",
			expectErr: model.ErrServerError,
		},
		{
			name:      "the real anchor's key held",
			reference: "10.2",
			anchors:   map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: anchorKeySet(t, anchorKey.Public(), nil)},
			expectErr: model.ErrInvalidTrustAnchor,
			expectMsg: "not signed by any key configured for it",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.Configuration{TrustAnchors: tc.anchors}
			_, err := ResolveMetadata(t.Context(), cfg, chainAnchor, chainAnchor, forgedChain(t, attackerKey, chainSubject, chainAnchor), nil)
			if err == nil {
				t.Fatalf("[%s] a chain signed throughout by the attacker's own key must not resolve", tc.reference)
			}
			if !errors.Is(err, tc.expectErr) {
				t.Errorf("[%s] expected %v, got %v", tc.reference, tc.expectErr, err)
			}
			if !strings.Contains(err.Error(), tc.expectMsg) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectMsg, err)
			}
		})
	}
}

func TestResolveMetadata_WithNoKeysHeldTheAnchorIsFetchedNotTakenFromTheChain(t *testing.T) {
	client, subject, anchor := federationWithClaims(t, "example.com", federationClaims{})

	_, err := ResolveMetadata(t.Context(), model.Configuration{HttpClient: client}, anchor, anchor, forgedChain(t, chainSigningKey(t), subject, anchor), nil)
	if err == nil {
		t.Fatal("[10.2] a chain whose anchor configuration the caller forged must be checked against the anchor's real configuration, and refused")
	}
	if !errors.Is(err, model.ErrInvalidTrustChain) {
		t.Errorf("[10.2] expected the forged link to be refused as an invalid trust chain, got %v", err)
	}

	built, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: client}, subject, anchor, nil)
	if err != nil {
		t.Fatalf("the fixture is wrong: the genuine chain does not build, %v", err)
	}
	if _, err := ResolveMetadata(t.Context(), model.Configuration{HttpClient: client}, anchor, anchor, built, nil); err != nil {
		t.Errorf("[10.2] a genuine chain with no keys held must still resolve against the anchor's fetched configuration, got %v", err)
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
			name:      "no anchors configured, so the anchor's own configuration must be fetched, and there is no client",
			reference: "10.2",
			configure: func(*testing.T, *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks { return nil },
			expectErr: "no http client present",
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
			name:      "an anchor whose configured key has no kty is this deployment's own fault",
			reference: "8.9",
			configure: func(*testing.T, *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: {Keys: []map[string]any{{"kid": "broken"}}}}
			},
			expectErr: "no key that can verify a signature",
		},
		{
			name:      "an anchor configured with an Ed25519 key this library cannot verify with is this deployment's own fault",
			reference: "8.9",
			configure: func(*testing.T, *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: {Keys: []map[string]any{{"kid": "ed", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}}}
			},
			expectErr: "no key that can verify a signature",
		},
		{
			name:      "an anchor configured with a symmetric key is this deployment's own fault",
			reference: "8.9",
			configure: func(*testing.T, *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: {Keys: []map[string]any{{"kid": "oct", "kty": "oct", "k": "AQAB"}}}}
			},
			expectErr: "no key that can verify a signature",
		},
		{
			name:      "an anchor configured with an RSA key carrying no modulus is this deployment's own fault",
			reference: "8.9",
			configure: func(*testing.T, *rsa.PrivateKey) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: {Keys: []map[string]any{{"kid": "rsa", "kty": "RSA", "e": "AQAB"}}}}
			},
			expectErr: "no key that can verify a signature",
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
				if strings.Contains(tc.expectErr, "can verify a signature") || strings.Contains(tc.expectErr, "no http client") {
					if !errors.Is(err, model.ErrServerError) {
						t.Errorf("[%s] a fault in this deployment's own configuration is a server fault, got %v", tc.reference, err)
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

func TestResolveMetadata_ACallerSuppliedChainDrivesNoFetchItCannotUse(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"ta"}, "ta": {}})
	cfg := model.Configuration{HttpClient: tp.server.Client()}

	leafEC := createEntityStatement(t, tp.id["leaf"], tp.id["leaf"], []model.EntityIdentifier{tp.id["ta"]}, tp.keys["leaf"], false)
	subordinateStatement := createSubordinateStatement(t, tp.id["ta"], tp.id["leaf"], tp.keys["ta"], tp.keys["leaf"].Public())

	tests := []struct {
		name      string
		reference string
		chain     []string
		expectErr error
	}{
		{
			name:      "a chain of one subordinate statement",
			reference: "10.2",
			chain:     []string{subordinateStatement},
			expectErr: model.ErrInvalidTrustChain,
		},
		{
			name:      "a chain whose subordinate statement is above its subject's configuration",
			reference: "10.2",
			chain:     []string{leafEC, subordinateStatement},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp.mu.Lock()
			tp.hits["ta"] = 0
			tp.mu.Unlock()

			_, err := ResolveMetadata(t.Context(), cfg, tp.id["leaf"], tp.id["ta"], tc.chain, resolvecache.New())

			tp.mu.Lock()
			hits := tp.hits["ta"]
			tp.mu.Unlock()

			if tc.expectErr == nil {
				if err != nil {
					t.Fatalf("[%s] expected the chain to resolve, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] a chain with no statement about its subject can never resolve", tc.reference)
			}
			if !errors.Is(err, tc.expectErr) {
				t.Errorf("[%s] expected %v, got %v", tc.reference, tc.expectErr, err)
			}
			if hits != 0 {
				t.Errorf("[%s] a chain too short to resolve must buy no outbound request, got %d", tc.reference, hits)
			}
		})
	}
}

func TestResolveMetadata_AnUnreachableAnchorIsNotAServerFault(t *testing.T) {
	statuses := []int{401, 403, 404, 418, 500, 503}

	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var served int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				served++
				w.WriteHeader(status)
			}))
			t.Cleanup(server.Close)

			anchor := model.EntityIdentifier(server.URL)
			leafKey := chainSigningKey(t)
			now := time.Now().UTC()

			leafEC := chainSignStatement(t, leafKey, map[string]any{
				"iss":             string(chainSubject),
				"sub":             string(chainSubject),
				"iat":             now.Unix(),
				"exp":             now.Add(time.Hour).Unix(),
				"jwks":            chainJwks(t, leafKey),
				"authority_hints": []any{string(anchor)},
				"metadata":        map[string]any{},
			})
			subordinateStatement := chainSignStatement(t, leafKey, map[string]any{
				"iss":  string(anchor),
				"sub":  string(chainSubject),
				"iat":  now.Unix(),
				"exp":  now.Add(time.Hour).Unix(),
				"jwks": chainJwks(t, leafKey),
			})

			cfg := model.Configuration{HttpClient: server.Client()}
			_, err := ResolveMetadata(t.Context(), cfg, chainSubject, anchor, []string{leafEC, subordinateStatement}, resolvecache.New())
			if err == nil {
				t.Fatalf("[8.9] expected an unreachable trust anchor to be refused")
			}
			if errors.Is(err, model.ErrServerError) {
				t.Errorf("[8.9] a peer this server cannot reach is not an unexpected condition in this server, got %v", err)
			}
			if !errors.Is(err, model.ErrInvalidTrustAnchor) {
				t.Errorf("[8.9] expected invalid_trust_anchor for an anchor that cannot be found or used, got %v", err)
			}
			if strings.Contains(err.Error(), http.StatusText(status)) || strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Errorf("[8.9] the refusal echoes the peer's status, which makes it a probe oracle: %v", err)
			}
			if served != 1 {
				t.Errorf("[8.9] expected the anchor's configuration to be fetched once, got %d", served)
			}
		})
	}
}

func TestResolveMetadata_TheFetchedAnchorConfigurationIsWhatIsVerified(t *testing.T) {
	anchorKey := chainSigningKey(t)
	attackerKey := chainSigningKey(t)
	leafKey := chainSigningKey(t)

	anchorPub := anchorKeySet(t, anchorKey.Public(), map[string]any{"kid": "chain-key"})
	attackerPub := anchorKeySet(t, attackerKey.Public(), map[string]any{"kid": "attacker"})

	var served atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(served.Load().(string)))
	}))
	t.Cleanup(server.Close)

	anchor := model.EntityIdentifier(server.URL)
	now := time.Now().UTC()

	configuration := func(signer *rsa.PrivateKey, kid string, keys ...map[string]any) string {
		entries := make([]any, 0, len(keys))
		for _, key := range keys {
			entries = append(entries, key)
		}
		return chainSignStatementWithKid(t, signer, kid, map[string]any{
			"iss":      string(anchor),
			"sub":      string(anchor),
			"iat":      now.Unix(),
			"exp":      now.Add(time.Hour).Unix(),
			"jwks":     map[string]any{"keys": entries},
			"metadata": map[string]any{},
		})
	}

	leafEC := chainSignStatement(t, leafKey, map[string]any{
		"iss":             string(chainSubject),
		"sub":             string(chainSubject),
		"iat":             now.Unix(),
		"exp":             now.Add(time.Hour).Unix(),
		"jwks":            chainJwks(t, leafKey),
		"authority_hints": []any{string(anchor)},
		"metadata":        map[string]any{},
	})
	subordinateStatement := chainSignStatement(t, anchorKey, map[string]any{
		"iss":  string(anchor),
		"sub":  string(chainSubject),
		"iat":  now.Unix(),
		"exp":  now.Add(time.Hour).Unix(),
		"jwks": chainJwks(t, leafKey),
	})

	tests := []struct {
		name      string
		reference string
		served    string
		expectErr bool
	}{
		{
			name:      "the anchor's genuine configuration",
			reference: "10.2",
			served:    configuration(anchorKey, "chain-key", anchorPub.Keys[0]),
		},
		{
			name:      "a configuration signed by a key the anchor's set carries but this deployment does not hold",
			reference: "10.2",
			served:    configuration(attackerKey, "attacker", anchorPub.Keys[0], attackerPub.Keys[0]),
			expectErr: true,
		},
	}

	cfg := model.Configuration{
		HttpClient:   server.Client(),
		TrustAnchors: map[model.EntityIdentifier]josemodel.Jwks{anchor: {Keys: []map[string]any{anchorPub.Keys[0]}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			served.Store(tc.served)

			_, err := ResolveMetadata(t.Context(), cfg, chainSubject, anchor, []string{leafEC, subordinateStatement}, resolvecache.New())
			if !tc.expectErr {
				if err != nil {
					t.Fatalf("[%s] expected the genuine anchor configuration to resolve, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] the statement verified must be the anchor's own fetched configuration, not the caller's subordinate statement, which is genuine here", tc.reference)
			}
			if !errors.Is(err, model.ErrInvalidTrustAnchor) {
				t.Errorf("[%s] expected invalid_trust_anchor, got %v", tc.reference, err)
			}
		})
	}
}

func TestResolveMetadata_AnUnusableConfiguredSetCostsNoRequest(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		keys      []map[string]any
	}{
		{name: "an Ed25519 key", reference: "8.9", keys: []map[string]any{{"kid": "ed", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}},
		{name: "a symmetric key", reference: "8.9", keys: []map[string]any{{"kid": "oct", "kty": "oct", "k": "AQAB"}}},
		{name: "an RSA key published for an algorithm this library cannot verify with", reference: "8.9", keys: []map[string]any{{"kid": "rsa", "kty": "RSA", "n": "AQAB", "e": "AQAB", "alg": "EdDSA"}}},
		{name: "a key with no kty", reference: "8.9", keys: []map[string]any{{"kid": "broken"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp := newTopo(t, map[string][]string{"leaf": {"ta"}, "ta": {}})
			cfg := model.Configuration{
				HttpClient:   tp.server.Client(),
				TrustAnchors: map[model.EntityIdentifier]josemodel.Jwks{tp.id["ta"]: {Keys: tc.keys}},
			}

			leafEC := createEntityStatement(t, tp.id["leaf"], tp.id["leaf"], []model.EntityIdentifier{tp.id["ta"]}, tp.keys["leaf"], false)
			subordinateStatement := createSubordinateStatement(t, tp.id["ta"], tp.id["leaf"], tp.keys["ta"], tp.keys["leaf"].Public())

			for _, entry := range []struct {
				name string
				call func() error
			}{
				{
					name: "BuildTrustChain",
					call: func() error {
						_, _, _, err := BuildTrustChain(t.Context(), cfg, tp.id["leaf"], tp.id["ta"], resolvecache.New())
						return err
					},
				},
				{
					name: "ResolveMetadata with an omitted anchor",
					call: func() error {
						_, err := ResolveMetadata(t.Context(), cfg, tp.id["leaf"], tp.id["ta"], []string{leafEC, subordinateStatement}, resolvecache.New())
						return err
					},
				},
			} {
				t.Run(entry.name, func(t *testing.T) {
					tp.mu.Lock()
					tp.hits["leaf"], tp.hits["ta"] = 0, 0
					tp.mu.Unlock()

					err := entry.call()

					tp.mu.Lock()
					walked := tp.hits["leaf"] + tp.hits["ta"]
					tp.mu.Unlock()

					if !errors.Is(err, model.ErrServerError) {
						t.Errorf("[%s] a configured set this deployment cannot verify with is its own fault, got %v", tc.reference, err)
					}
					if errors.Is(err, model.ErrInvalidTrustAnchor) {
						t.Errorf("[%s] must not blame the anchor for this deployment's configuration, got %v", tc.reference, err)
					}
					if walked != 0 {
						t.Errorf("[%s] this is decidable with no I/O, yet %d requests were made", tc.reference, walked)
					}
				})
			}
		})
	}
}

func TestResolveMetadata_ACancelledAnchorFetchIsNotTheAnchorsFault(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		cancel()
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(server.Close)

	anchor := model.EntityIdentifier(server.URL)
	leafKey := chainSigningKey(t)
	now := time.Now().UTC()

	leafEC := chainSignStatement(t, leafKey, map[string]any{
		"iss":             string(chainSubject),
		"sub":             string(chainSubject),
		"iat":             now.Unix(),
		"exp":             now.Add(time.Hour).Unix(),
		"jwks":            chainJwks(t, leafKey),
		"authority_hints": []any{string(anchor)},
		"metadata":        map[string]any{},
	})
	subordinateStatement := chainSignStatement(t, leafKey, map[string]any{
		"iss":  string(anchor),
		"sub":  string(chainSubject),
		"iat":  now.Unix(),
		"exp":  now.Add(time.Hour).Unix(),
		"jwks": chainJwks(t, leafKey),
	})

	_, err := ResolveMetadata(ctx, model.Configuration{HttpClient: server.Client()}, chainSubject, anchor, []string{leafEC, subordinateStatement}, resolvecache.New())
	if !errors.Is(err, model.ErrTemporarilyUnavailable) {
		t.Fatalf("[8.9] a fetch abandoned because the caller's own context ended is a walk that did not complete, not an anchor fault, got %v", err)
	}
	if errors.Is(err, model.ErrInvalidTrustAnchor) {
		t.Errorf("[8.9] must not blame the anchor, got %v", err)
	}
}

func TestVerifyTrustAnchor_RefusesAnUnusableConfiguredSetAtTheChainToo(t *testing.T) {
	anchorKey := chainSigningKey(t)
	now := time.Now().UTC()
	signed := chainSignStatement(t, anchorKey, map[string]any{
		"iss":  string(chainAnchor),
		"sub":  string(chainAnchor),
		"iat":  now.Unix(),
		"exp":  now.Add(time.Hour).Unix(),
		"jwks": chainJwks(t, anchorKey),
	})

	tests := []struct {
		name      string
		reference string
		keys      []map[string]any
		expectErr error
	}{
		{name: "the anchor's own key", reference: "10.2", keys: []map[string]any{anchorKeySet(t, anchorKey.Public(), nil).Keys[0]}},
		{name: "an Ed25519 key", reference: "8.9", keys: []map[string]any{{"kid": "ed", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}, expectErr: model.ErrServerError},
		{name: "a key with no kty", reference: "8.9", keys: []map[string]any{{"kid": "broken"}}, expectErr: model.ErrServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.Configuration{TrustAnchors: map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: {Keys: tc.keys}}}
			err := verifyTrustAnchor(t.Context(), cfg, chainAnchor, signed, model.EntityStatement{Iss: chainAnchor, Sub: chainAnchor})

			if tc.expectErr == nil {
				if err != nil {
					t.Fatalf("[%s] expected the anchor to verify, got %v", tc.reference, err)
				}
				return
			}
			if !errors.Is(err, tc.expectErr) {
				t.Errorf("[%s] the entry check catches this first through every public entry point, so this branch is defence in depth and must still answer %v, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}
