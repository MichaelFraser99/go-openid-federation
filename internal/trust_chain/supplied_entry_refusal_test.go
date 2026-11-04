package trust_chain

import (
	"errors"
	"strings"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_ARefusedEntryIsDescribedWithoutTheParsersText(t *testing.T) {
	const marker = "peer-chosen-7Qz"
	reflectingOwners := map[string]any{"trust_mark_owners": map[string]any{
		"https://" + marker + ".example/type": map[string]any{"sub": "not a url", "jwks": map[string]any{"keys": []any{}}},
	}}

	tests := []struct {
		name        string
		entry       int
		extra       map[string]any
		description string
		class       error
		notClass    error
		reason      string
	}{
		{
			name:        "the subject's entity configuration",
			entry:       0,
			extra:       reflectingOwners,
			description: "trust chain entry 0 is not a valid entity configuration",
			class:       model.ErrInvalidTrustChain,
			notClass:    model.ErrInvalidMetadata,
			reason:      marker,
		},
		{
			name:        "the subordinate statement about the subject",
			entry:       1,
			extra:       map[string]any{"metadata_policy_crit": []any{"regexp"}},
			description: "trust chain entry 1 is not a valid subordinate statement",
			class:       model.ErrInvalidTrustChain,
			notClass:    model.ErrInvalidMetadata,
			reason:      "none of which this implementation understands",
		},
		{
			name:        "the trust anchor's entity configuration",
			entry:       2,
			extra:       reflectingOwners,
			description: "trust chain entry 2 is not a valid entity configuration",
			class:       model.ErrInvalidTrustChain,
			notClass:    model.ErrInvalidMetadata,
			reason:      marker,
		},
		{
			name:        "a metadata fault keeps its class",
			entry:       0,
			extra:       map[string]any{"metadata": map[string]any{"openid_relying_party": map[string]any{"jwks_uri": "http://" + marker + ".example"}}},
			description: "trust chain entry 0 is not a valid entity configuration",
			class:       model.ErrInvalidMetadata,
			notClass:    model.ErrInvalidTrustChain,
			reason:      "jwks_uri",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			subjectKey, anchorKey := chainSigningKey(t), chainSigningKey(t)
			now := time.Now().UTC()
			bodies := []map[string]any{
				{"iss": string(chainSubject), "sub": string(chainSubject), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": chainJwks(t, subjectKey), "authority_hints": []any{string(chainAnchor)}},
				{"iss": string(chainAnchor), "sub": string(chainSubject), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": chainJwks(t, subjectKey)},
				{"iss": string(chainAnchor), "sub": string(chainAnchor), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": chainJwks(t, anchorKey), "metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": string(chainAnchor) + "/fetch"}}},
			}
			for claim, value := range tc.extra {
				bodies[tc.entry][claim] = value
			}
			chain := []string{chainSignStatement(t, subjectKey, bodies[0]), chainSignStatement(t, anchorKey, bodies[1]), chainSignStatement(t, anchorKey, bodies[2])}
			cfg := model.Configuration{TrustAnchors: map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: anchorKeySet(t, anchorKey.Public(), map[string]any{"kid": "chain-key"})}}

			_, err := ResolveMetadata(t.Context(), cfg, chainAnchor, chainAnchor, chain, nil)
			if err == nil {
				t.Fatal("expected the chain to be refused")
			}
			if err.Error() != tc.description {
				t.Errorf("[8.9] the description must name the entry and nothing a peer chose, expected %q, got %q", tc.description, err.Error())
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("[8.9] a peer's bytes must not reach the description, got %q", err.Error())
			}
			if !errors.Is(err, tc.class) {
				t.Errorf("expected the refusal to keep the class %v, got %v", tc.class, err)
			}
			if errors.Is(err, tc.notClass) {
				t.Errorf("[8.9] the response code is chosen from the first class that matches, so the refusal must not also be %v, got %v", tc.notClass, err)
			}
			cause := errors.Unwrap(err)
			if cause == nil || !strings.Contains(cause.Error(), tc.reason) {
				t.Errorf("a Go caller must still be able to read why the entry was refused, expected a cause containing %q, got %v", tc.reason, cause)
			}
		})
	}
}

func TestSuppliedEntryRefused_AnUnclassifiedCauseIsStillAnInvalidTrustChain(t *testing.T) {
	cause := errors.New("a validation fault carrying no class")
	err := suppliedEntryRefused(cause, 3, "subordinate statement")

	if err.Error() != "trust chain entry 3 is not a valid subordinate statement" {
		t.Errorf("expected the fixed description, got %q", err.Error())
	}
	if !errors.Is(err, model.ErrInvalidTrustChain) {
		t.Errorf("[8.9] an entry the caller supplied that fails validation is the caller's fault, so it must be invalid_trust_chain rather than a server fault, got %v", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("expected the cause to stay reachable, got %v", err)
	}
}
