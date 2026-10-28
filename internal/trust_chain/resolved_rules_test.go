package trust_chain

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func conformingProvider(issuer string) map[string]any {
	return map[string]any{"openid_provider": map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []any{"code"},
		"subject_types_supported":               []any{"public"},
		"id_token_signing_alg_values_supported": []any{"RS256"},
	}}
}

func TestResolveMetadata_AnIssuerThatIsNotTheSubjectIsRefusedOnEveryPath(t *testing.T) {
	tests := []struct {
		name             string
		subjectMetadata  map[string]any
		subordinateExtra map[string]any
		singleEntry      bool
	}{
		{
			name:            "the subject publishes another entity's issuer, with no policy in the chain",
			subjectMetadata: conformingProvider("https://attacker.example.com"),
		},
		{
			name:            "a superior's policy replaces the issuer with another entity's",
			subjectMetadata: conformingProvider(string(chainSubject)),
			subordinateExtra: map[string]any{"metadata_policy": map[string]any{"openid_provider": map[string]any{
				"issuer": map[string]any{"value": "https://attacker.example.com"},
			}}},
		},
		{
			name:            "a superior's metadata claim replaces the issuer with another entity's",
			subjectMetadata: conformingProvider(string(chainSubject)),
			subordinateExtra: map[string]any{"metadata": map[string]any{"openid_provider": map[string]any{
				"issuer": "https://attacker.example.com",
			}}},
		},
		{
			name:            "a single entry chain publishing another entity's issuer",
			subjectMetadata: conformingProvider("https://attacker.example.com"),
			singleEntry:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := chainWithClaims(t, test.subjectMetadata, test.subordinateExtra)
			anchor := chainAnchor
			if test.singleEntry {
				chain = chain[:1]
				anchor = chainSubject
			}

			_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, anchor, chain, nil)
			if err == nil {
				t.Fatal("[Connect 1.1 5.1.2] the issuer parameter MUST match the Federation Entity Identifier, so this must not resolve")
			}
			if !errors.Is(err, model.ErrInvalidMetadata) {
				t.Errorf("[8.9] metadata that cannot be resolved conformantly is invalid_metadata, got %T: %v", err, err)
			}
			if strings.Contains(err.Error(), "attacker.example.com") {
				t.Errorf("[8.9] a value a superior chose must not be echoed to the caller, got %q", err.Error())
			}
		})
	}
}

func TestResolveMetadata_AnIssuerMatchingTheSubjectResolves(t *testing.T) {
	chain := chainWithClaims(t, conformingProvider(string(chainSubject)), nil)
	if _, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chain, nil); err != nil {
		t.Errorf("[Connect 1.1 5.1.2] an issuer equal to the entity identifier must resolve, got %v", err)
	}
}

func TestResolveMetadata_APolicyCannotReinstateAValueTheParserRefuses(t *testing.T) {
	tests := []struct {
		name            string
		reference       string
		subjectMetadata map[string]any
		policy          map[string]any
	}{
		{
			name:            "an rp signing algorithm of none",
			reference:       "OIDC Registration 2",
			subjectMetadata: map[string]any{"openid_relying_party": map[string]any{"redirect_uris": []any{"https://leaf.example.com/cb"}}},
			policy: map[string]any{"openid_relying_party": map[string]any{
				"token_endpoint_auth_signing_alg": map[string]any{"value": "none"},
			}},
		},
		{
			name:            "a federation endpoint that is not https",
			reference:       "OpenID Federation 5.2.1",
			subjectMetadata: map[string]any{"federation_entity": map[string]any{"contacts": []any{"ops@leaf.example.com"}}},
			policy: map[string]any{"federation_entity": map[string]any{
				"federation_fetch_endpoint": map[string]any{"value": "http://leaf.example.com/fetch"},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := chainWithClaims(t, test.subjectMetadata, map[string]any{"metadata_policy": test.policy})
			_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chain, nil)
			if err == nil {
				t.Fatalf("[%s] the parser refuses this value on input, so a policy must not be able to put it back", test.reference)
			}
			if !errors.Is(err, model.ErrInvalidMetadata) {
				t.Errorf("[8.9] expected invalid_metadata, got %T: %v", err, err)
			}
		})
	}
}

func TestResolveMetadata_TheSubjectEntryMustBeAnEntityConfiguration(t *testing.T) {
	subjectKey := chainSigningKey(t)
	anchorKey := chainSigningKey(t)
	now := time.Now().UTC()

	leaf := map[string]any{
		"iss":             string(chainAnchor),
		"sub":             string(chainSubject),
		"iat":             now.Unix(),
		"exp":             now.Add(time.Hour).Unix(),
		"jwks":            chainJwks(t, subjectKey),
		"authority_hints": []any{string(chainAnchor)},
		"metadata":        conformingProvider(string(chainAnchor)),
	}
	subordinate := map[string]any{
		"iss":  string(chainAnchor),
		"sub":  string(chainSubject),
		"iat":  now.Unix(),
		"exp":  now.Add(time.Hour).Unix(),
		"jwks": chainJwks(t, subjectKey),
	}
	anchor := map[string]any{
		"iss":  string(chainAnchor),
		"sub":  string(chainAnchor),
		"iat":  now.Unix(),
		"exp":  now.Add(time.Hour).Unix(),
		"jwks": chainJwks(t, anchorKey),
		"metadata": map[string]any{
			"federation_entity": map[string]any{"federation_fetch_endpoint": string(chainAnchor) + "/fetch"},
		},
	}
	chain := []string{
		chainSignStatement(t, subjectKey, leaf),
		chainSignStatement(t, anchorKey, subordinate),
		chainSignStatement(t, anchorKey, anchor),
	}

	_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chain, nil)
	if err == nil {
		t.Fatal("[4] the first entry of a trust chain is the subject's own entity configuration, so a statement about someone else must be refused")
	}
	if !errors.Is(err, model.ErrInvalidTrustChain) {
		t.Errorf("[8.9] a chain whose first entry is not an entity configuration is a chain fault, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "'iss' and 'sub' claims do not match") {
		t.Errorf("[4] the refusal must name the mismatch that disqualifies the entry, got %q", err.Error())
	}
}

func TestResolveMetadata_NoValueASuperiorChoseReachesTheResponse(t *testing.T) {
	const marker = "ZZMARKER.example.com"

	tests := []struct {
		name   string
		policy map[string]any
	}{
		{
			name: "an issuer a policy replaced",
			policy: map[string]any{"openid_provider": map[string]any{
				"issuer": map[string]any{"value": "https://" + marker},
			}},
		},
		{
			name: "an endpoint a policy made unparseable",
			policy: map[string]any{"federation_entity": map[string]any{
				"federation_fetch_endpoint": map[string]any{"value": "https://" + marker + "/%zz"},
			}},
		},
		{
			name: "an endpoint a policy gave a scheme of its own choosing",
			policy: map[string]any{"federation_entity": map[string]any{
				"federation_fetch_endpoint": map[string]any{"value": strings.ToLower(marker) + "://host.example.com/fetch"},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subjectMetadata := conformingProvider(string(chainSubject))
			subjectMetadata["federation_entity"] = map[string]any{"federation_fetch_endpoint": string(chainSubject) + "/fetch"}
			chain := chainWithClaims(t, subjectMetadata, map[string]any{"metadata_policy": test.policy})
			_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chain, nil)
			if err == nil {
				t.Fatal("expected the resolution to be refused")
			}
			if !errors.Is(err, model.ErrInvalidMetadata) {
				t.Errorf("[8.9] expected invalid_metadata, got %T: %v", err, err)
			}
			if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(marker)) {
				t.Errorf("[8.9] a superior supplies this value and the caller can name the superior, so it must not be reflected: got %q", err.Error())
			}
			if !strings.Contains(err.Error(), string(chainSubject)) {
				t.Errorf("the refusal must still name the subject it concerns, got %q", err.Error())
			}
		})
	}
}
