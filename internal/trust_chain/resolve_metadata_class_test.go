package trust_chain

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const chainEntryMarker = "chain-entry-marker-zzzz"

func unsignedStatement(t *testing.T, claims map[string]any) string {
	t.Helper()
	head, err := json.Marshal(map[string]any{"kid": "peer", "typ": "entity-statement+jwt", "alg": "ES256"})
	if err != nil {
		t.Fatalf("failed to marshal the header: %v", err)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal the body: %v", err)
	}
	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString(head),
		base64.RawURLEncoding.EncodeToString(body),
		base64.RawURLEncoding.EncodeToString([]byte("signature")),
	}, ".")
}

func TestResolveMetadata_AFinalEntryTheCallerSuppliedIsNotAServerFault(t *testing.T) {
	tests := map[string]struct {
		reference string
		claims    map[string]any
	}{
		"a sub claim that is not an entity identifier": {
			reference: "8.9 invalid_trust_chain",
			claims: map[string]any{
				"iss": "https://ta.example.com",
				"sub": "http://" + chainEntryMarker + ".example.com",
			},
		},
		"an iss claim that is not an entity identifier": {
			reference: "8.9 invalid_trust_chain",
			claims: map[string]any{
				"iss": "http://" + chainEntryMarker + ".example.com",
				"sub": "https://leaf.example.com",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ResolveMetadata(t.Context(), model.Configuration{}, "https://resolver.example.com", []string{unsignedStatement(t, tc.claims)}, resolvecache.New())
			if err == nil {
				t.Fatalf("[%s] expected the chain to be refused", tc.reference)
			}
			if !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Fatalf("[%s] expected a chain the caller supplied to be refused as an invalid trust chain, got %v", tc.reference, err)
			}
			if errors.Is(err, model.ErrServerError) {
				t.Errorf("[%s] a chain the caller supplied must not be reported as this server's fault, got %v", tc.reference, err)
			}
			if strings.Contains(err.Error(), chainEntryMarker) {
				t.Errorf("[%s] the error reflects the claim value the caller supplied: %v", tc.reference, err)
			}
		})
	}
}

func TestSubordinateStatementFailure_KeepsTheClassAndDropsThePeersText(t *testing.T) {
	tests := map[string]struct {
		reference   string
		err         error
		expectKind  error
		description string
	}{
		"a failure of this server's own": {
			reference:   "8.9 server_error",
			err:         model.NewServerError("no http client present"),
			expectKind:  model.ErrServerError,
			description: "no http client present",
		},
		"metadata the superior published": {
			reference:   "8.9 invalid_metadata",
			err:         model.NewInvalidMetadataError("invalid openid_relying_party metadata: " + chainEntryMarker),
			expectKind:  model.ErrInvalidMetadata,
			description: subordinateStatementUnusable,
		},
		"a statement the superior would not serve": {
			reference:   "8.9 invalid_trust_chain",
			err:         model.NewInvalidTrustChainError("non-200 response from " + chainEntryMarker),
			expectKind:  model.ErrInvalidTrustChain,
			description: subordinateStatementUnusable,
		},
		"a failure carrying no class at all": {
			reference:   "8.9 invalid_trust_chain",
			err:         errors.New("dial tcp 127.0.0.1:1: connect: connection refused"),
			expectKind:  model.ErrInvalidTrustChain,
			description: subordinateStatementUnusable,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := subordinateStatementFailure(tc.err)
			if !errors.Is(got, tc.expectKind) {
				t.Fatalf("[%s] expected the class the spec defines for this fault, got %v", tc.reference, got)
			}
			if got.Error() != tc.description {
				t.Fatalf("[%s] expected the description %q, got %q", tc.reference, tc.description, got.Error())
			}
			if strings.Contains(got.Error(), chainEntryMarker) {
				t.Errorf("[%s] the description reflects what the superior said: %q", tc.reference, got.Error())
			}
		})
	}
}
