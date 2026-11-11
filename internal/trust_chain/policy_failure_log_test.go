package trust_chain

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_APolicyThatCannotBeAppliedIsLoggedWithoutThePeersValues(t *testing.T) {
	const (
		subjectMarker = "subject-chose-this-value"
		privateMarker = "jpsQnnGQmL-YBIffH1136cLvhgLlb8TXx0cfw3xQk9Q"
		policyMarker  = "superior-chose-this-value"
	)
	subjectMetadata := func() map[string]any {
		return map[string]any{"federation_entity": map[string]any{
			"contacts": []any{"leaf@leaf.example.com"},
			"x_note":   subjectMarker,
			"x_signing": map[string]any{
				"kty": "EC", "crv": "P-256", "kid": "leaked",
				"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				"y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
				"d": privateMarker,
			},
		}}
	}

	tests := []struct {
		name   string
		policy map[string]any
	}{
		{
			name: "an essential parameter the subject does not publish",
			policy: map[string]any{
				"x_pinned":          map[string]any{"value": policyMarker},
				"missing_parameter": map[string]any{"essential": true},
			},
		},
		{
			name: "an object parameter that is not one of the allowed objects",
			policy: map[string]any{
				"x_signing": map[string]any{"one_of": []any{map[string]any{"kid": policyMarker}}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain := chainWithClaims(t, subjectMetadata(), map[string]any{"metadata_policy": map[string]any{"federation_entity": tc.policy}})

			var logs bytes.Buffer
			cfg := model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
			_, err := resolveTrustingSuppliedAnchor(t, t.Context(), cfg, chainAnchor, chainAnchor, chain, nil)
			if !errors.Is(err, model.ErrInvalidMetadata) {
				t.Fatalf("[6.1.4.1] expected a policy that cannot be applied to be refused as invalid metadata, got %v", err)
			}

			logged := false
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, `"msg":"failed to apply policy"`) && strings.Contains(line, string(chainSubject)) {
					logged = true
				}
			}
			if !logged {
				t.Errorf("expected the failure logged with the subject named, got %s", logs.String())
			}
			for _, marker := range []string{privateMarker, subjectMarker, policyMarker} {
				if strings.Contains(logs.String(), marker) {
					t.Errorf("expected no value the peer or its superior chose in the log, found %q in %s", marker, logs.String())
				}
			}
		})
	}
}
