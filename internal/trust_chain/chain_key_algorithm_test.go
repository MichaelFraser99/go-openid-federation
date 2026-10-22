package trust_chain

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestVerifyChainLinks_TheAlgorithmASuperiorPublishesBindsItsSubordinate(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		keyAlg    any
		expectErr bool
	}{
		{name: "the algorithm the subordinate signs with", reference: "RFC 8725 3.1", keyAlg: "RS256"},
		{name: "no algorithm published leaves the key unconstrained", reference: "RFC 7517 4.4", keyAlg: nil},
		{name: "an algorithm the subordinate does not sign with", reference: "RFC 8725 3.1", keyAlg: "PS256", expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			subjectKey := chainSigningKey(t)
			anchorKey := chainSigningKey(t)
			now := time.Now().UTC()

			registered := chainJwks(t, subjectKey)
			for _, key := range registered["keys"].([]any) {
				entry := key.(map[string]any)
				if tc.keyAlg == nil {
					delete(entry, "alg")
					continue
				}
				entry["alg"] = tc.keyAlg
			}

			signed := []string{
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
					"jwks": registered,
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

			parsed := make([]model.EntityStatement, 0, len(signed))
			for _, token := range signed {
				body := strings.Split(token, ".")[1]
				raw, err := base64.RawURLEncoding.DecodeString(body)
				if err != nil {
					t.Fatalf("failed to decode a fixture statement: %v", err)
				}
				var statement model.EntityStatement
				if err := json.Unmarshal(raw, &statement); err != nil {
					t.Fatalf("failed to parse a fixture statement: %v", err)
				}
				parsed = append(parsed, statement)
			}

			var logs bytes.Buffer
			cfg := model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}

			err := verifyChainLinks(t.Context(), cfg, signed, parsed)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("[%s] expected the link to be refused", tc.reference)
				}
				if !errors.Is(err, model.ErrInvalidTrustChain) {
					t.Errorf("[%s] expected the refusal to name the trust chain, got %v", tc.reference, err)
				}
				if strings.Contains(err.Error(), "'alg'") {
					t.Errorf("[%s] the description must not carry text this server was given by a peer, got %v", tc.reference, err)
				}
				if !strings.Contains(logs.String(), "does not match the 'alg' the selected key") {
					t.Errorf("[%s] the operator must still be able to see the mismatch in the log, got %s", tc.reference, logs.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected the link to verify, got %v", tc.reference, err)
			}
		})
	}
}
