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

func chainParseStatement(t *testing.T, signed string) model.EntityStatement {
	t.Helper()
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode a fixture statement: %v", err)
	}
	var statement model.EntityStatement
	if err := json.Unmarshal(raw, &statement); err != nil {
		t.Fatalf("failed to parse a fixture statement: %v", err)
	}
	return statement
}

func TestVerifyChainLinks_ARefusalCarriesNoTextASuperiorChose(t *testing.T) {
	const marker = "SUPERIOR-CHOSEN-MARKER"

	tests := []struct {
		name       string
		reference  string
		registered func(entry map[string]any)
		expectLog  string
	}{
		{
			name:      "a key type the library cannot parse",
			reference: "8.9",
			registered: func(entry map[string]any) {
				entry["kty"] = marker
			},
			expectLog: marker,
		},
		{
			name:      "a curve the library cannot parse",
			reference: "8.9",
			registered: func(entry map[string]any) {
				entry["kty"] = "EC"
				entry["crv"] = marker
			},
			expectLog: marker,
		},
		{
			name:      "an algorithm the subordinate does not sign with",
			reference: "RFC 8725 3.1",
			registered: func(entry map[string]any) {
				entry["alg"] = marker
			},
			expectLog: "'alg'",
		},
		{
			name:      "a modulus the library cannot decode",
			reference: "8.9",
			registered: func(entry map[string]any) {
				entry["n"] = marker + "!!!"
			},
			expectLog: "invalid base64url",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			subjectKey := chainSigningKey(t)
			anchorKey := chainSigningKey(t)
			now := time.Now().UTC()

			registered := chainJwks(t, subjectKey)
			for _, key := range registered["keys"].([]any) {
				tc.registered(key.(map[string]any))
			}

			signed := []string{
				chainSignStatement(t, subjectKey, map[string]any{
					"iss":             string(chainSubject),
					"sub":             string(chainSubject),
					"iat":             now.Unix(),
					"exp":             now.Add(time.Hour).Unix(),
					"jwks":            chainJwks(t, subjectKey),
					"authority_hints": []any{string(chainAnchor)},
					"metadata":        map[string]any{},
				}),
				chainSignStatement(t, anchorKey, map[string]any{
					"iss":  string(chainAnchor),
					"sub":  string(chainSubject),
					"iat":  now.Unix(),
					"exp":  now.Add(time.Hour).Unix(),
					"jwks": registered,
				}),
			}

			parsed := []model.EntityStatement{
				{Iss: chainSubject, Sub: chainSubject},
				chainParseStatement(t, signed[1]),
			}

			var logs bytes.Buffer
			cfg := model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}

			err := verifyChainLinks(t.Context(), cfg, signed, parsed)
			if err == nil {
				t.Fatalf("[%s] expected the link to be refused", tc.reference)
			}
			if !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[%s] expected the refusal to name the trust chain, got %v", tc.reference, err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("[%s] a superior chose this text, so it must not reach the response description: %v", tc.reference, err)
			}
			if !strings.Contains(logs.String(), tc.expectLog) {
				t.Errorf("[%s] the operator must still be able to see %q in the log, got %s", tc.reference, tc.expectLog, logs.String())
			}
		})
	}
}
