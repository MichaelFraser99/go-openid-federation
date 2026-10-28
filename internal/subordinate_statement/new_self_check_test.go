package subordinate_statement

import (
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func selfCheckRetriever(t *testing.T) func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build signer: %v", err)
	}
	return func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
		return &model.SubordinateConfiguration{
			JWKs: josemodel.Jwks{Keys: []map[string]any{{"kid": "leaf", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}}},
		}, &model.SignerConfiguration{
			Signer:    signer,
			KeyID:     "ta",
			Algorithm: "ES256",
		}, nil
	}
}

func TestNew_RefusesSubordinateStatementsItsOwnParserRejects(t *testing.T) {
	tests := []struct {
		name    string
		step    string
		subject model.EntityIdentifier
	}{
		{name: "a subject over plain http", step: "1.2", subject: "http://leaf.example.com"},
		{name: "a subject carrying userinfo", step: "1.2", subject: "https://leaf.example.com@evil.example"},
		{name: "a subject carrying a fragment", step: "1.2", subject: "https://leaf.example.com#f"},
		{name: "a subject carrying a query", step: "1.2", subject: "https://leaf.example.com?x=1"},
	}

	cfg := model.ServerConfiguration{
		EntityIdentifier: "https://ta.example.com",
		IntermediateConfiguration: &model.IntermediateConfiguration{
			SubordinateStatementLifetime: time.Hour,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, err := New(t.Context(), tc.subject, selfCheckRetriever(t), cfg)
			if err == nil {
				t.Fatalf("[%s] expected issuance to be refused, got a signed statement %v", tc.step, token)
			}
			if !strings.Contains(err.Error(), "refusing to publish") {
				t.Fatalf("[%s] expected a refusal to publish, got %v", tc.step, err)
			}
		})
	}
}

func TestNew_RefusesANegativeSubordinateLifetime(t *testing.T) {
	cfg := model.ServerConfiguration{
		EntityIdentifier: "https://ta.example.com",
		IntermediateConfiguration: &model.IntermediateConfiguration{
			SubordinateStatementLifetime: -time.Hour,
		},
	}

	if _, err := New(t.Context(), "https://leaf.example.com", selfCheckRetriever(t), cfg); err == nil {
		t.Fatal("expected a negative lifetime to be refused")
	} else if !strings.Contains(err.Error(), "must not be negative") {
		t.Fatalf("expected the negative lifetime to be named, got %v", err)
	}
}

func TestNew_IssuedSubordinateStatementSurvivesItsOwnParser(t *testing.T) {
	tests := []struct {
		name     string
		lifetime time.Duration
	}{
		{name: "an explicit lifetime", lifetime: time.Hour},
		{name: "no lifetime falls back to the default", lifetime: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.ServerConfiguration{
				EntityIdentifier: "https://ta.example.com",
				IntermediateConfiguration: &model.IntermediateConfiguration{
					SubordinateStatementLifetime: tc.lifetime,
				},
			}

			token, err := New(t.Context(), "https://leaf.example.com", selfCheckRetriever(t), cfg)
			if err != nil {
				t.Fatalf("expected the statement to be issued, got %v", err)
			}

			statement := parseIssuedStatement(t, *token)
			if statement.Iat >= statement.Exp {
				t.Errorf("expected a positive lifetime, got iat %d and exp %d", statement.Iat, statement.Exp)
			}
			if statement.Sub != "https://leaf.example.com" {
				t.Errorf("expected the subject to be carried, got %q", statement.Sub)
			}
		})
	}
}
