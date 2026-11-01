package subordinate_statement

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_HoldsTheStatementToTheConfiguredAlgorithms(t *testing.T) {
	const (
		trustAnchor = model.EntityIdentifier("https://ta.example.com")
		leaf        = model.EntityIdentifier("https://leaf.example.com")
	)
	issuerKey := testKey(t)
	issuerJwk := testPublicJwk(t, issuerKey.Public(), "ta")
	delete(issuerJwk, "alg")
	issuer := testIssuerStatement(t, trustAnchor, issuerJwk)
	body := map[string]any{
		"iss":  string(trustAnchor),
		"sub":  string(leaf),
		"iat":  time.Now().UTC().Unix(),
		"exp":  time.Now().Add(time.Hour).UTC().Unix(),
		"jwks": map[string]any{"keys": []any{testPublicJwk(t, testKey(t).Public(), "leaf")}},
	}
	statement := testSign(t, issuerKey, map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "PS256"}, body)

	if _, err := Validate(t.Context(), model.Configuration{SigningAlgorithms: []jwa.Algorithm{jwa.RS256, jwa.PS256}}, issuer, statement); err != nil {
		t.Fatalf("the fixture is wrong: a list naming PS256 must accept it, got %v", err)
	}
	_, err := Validate(t.Context(), model.Configuration{SigningAlgorithms: []jwa.Algorithm{jwa.RS256}}, issuer, statement)
	if !errors.Is(err, model.ErrInvalidTrustChain) {
		t.Fatalf("[3.2] a subordinate statement signed with an algorithm the deployment does not accept is refused, got %v", err)
	}
	if strings.Contains(err.Error(), "PS256") {
		t.Errorf("the refusal must not carry the alg the peer chose, got %v", err)
	}
}
