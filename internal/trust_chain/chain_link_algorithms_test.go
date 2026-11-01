package trust_chain

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestVerifyChainLinks_HoldsEachLinkToTheConfiguredAlgorithms(t *testing.T) {
	anchorKey, subjectKey := chainSigningKey(t), chainSigningKey(t)
	now := time.Now().UTC()
	signed := []string{
		chainSignStatementAs(t, subjectKey, jwa.RS256, map[string]any{
			"iss": string(chainSubject), "sub": string(chainSubject), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, subjectKey), "authority_hints": []any{string(chainAnchor)},
		}),
		chainSignStatementAs(t, anchorKey, jwa.PS256, map[string]any{
			"iss": string(chainAnchor), "sub": string(chainSubject), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, subjectKey),
		}),
		chainSignStatementAs(t, anchorKey, jwa.RS256, map[string]any{
			"iss": string(chainAnchor), "sub": string(chainAnchor), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, anchorKey),
		}),
	}
	parsed := make([]model.EntityStatement, 0, len(signed))
	for _, token := range signed {
		raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
		if err != nil {
			t.Fatalf("failed to decode a fixture statement: %v", err)
		}
		var statement model.EntityStatement
		if err := json.Unmarshal(raw, &statement); err != nil {
			t.Fatalf("failed to parse a fixture statement: %v", err)
		}
		parsed = append(parsed, statement)
	}

	if err := verifyChainLinks(t.Context(), model.Configuration{SigningAlgorithms: []jwa.Algorithm{jwa.RS256, jwa.PS256}}, signed, parsed); err != nil {
		t.Fatalf("the fixture is wrong: a list naming PS256 must accept the links, got %v", err)
	}
	err := verifyChainLinks(t.Context(), model.Configuration{SigningAlgorithms: []jwa.Algorithm{jwa.RS256}}, signed, parsed)
	if !errors.Is(err, model.ErrInvalidTrustChain) {
		t.Fatalf("[3.2] a link signed with an algorithm the deployment does not accept is refused, got %v", err)
	}
}
