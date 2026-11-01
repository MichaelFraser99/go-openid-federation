package entity_configuration

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_HoldsTheEntityConfigurationToTheConfiguredAlgorithms(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	published, err := jwk.PublicJwk(key.Public())
	if err != nil {
		t.Fatalf("failed to build jwk: %v", err)
	}
	(*published)["kid"] = "leaf"
	token := rawRSAToken(t, key, map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "PS256"}, map[string]any{
		"iss":  string(leaf),
		"sub":  string(leaf),
		"iat":  time.Now().UTC().Unix(),
		"exp":  time.Now().Add(time.Hour).UTC().Unix(),
		"jwks": map[string]any{"keys": []any{*published}},
	})

	if _, err := Validate(t.Context(), model.Configuration{SigningAlgorithms: []jwa.Algorithm{jwa.RS256, jwa.PS256}}, leaf, token); err != nil {
		t.Fatalf("the fixture is wrong: a list naming PS256 must accept it, got %v", err)
	}
	_, err = Validate(t.Context(), model.Configuration{SigningAlgorithms: []jwa.Algorithm{jwa.RS256}}, leaf, token)
	if err == nil {
		t.Fatal("[3.2] an entity configuration signed with an algorithm the deployment does not accept must be refused")
	}
	if strings.Contains(err.Error(), "PS256") {
		t.Errorf("the refusal must not carry the alg the peer chose, got %v", err)
	}
}
