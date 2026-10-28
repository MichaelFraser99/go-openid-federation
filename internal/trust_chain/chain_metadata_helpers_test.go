package trust_chain

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const (
	chainSubject = model.EntityIdentifier("https://leaf.example.com")
	chainAnchor  = model.EntityIdentifier("https://ta.example.com")
)

func chainSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

func chainJwks(t *testing.T, signer crypto.Signer) map[string]any {
	t.Helper()
	publicJwk, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to create public jwk: %v", err)
	}
	(*publicJwk)["kid"] = "chain-key"
	return map[string]any{"keys": []any{*publicJwk}}
}

func chainSignStatement(t *testing.T, signer crypto.Signer, body map[string]any) string {
	t.Helper()
	header := map[string]any{"kid": "chain-key", "typ": "entity-statement+jwt", "alg": "RS256"}
	token, err := jwt.New(signer, header, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to sign statement: %v", err)
	}
	return *token
}

func chainWithClaims(t *testing.T, subjectMetadata map[string]any, subordinateExtra map[string]any) []string {
	t.Helper()
	subjectKey := chainSigningKey(t)
	anchorKey := chainSigningKey(t)
	now := time.Now().UTC()

	if subjectMetadata == nil {
		subjectMetadata = map[string]any{
			"federation_entity": map[string]any{"contacts": []any{"leaf@leaf.example.com"}},
		}
	}

	subject := map[string]any{
		"iss":             string(chainSubject),
		"sub":             string(chainSubject),
		"iat":             now.Unix(),
		"exp":             now.Add(time.Hour).Unix(),
		"jwks":            chainJwks(t, subjectKey),
		"authority_hints": []any{string(chainAnchor)},
		"metadata":        subjectMetadata,
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
	for k, v := range subordinateExtra {
		subordinate[k] = v
	}
	return []string{
		chainSignStatement(t, subjectKey, subject),
		chainSignStatement(t, anchorKey, subordinate),
		chainSignStatement(t, anchorKey, anchor),
	}
}

func resolvedFederationParameter(t *testing.T, result *model.ResolveResponse, parameter string) any {
	t.Helper()
	if result == nil || result.Metadata == nil || result.Metadata.FederationMetadata == nil {
		t.Fatalf("no federation_entity metadata in the result")
	}
	return (*result.Metadata.FederationMetadata)[parameter]
}

const chainIntermediate = model.EntityIdentifier("https://intermediate.example.com")

func chainThroughIntermediate(t *testing.T, immediateExtra, grandparentExtra map[string]any) []string {
	t.Helper()
	return chainThroughIntermediateWithMetadata(t, map[string]any{
		"federation_entity": map[string]any{"contacts": []any{"leaf@leaf.example.com"}},
	}, immediateExtra, grandparentExtra)
}

func chainThroughIntermediateWithMetadata(t *testing.T, subjectMetadata, immediateExtra, grandparentExtra map[string]any) []string {
	t.Helper()
	subjectKey := chainSigningKey(t)
	intermediateKey := chainSigningKey(t)
	anchorKey := chainSigningKey(t)
	now := time.Now().UTC()

	subject := map[string]any{
		"iss":             string(chainSubject),
		"sub":             string(chainSubject),
		"iat":             now.Unix(),
		"exp":             now.Add(time.Hour).Unix(),
		"jwks":            chainJwks(t, subjectKey),
		"authority_hints": []any{string(chainIntermediate)},
		"metadata":        subjectMetadata,
	}
	immediate := map[string]any{
		"iss":  string(chainIntermediate),
		"sub":  string(chainSubject),
		"iat":  now.Unix(),
		"exp":  now.Add(time.Hour).Unix(),
		"jwks": chainJwks(t, subjectKey),
	}
	grandparent := map[string]any{
		"iss":  string(chainAnchor),
		"sub":  string(chainIntermediate),
		"iat":  now.Unix(),
		"exp":  now.Add(time.Hour).Unix(),
		"jwks": chainJwks(t, intermediateKey),
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
	for k, v := range immediateExtra {
		immediate[k] = v
	}
	for k, v := range grandparentExtra {
		grandparent[k] = v
	}

	return []string{
		chainSignStatement(t, subjectKey, subject),
		chainSignStatement(t, intermediateKey, immediate),
		chainSignStatement(t, anchorKey, grandparent),
		chainSignStatement(t, anchorKey, anchor),
	}
}

func chainWithoutSubjectMetadata(t *testing.T, subordinateExtra map[string]any) []string {
	t.Helper()
	subjectKey := chainSigningKey(t)
	anchorKey := chainSigningKey(t)
	now := time.Now().UTC()

	subject := map[string]any{
		"iss":             string(chainSubject),
		"sub":             string(chainSubject),
		"iat":             now.Unix(),
		"exp":             now.Add(time.Hour).Unix(),
		"jwks":            chainJwks(t, subjectKey),
		"authority_hints": []any{string(chainAnchor)},
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
	for k, v := range subordinateExtra {
		subordinate[k] = v
	}

	return []string{
		chainSignStatement(t, subjectKey, subject),
		chainSignStatement(t, anchorKey, subordinate),
		chainSignStatement(t, anchorKey, anchor),
	}
}
