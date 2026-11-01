package trust_chain

import (
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func chainSignedWith(t *testing.T, anchor crypto.Signer, anchorAlg jwa.Algorithm, subject crypto.Signer, subjectAlg jwa.Algorithm) []string {
	t.Helper()
	now := time.Now().UTC()
	return []string{
		chainSignStatementAs(t, subject, subjectAlg, map[string]any{
			"iss": string(chainSubject), "sub": string(chainSubject), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, subject), "authority_hints": []any{string(chainAnchor)},
			"metadata": map[string]any{"federation_entity": map[string]any{"contacts": []any{"leaf@leaf.example.com"}}},
		}),
		chainSignStatementAs(t, anchor, anchorAlg, map[string]any{
			"iss": string(chainAnchor), "sub": string(chainSubject), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jwks": chainJwks(t, subject),
		}),
		chainSignStatementAs(t, anchor, anchorAlg, map[string]any{
			"iss": string(chainAnchor), "sub": string(chainAnchor), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jwks":     chainJwks(t, anchor),
			"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": string(chainAnchor) + "/fetch"}},
		}),
	}
}

func mlDSASigner(t *testing.T, alg jwa.Algorithm) crypto.Signer {
	t.Helper()
	signer, err := jws.GetSigner(alg, nil)
	if err != nil {
		t.Fatalf("failed to build the %s signer: %v", alg, err)
	}
	return signer
}

func TestResolveMetadata_ResolvesChainsSignedWithMLDSA(t *testing.T) {
	tests := []struct {
		name       string
		anchor     crypto.Signer
		anchorAlg  jwa.Algorithm
		subject    crypto.Signer
		subjectAlg jwa.Algorithm
	}{
		{name: "an ML-DSA-65 anchor above an RS256 subject", anchor: mlDSASigner(t, jwa.MLDSA65), anchorAlg: jwa.MLDSA65, subject: chainSigningKey(t), subjectAlg: jwa.RS256},
		{name: "an RS256 anchor above an ML-DSA-87 subject", anchor: chainSigningKey(t), anchorAlg: jwa.RS256, subject: mlDSASigner(t, jwa.MLDSA87), subjectAlg: jwa.MLDSA87},
		{name: "an ML-DSA-44 anchor above an ML-DSA-87 subject", anchor: mlDSASigner(t, jwa.MLDSA44), anchorAlg: jwa.MLDSA44, subject: mlDSASigner(t, jwa.MLDSA87), subjectAlg: jwa.MLDSA87},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain := chainSignedWith(t, tc.anchor, tc.anchorAlg, tc.subject, tc.subjectAlg)
			anchors := map[model.EntityIdentifier]josemodel.Jwks{chainAnchor: anchorKeySet(t, tc.anchor.Public(), nil)}

			resolved, err := ResolveMetadata(t.Context(), model.Configuration{TrustAnchors: anchors}, chainAnchor, chainAnchor, chain, nil)
			if err != nil {
				t.Fatalf("[3] a trust chain can mix signing algorithms, so this chain must resolve, got %v", err)
			}
			if resolved.Metadata == nil || resolved.Metadata.FederationMetadata == nil {
				t.Fatalf("expected the subject's metadata in the response, got %v", resolved.Metadata)
			}

			narrowed := []jwa.Algorithm{jwa.ES256}
			if _, err := ResolveMetadata(t.Context(), model.Configuration{TrustAnchors: anchors, SigningAlgorithms: narrowed}, chainAnchor, chainAnchor, chain, nil); !errors.Is(err, model.ErrServerError) {
				t.Errorf("[8.9] a list leaving out the configured anchor key's algorithm is this deployment's fault, got %v", err)
			}
		})
	}
}
