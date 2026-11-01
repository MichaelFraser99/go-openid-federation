package entity_configuration

import (
	"context"
	"fmt"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestPublishedKeySet_LooksUpEachKeyIDOnceThroughTheIndex(t *testing.T) {
	authority, _ := issuanceSigner(t)
	keys := make([]josemodel.Signer, 2)
	for i := range keys {
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		keys[i] = signer
	}
	ownKeys := make([]map[string]any, 3)
	for i := range ownKeys {
		public, err := jwk.PublicJwk(keys[0].Public())
		if err != nil {
			t.Fatalf("failed to read a public key: %v", err)
		}
		(*public)["kid"] = fmt.Sprintf("own-%d", i)
		ownKeys[i] = *public
	}

	distinct := func(i int) (string, josemodel.Signer, string) {
		return fmt.Sprintf("signer-%d", i), keys[i%2], "ES256"
	}
	pairsSharingAKeyID := func(i int) (string, josemodel.Signer, string) {
		return fmt.Sprintf("signer-%d", i/2), keys[i%2], "ES256"
	}
	unsignable := func(i int) (string, josemodel.Signer, string) {
		return fmt.Sprintf("signer-%d", i), keys[i%2], "EdDSA"
	}

	tests := []struct {
		name      string
		signers   int
		own       []map[string]any
		signer    func(i int) (string, josemodel.Signer, string)
		lookups   int
		published int
	}{
		{name: "50 signers under distinct key IDs", signers: 50, signer: distinct, lookups: 1 + 50, published: 1 + 50},
		{name: "200 signers under distinct key IDs", signers: 200, signer: distinct, lookups: 1 + 200, published: 1 + 200},
		{name: "800 signers under distinct key IDs", signers: 800, signer: distinct, lookups: 1 + 800, published: 1 + 800},
		{name: "200 signers beside three keys of the authority's own", signers: 200, own: ownKeys, signer: distinct, lookups: 3 + 1 + 200, published: 3 + 1 + 200},
		{name: "200 signers in pairs sharing a key ID with different keys", signers: 200, signer: pairsSharingAKeyID, lookups: 1 + 200, published: 1 + 100},
		{name: "200 signers whose algorithm cannot be signed with", signers: 200, signer: unsignable, lookups: 1, published: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			intermediate := &model.IntermediateConfiguration{}
			for i := range tc.signers {
				kid, signer, algorithm := tc.signer(i)
				intermediate.AddSubordinate(model.EntityIdentifier(fmt.Sprintf("https://s%04d.example.com", i)), &model.SubordinateConfiguration{
					SignerConfiguration: &model.SignerConfiguration{Algorithm: algorithm, Signer: signer, KeyID: kid},
				})
			}
			cfg := model.ServerConfiguration{
				SignerConfiguration:       authority,
				IntermediateConfiguration: intermediate,
				EntityConfiguration:       model.EntityStatement{JWKs: josemodel.Jwks{Keys: tc.own}},
			}

			index, err := publishedKeySet(context.Background(), cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if index.lookups != tc.lookups {
				t.Errorf("every key ID must be looked up once, through the index, so building the set stays linear in the signers: expected %d lookups, got %d", tc.lookups, index.lookups)
			}
			if len(index.jwks.Keys) != tc.published {
				t.Errorf("expected %d published keys, got %d", tc.published, len(index.jwks.Keys))
			}
			seen := map[string]bool{}
			for _, key := range index.jwks.Keys {
				kid, _ := key["kid"].(string)
				if seen[kid] {
					t.Fatalf("[3.1.1] every key in the jwks claim must carry a unique kid, %q appears twice", kid)
				}
				seen[kid] = true
			}
		})
	}
}
