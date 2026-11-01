package entity_configuration

import (
	"fmt"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_IssuesAnEntityConfigurationSignedWithMLDSA(t *testing.T) {
	for _, alg := range []jwa.Algorithm{jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87} {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := jws.GetSigner(alg, nil)
			if err != nil {
				t.Fatalf("failed to build the signer: %v", err)
			}
			cfg := model.ServerConfiguration{
				EntityIdentifier:            "https://ta.example.com",
				SignerConfiguration:         model.SignerConfiguration{KeyID: "ml-key", Algorithm: alg.String(), Signer: signer},
				EntityConfigurationLifetime: time.Hour,
			}

			token, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("[RFC 9964] expected an entity configuration signed with %s, got %v", alg, err)
			}
			keys := issuedClaims(t, *token)["jwks"].(map[string]any)["keys"].([]any)
			if len(keys) != 1 {
				t.Fatalf("expected the signing key alone in the published set, got %d keys", len(keys))
			}
			key := keys[0].(map[string]any)
			if key["kty"] != "AKP" || key["alg"] != alg.String() || key["kid"] != "ml-key" {
				t.Errorf("[RFC 9964] expected an AKP key published for %s, got %v", alg, key)
			}
			if _, leaked := key["priv"]; leaked {
				t.Error("[RFC 9964] the published key carries its private seed")
			}
			if _, err := Validate(t.Context(), model.Configuration{}, cfg.EntityIdentifier, *token); err != nil {
				t.Errorf("the entity configuration this server issued must validate, got %v", err)
			}
		})
	}
}

func TestValidate_AnEntityConfigurationCarryingManyMLDSA87KeysFitsTheDefaultBounds(t *testing.T) {
	const keyCount = 10
	signer, err := jws.GetSigner(jwa.MLDSA87, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	keys := make([]map[string]any, 0, keyCount)
	for i := range keyCount {
		spare, err := jws.GetSigner(jwa.MLDSA87, nil)
		if err != nil {
			t.Fatalf("failed to build a spare signer: %v", err)
		}
		published, err := jwk.PublicJwk(spare.Public())
		if err != nil {
			t.Fatalf("failed to build a spare jwk: %v", err)
		}
		(*published)["kid"] = fmt.Sprintf("spare-%d", i)
		keys = append(keys, *published)
	}
	cfg := model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		SignerConfiguration:         model.SignerConfiguration{KeyID: "ml-key", Algorithm: jwa.MLDSA87.String(), Signer: signer},
		EntityConfigurationLifetime: time.Hour,
		EntityConfiguration:         model.EntityStatement{JWKs: josemodel.Jwks{Keys: keys}},
	}

	token, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("expected the configuration to be issued, got %v", err)
	}
	if size := int64(len(*token)); size > model.DefaultMaxPeerResponseBytes {
		t.Fatalf("the fixture is wrong: %d bytes is over the default response bound before this test asks anything", size)
	}
	if _, err := Validate(t.Context(), model.Configuration{}, cfg.EntityIdentifier, *token); err != nil {
		t.Errorf("[RFC 9964] eleven ML-DSA-87 keys must fit the default value and byte bounds, got %v", err)
	}
}
