package subordinate_statement

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

type otherPublicKeySigner struct {
	josemodel.Signer
	public crypto.PublicKey
}

func (o otherPublicKeySigner) Public() crypto.PublicKey { return o.public }

func TestNew_ASignerFaultIsAnUnusableRecordOnlyWhenTheRecordSuppliedTheSigner(t *testing.T) {
	signerFor := func(t *testing.T, algorithm jwa.Algorithm) josemodel.Signer {
		t.Helper()
		signer, err := jws.GetSigner(algorithm, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		return signer
	}

	faults := map[string]func(t *testing.T) model.SignerConfiguration{
		"an empty key id": func(t *testing.T) model.SignerConfiguration {
			return model.SignerConfiguration{Algorithm: "ES256", Signer: signerFor(t, jwa.ES256)}
		},
		"an algorithm this library does not issue with": func(t *testing.T) model.SignerConfiguration {
			return model.SignerConfiguration{Algorithm: "HS256", KeyID: "signer", Signer: signerFor(t, jwa.ES256)}
		},
		"an RSA signer declared as ES256": func(t *testing.T) model.SignerConfiguration {
			return model.SignerConfiguration{Algorithm: "ES256", KeyID: "signer", Signer: signerFor(t, jwa.RS256)}
		},
		"a signature that does not verify under the signer's public key": func(t *testing.T) model.SignerConfiguration {
			return model.SignerConfiguration{Algorithm: "ES256", KeyID: "signer", Signer: otherPublicKeySigner{Signer: signerFor(t, jwa.ES256), public: signerFor(t, jwa.ES256).Public()}}
		},
	}

	for name, fault := range faults {
		for _, recordsOwn := range []bool{true, false} {
			owner := "the authority's signer"
			if recordsOwn {
				owner = "the record's own signer"
			}
			t.Run(name+" on "+owner, func(t *testing.T) {
				subjectKey := testKey(t)
				signer := fault(t)
				record := &model.SubordinateConfiguration{
					JWKs: josemodel.Jwks{Keys: []map[string]any{testPublicJwk(t, subjectKey.Public(), "leaf")}},
				}
				if recordsOwn {
					record.SignerConfiguration = &signer
				}
				retrieve := func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
					return record, &signer, nil
				}
				cfg := model.ServerConfiguration{
					EntityIdentifier:          "https://ta.example.com",
					IntermediateConfiguration: &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
				}

				_, err := New(t.Context(), "https://leaf.example.com", retrieve, cfg)
				if err == nil {
					t.Fatalf("expected the statement to be refused")
				}
				if errors.Is(err, ErrUnusableRecord) != recordsOwn {
					t.Errorf("expected an unusable record to be %t, because only a signer the record supplies is that record's fault, got %v", recordsOwn, err)
				}
			})
		}
	}
}
