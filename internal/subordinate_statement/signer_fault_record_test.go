package subordinate_statement

import (
	"context"
	"crypto"
	"errors"
	"io"
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

type failingSigner struct {
	public crypto.PublicKey
	err    error
}

func (f failingSigner) Public() crypto.PublicKey { return f.public }

func (f failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, f.err }

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
		"a signer that refuses to sign": func(t *testing.T) model.SignerConfiguration {
			return model.SignerConfiguration{Algorithm: "ES256", KeyID: "signer", Signer: failingSigner{public: signerFor(t, jwa.ES256).Public(), err: errors.New("key disabled")}}
		},
		"a throttled signer": func(t *testing.T) model.SignerConfiguration {
			return model.SignerConfiguration{Algorithm: "ES256", KeyID: "signer", Signer: failingSigner{public: signerFor(t, jwa.ES256).Public(), err: model.NewTemporarilyUnavailableError("the key store is throttling requests")}}
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
				want := recordsOwn && name != "a throttled signer"
				if errors.Is(err, ErrUnusableRecord) != want {
					t.Errorf("expected an unusable record to be %t: only a signer the record supplies is that record's fault, and a throttle is left to fail the page because key stores are usually shared, got %v", want, err)
				}
				if name == "a throttled signer" && !errors.Is(err, model.ErrTemporarilyUnavailable) {
					t.Errorf("[8.9 temporarily_unavailable] expected a throttle to keep its class, got %v", err)
				}
			})
		}
	}
}

func TestNew_ASigningFailureAfterTheRequestEndedIsNotTheRecordsFault(t *testing.T) {
	tests := map[string]struct {
		cancel    bool
		signerErr error
		perRecord bool
	}{
		"the request cancelled while the record's signer ran":                  {cancel: true, signerErr: context.Canceled},
		"the request's deadline passed while the record's signer ran":          {cancel: true, signerErr: context.DeadlineExceeded},
		"the record's signer timing out on its own while the request is alive": {signerErr: context.DeadlineExceeded, perRecord: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ec, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build a signer: %v", err)
			}
			signer := model.SignerConfiguration{Algorithm: "ES256", KeyID: "signer", Signer: failingSigner{public: ec.Public(), err: tc.signerErr}}
			subjectKey := testKey(t)
			record := &model.SubordinateConfiguration{
				JWKs:                josemodel.Jwks{Keys: []map[string]any{testPublicJwk(t, subjectKey.Public(), "leaf")}},
				SignerConfiguration: &signer,
			}
			retrieve := func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
				return record, &signer, nil
			}
			cfg := model.ServerConfiguration{
				EntityIdentifier:          "https://ta.example.com",
				IntermediateConfiguration: &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancel {
				cancel()
			}

			_, err = New(ctx, "https://leaf.example.com", retrieve, cfg)
			if err == nil {
				t.Fatalf("expected the statement to be refused")
			}
			if errors.Is(err, ErrUnusableRecord) != tc.perRecord {
				t.Errorf("expected an unusable record to be %t: a request that ended is not the record's fault, but the record's own signer timing out is, got %v", tc.perRecord, err)
			}
		})
	}
}
