package subordinate_statement

import (
	"context"
	"crypto"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type cancelsAfterSigning struct {
	josemodel.Signer
	cancel context.CancelFunc
}

func (s cancelsAfterSigning) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := s.Signer.Sign(rand, digest, opts)
	s.cancel()
	return signature, err
}

func interruptedIssuance(t *testing.T, recordsOwn bool, cancel context.CancelFunc) (model.ServerConfiguration, func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error), josemodel.Jwks) {
	t.Helper()
	ec, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	publicJWK, err := jwk.PublicJwk(ec.Public())
	if err != nil {
		t.Fatalf("failed to read the signer's key: %v", err)
	}
	(*publicJWK)["kid"] = "signer"
	var signer crypto.Signer = ec
	if cancel != nil {
		signer = cancelsAfterSigning{Signer: ec, cancel: cancel}
	}
	signerConfiguration := model.SignerConfiguration{Algorithm: "ES256", KeyID: "signer", Signer: signer}
	record := &model.SubordinateConfiguration{
		JWKs: josemodel.Jwks{Keys: []map[string]any{testPublicJwk(t, testKey(t).Public(), "leaf")}},
	}
	if recordsOwn {
		record.SignerConfiguration = &signerConfiguration
	}
	retrieve := func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
		return record, &signerConfiguration, nil
	}
	cfg := model.ServerConfiguration{
		EntityIdentifier:          "https://ta.example.com",
		SignerConfiguration:       signerConfiguration,
		IntermediateConfiguration: &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
	}
	return cfg, retrieve, josemodel.Jwks{Keys: []map[string]any{*publicJWK}}
}

func TestNew_ASelfCheckTheRequestsEndInterruptsIsTheRequestNotCompleting(t *testing.T) {
	for name, recordsOwn := range map[string]bool{"the authority's signer": false, "the record's own signer": true} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cfg, retrieve, _ := interruptedIssuance(t, recordsOwn, cancel)

			_, err := New(ctx, "https://leaf.example.com", retrieve, cfg)
			if !errors.Is(err, model.ErrTemporarilyUnavailable) || !errors.Is(err, context.Canceled) {
				t.Errorf("[8.9] a self-check the request's end interrupted found nothing wrong with the statement, so this is the request not completing, temporarily_unavailable carrying context.Canceled, got %v", err)
			}
			if errors.Is(err, ErrUnusableRecord) {
				t.Errorf("a request that ended is not the record's fault, got %v", err)
			}
		})
	}
}

func TestValidate_AVerificationTheRequestsEndInterruptsKeepsTheContextError(t *testing.T) {
	cfg, retrieve, issuerKeys := interruptedIssuance(t, false, nil)
	token, err := New(t.Context(), "https://leaf.example.com", retrieve, cfg)
	if err != nil {
		t.Fatalf("the fixture is wrong: the subordinate statement cannot be issued, %v", err)
	}
	issuer := model.EntityStatement{Iss: cfg.EntityIdentifier, Sub: cfg.EntityIdentifier, JWKs: issuerKeys}
	if _, err := Validate(t.Context(), cfg.Configuration, issuer, *token); err != nil {
		t.Fatalf("the fixture is wrong: the subordinate statement does not validate on a live request, %v", err)
	}

	for name, ending := range map[string]struct {
		ctx   func() (context.Context, context.CancelFunc)
		cause error
	}{
		"a cancelled request": {ctx: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			return ctx, cancel
		}, cause: context.Canceled},
		"a request past its deadline": {ctx: func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		}, cause: context.DeadlineExceeded},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := ending.ctx()
			defer cancel()
			_, err := Validate(ctx, cfg.Configuration, issuer, *token)
			if !errors.Is(err, ending.cause) {
				t.Errorf("[8.9] a verification the request's end interrupted says nothing about the statement, so it must carry %v, got %v", ending.cause, err)
			}
			if errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[8.9] a verification the request's end interrupted is not the statement failing validation, got %v", err)
			}
		})
	}
}
