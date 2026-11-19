package entity_configuration

import (
	"context"
	"crypto"
	"errors"
	"io"
	"testing"
	"time"

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

func TestNew_ASelfCheckTheRequestsEndInterruptsIsTheRequestNotCompleting(t *testing.T) {
	signerConfiguration, _ := issuanceSigner(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	signerConfiguration.Signer = cancelsAfterSigning{Signer: signerConfiguration.Signer.(josemodel.Signer), cancel: cancel}

	_, err := New(ctx, model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		SignerConfiguration:         signerConfiguration,
		EntityConfigurationLifetime: time.Hour,
	})
	if !errors.Is(err, model.ErrTemporarilyUnavailable) || !errors.Is(err, context.Canceled) {
		t.Errorf("[8.9] a self-check the request's end interrupted found nothing wrong with the statement, so this is the request not completing, temporarily_unavailable carrying context.Canceled, got %v", err)
	}
}

func TestValidate_AVerificationTheRequestsEndInterruptsKeepsTheContextError(t *testing.T) {
	signerConfiguration, _ := issuanceSigner(t)
	cfg := model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		SignerConfiguration:         signerConfiguration,
		EntityConfigurationLifetime: time.Hour,
	}
	token, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("the fixture is wrong: the entity configuration cannot be issued, %v", err)
	}
	if _, err := Validate(t.Context(), cfg.Configuration, cfg.EntityIdentifier, *token); err != nil {
		t.Fatalf("the fixture is wrong: the entity configuration does not validate on a live request, %v", err)
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
			_, err := Validate(ctx, cfg.Configuration, cfg.EntityIdentifier, *token)
			if !errors.Is(err, ending.cause) {
				t.Errorf("[8.9] a verification the request's end interrupted says nothing about the statement, so it must carry %v, got %v", ending.cause, err)
			}
			if errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[8.9] a verification the request's end interrupted is not the statement failing validation, got %v", err)
			}
		})
	}
}
