package entity_statement

import (
	"context"
	"errors"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestVerification_AnInterruptedCheckKeepsTheContextError(t *testing.T) {
	key := selectorKey(t)
	other := selectorKey(t)
	token := anyKeySign(t, key, "leaf")
	signing := josemodel.Jwks{Keys: []map[string]any{selectorJwk(t, key.Public(), "leaf")}}
	wrong := josemodel.Jwks{Keys: []map[string]any{selectorJwk(t, other.Public(), "leaf")}}
	algorithms := model.DefaultSigningAlgorithms()

	verifiers := []struct {
		name   string
		verify func(context.Context, josemodel.Jwks) error
		keys   bool
	}{
		{
			name: "the key the header kid names",
			verify: func(ctx context.Context, jwks josemodel.Jwks) error {
				return VerifyAgainstJwks(ctx, token, "leaf", jwks, algorithms)
			},
			keys: true,
		},
		{
			name: "any key in a configured set",
			verify: func(ctx context.Context, jwks josemodel.Jwks) error {
				return VerifyAgainstAnyKey(ctx, token, jwks, algorithms)
			},
			keys: true,
		},
		{
			name: "the issuance self-check",
			verify: func(ctx context.Context, _ josemodel.Jwks) error {
				return VerifyIssuedSignature(ctx, token, "leaf", "RS256", key)
			},
		},
	}

	cancelled := func(t *testing.T) context.Context {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		return ctx
	}
	expired := func(t *testing.T) context.Context {
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		t.Cleanup(cancel)
		return ctx
	}

	for _, verifier := range verifiers {
		t.Run(verifier.name, func(t *testing.T) {
			if err := verifier.verify(t.Context(), signing); err != nil {
				t.Fatalf("the fixture is wrong: the signature does not verify on a live context, %v", err)
			}
			for _, tc := range []struct {
				name  string
				ctx   func(*testing.T) context.Context
				cause error
			}{
				{name: "a cancelled request", ctx: cancelled, cause: context.Canceled},
				{name: "a request past its deadline", ctx: expired, cause: context.DeadlineExceeded},
			} {
				t.Run(tc.name, func(t *testing.T) {
					err := verifier.verify(tc.ctx(t), signing)
					if !errors.Is(err, tc.cause) {
						t.Errorf("[8.9] a check the request's end interrupted says nothing about the signature, so it must carry %v, got %v", tc.cause, err)
					}
				})
			}
			if !verifier.keys {
				return
			}
			err := verifier.verify(t.Context(), wrong)
			if err == nil {
				t.Fatal("[10.2] expected a signature made with another key to be refused")
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("[10.2] a signature that does not verify on a live request is the peer's fault, not an interrupted check, got %v", err)
			}
		})
	}
}
