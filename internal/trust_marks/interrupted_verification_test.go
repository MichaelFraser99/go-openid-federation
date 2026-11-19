package trust_marks

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type stallOnMessage struct {
	stallOn  string
	mu       *sync.Mutex
	messages *[]string
}

func (h stallOnMessage) Enabled(context.Context, slog.Level) bool { return true }

func (h stallOnMessage) Handle(ctx context.Context, record slog.Record) error {
	h.mu.Lock()
	*h.messages = append(*h.messages, record.Message)
	h.mu.Unlock()
	if record.Message == h.stallOn {
		<-ctx.Done()
	}
	return nil
}

func (h stallOnMessage) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h stallOnMessage) WithGroup(string) slog.Handler { return h }

func TestValidate_ASignatureCheckTheRequestsEndInterruptsIsNotTheMarksFault(t *testing.T) {
	f := newRvFed(t, map[string]string{"member": "ta"})
	issuer := f.id("ta")
	ownerKey := rvKey(t)
	shadow := federationPublicJwk(t, rvKey(t).Public(), "owner-key")
	shadow["use"] = "enc"
	delegation := dlgSign(t, ownerKey, dlgHead("owner-key"), dlgBody(dlgOwner, issuer, rvType))

	tests := []struct {
		name     string
		owned    bool
		stallOn  string
		blaming  string
		ended    func(context.Context) (context.Context, context.CancelFunc)
		expected error
	}{
		{
			name:    "the trust mark's own signature",
			blaming: "failed to validate trust mark",
			ended: func(ctx context.Context) (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(ctx)
				cancel()
				return ctx, cancel
			},
			expected: context.Canceled,
		},
		{
			name:    "the delegation's signature",
			owned:   true,
			stallOn: "an owner key named by the delegation cannot verify it",
			blaming: "the delegation signature does not verify against an owner key",
			ended: func(ctx context.Context) (context.Context, context.CancelFunc) {
				return context.WithTimeout(ctx, 200*time.Millisecond)
			},
			expected: context.DeadlineExceeded,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			var carried *string
			if tc.owned {
				ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: {Sub: dlgOwner, JWKs: josemodel.Jwks{Keys: []map[string]any{shadow, federationPublicJwk(t, ownerKey.Public(), "owner-key")}}}}
				carried = &delegation
			}
			tm := dlgMark(t, f.ecKey["ta"], "test-key", issuer, rvType, rvSub, carried)
			opts := ValidateOptions{
				ExpectedType:             rvType,
				ExpectedSubject:          rvSub,
				AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(issuer)},
				TrustAnchor:              ta.Sub,
				TrustAnchorConfiguration: ta,
			}
			if _, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, tm, opts, nil); err != nil {
				t.Fatalf("the fixture is wrong: the trust mark does not verify on a live request, %v", err)
			}

			handler := stallOnMessage{stallOn: tc.stallOn, mu: &sync.Mutex{}, messages: &[]string{}}
			ctx, cancel := tc.ended(t.Context())
			defer cancel()
			_, err := Validate(ctx, model.Configuration{HttpClient: f.server.Client(), Logger: slog.New(handler)}, tm, opts, nil)
			if !errors.Is(err, tc.expected) {
				t.Errorf("[8.9] a signature check the request's end interrupted says nothing about the trust mark, so it must carry %v, got %v", tc.expected, err)
			}
			handler.mu.Lock()
			defer handler.mu.Unlock()
			if slices.Contains(*handler.messages, tc.blaming) {
				t.Errorf("[8.9] a signature check the request's end interrupted must not be logged as a signature that does not verify, got %q", tc.blaming)
			}
		})
	}
}
