package trust_chain

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/internal/subordinate_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type stallAndRecord struct {
	stallOn  string
	mu       *sync.Mutex
	messages *[]string
	errors   *[]string
}

func newStallAndRecord(stallOn string) stallAndRecord {
	return stallAndRecord{stallOn: stallOn, mu: &sync.Mutex{}, messages: &[]string{}, errors: &[]string{}}
}

func (h stallAndRecord) Enabled(context.Context, slog.Level) bool { return true }

func (h stallAndRecord) Handle(ctx context.Context, record slog.Record) error {
	h.mu.Lock()
	*h.messages = append(*h.messages, record.Message)
	if record.Level >= slog.LevelError {
		*h.errors = append(*h.errors, record.Message)
	}
	h.mu.Unlock()
	if record.Message == h.stallOn {
		<-ctx.Done()
	}
	return nil
}

func (h stallAndRecord) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h stallAndRecord) WithGroup(string) slog.Handler { return h }

func (h stallAndRecord) logged() ([]string, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(*h.messages), slices.Clone(*h.errors)
}

var peerBlamingMessages = []string{
	"trust chain entry not signed by a key published in the statement above it",
	"the chosen route failed validation, so the walk tries another route",
	"trust anchor entity configuration not signed by any key configured for it",
	"subject entity configuration not signed by a key published for it by its superior",
	"failed to validate self-signed entity configuration",
	"failed to validate chain step",
	"failed to validate subject entity configuration",
}

type requestEnding struct {
	name      string
	reference string
	limit     time.Duration
	caller    func(context.Context) (context.Context, context.CancelFunc)
	ownLimit  bool
}

var requestEndings = []requestEnding{
	{
		name:      "the resolver's own time limit",
		reference: "18.1",
		limit:     requestDeadline,
		caller:    context.WithCancel,
		ownLimit:  true,
	},
	{
		name:      "the caller cancels",
		reference: "8.9",
		limit:     time.Minute,
		caller: func(ctx context.Context) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(ctx)
			time.AfterFunc(requestDeadline, cancel)
			return ctx, cancel
		},
	},
}

func assertRequestEnding(t *testing.T, ending requestEnding, err error, handler stallAndRecord) {
	t.Helper()
	if ending.ownLimit {
		assertResolveTimeLimit(t, err)
	} else if !errors.Is(err, model.ErrTemporarilyUnavailable) || !errors.Is(err, context.Canceled) || errors.Is(err, model.ErrLimitReached) {
		t.Errorf("[%s] a caller that cancels has ended the request, which is temporarily_unavailable carrying context.Canceled, got %v", ending.reference, err)
	}
	messages, errorLines := handler.logged()
	if len(errorLines) != 0 {
		t.Errorf("[%s] a check the request's end interrupted is no fault of a key or an anchor, so nothing is logged at Error, got %v", ending.reference, errorLines)
	}
	for _, blaming := range peerBlamingMessages {
		if slices.Contains(messages, blaming) {
			t.Errorf("[%s] a check the request's end interrupted says nothing about the statement it was checking, got the log line %q", ending.reference, blaming)
		}
	}
}

func heldAnchorKeys(t *testing.T, federation *slowFederation) map[model.EntityIdentifier]josemodel.Jwks {
	t.Helper()
	publicJWK, err := jwk.PublicJwk(federation.key.Public())
	if err != nil {
		t.Fatalf("failed to read the anchor key: %v", err)
	}
	(*publicJWK)["kid"] = "chain-key"
	return map[model.EntityIdentifier]josemodel.Jwks{federation.entity("ta"): {Keys: []map[string]any{*publicJWK}}}
}

func TestResolveMetadata_AVerificationTheRequestsEndInterruptsIsNotAPeerFault(t *testing.T) {
	tests := []struct {
		name         string
		stallOn      string
		omitAnchor   bool
		reuseTheWalk bool
	}{
		{name: "the anchor's entity configuration in the chain", stallOn: "processing self-signed entity configuration"},
		{name: "the anchor's entity configuration against the keys held for it", stallOn: "retrieving omitted trust anchor entity configuration", omitAnchor: true, reuseTheWalk: true},
		{name: "a subordinate statement in the chain", stallOn: "validating chain step"},
		{name: "the subject's entity configuration against its own keys", stallOn: "validating subject entity configuration"},
		{name: "the subject's entity configuration against the keys its superior registered", stallOn: "verifying subject entity configuration against the key published by its superior"},
	}

	for _, tc := range tests {
		for _, ending := range requestEndings {
			t.Run(tc.name+" when "+ending.name, func(t *testing.T) {
				federation := newSlowFederation(t, map[string][]string{"leaf": {"ta"}})
				keys := heldAnchorKeys(t, federation)
				walkCache := resolvecache.New()
				built, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: federation.client, TrustAnchors: keys}, federation.entity("leaf"), federation.entity("ta"), walkCache)
				if err != nil {
					t.Fatalf("the fixture is wrong: the chain does not build, %v", err)
				}
				chain := built
				if tc.omitAnchor {
					chain = built[:len(built)-1]
				}
				cache := resolvecache.New()
				if tc.reuseTheWalk {
					cache = walkCache
				}
				handler := newStallAndRecord(tc.stallOn)
				cfg := model.Configuration{HttpClient: federation.client, TrustAnchors: keys, MaxResolveTime: ending.limit, MaxPeerResponseTime: peerResponseLimit}
				if _, err := ResolveMetadata(t.Context(), cfg, federation.entity("ta"), federation.entity("ta"), chain, cache); err != nil {
					t.Fatalf("the fixture is wrong: the chain does not resolve on a live request, %v", err)
				}

				cfg.Logger = slog.New(handler)
				ctx, cancel := ending.caller(t.Context())
				defer cancel()
				_, err = ResolveMetadata(ctx, cfg, federation.entity("ta"), federation.entity("ta"), chain, cache)
				assertRequestEnding(t, ending, err, handler)
			})
		}
	}
}

func TestBuildTrustChain_AVerificationTheRequestsEndInterruptsIsNotAPeerFault(t *testing.T) {
	for _, ending := range requestEndings {
		t.Run(ending.name, func(t *testing.T) {
			federation := newSlowFederation(t, map[string][]string{"leaf": {"ta"}})
			keys := heldAnchorKeys(t, federation)
			live := model.Configuration{HttpClient: federation.client, TrustAnchors: keys, MaxPeerResponseTime: peerResponseLimit}
			issuesRegardless := func(_ context.Context, issuer model.EntityStatement, subject model.EntityIdentifier) (*string, *model.EntityStatement, error) {
				return subordinate_statement.Retrieve(context.WithoutCancel(t.Context()), live, issuer, subject)
			}
			newCache := func() *resolvecache.Cache {
				cache := resolvecache.New()
				cache.SetOwn(federation.entity("ta"), nil, issuesRegardless)
				return cache
			}
			if _, _, _, err := BuildTrustChain(t.Context(), live, federation.entity("leaf"), federation.entity("ta"), newCache()); err != nil {
				t.Fatalf("the fixture is wrong: the chain does not build on a live request, %v", err)
			}

			handler := newStallAndRecord("trust chain walk finished")
			cfg := live
			cfg.MaxResolveTime = ending.limit
			cfg.Logger = slog.New(handler)
			ctx, cancel := ending.caller(t.Context())
			defer cancel()
			_, _, _, err := BuildTrustChain(ctx, cfg, federation.entity("leaf"), federation.entity("ta"), newCache())
			assertRequestEnding(t, ending, err, handler)
		})
	}
}

func TestVerifyTrustAnchor_AVerificationTheRequestsEndInterruptsIsNotTheAnchorsFault(t *testing.T) {
	federation := newSlowFederation(t, map[string][]string{"leaf": {"ta"}})
	keys := heldAnchorKeys(t, federation)
	signed, anchor, err := retrieveTrustAnchor(t.Context(), model.Configuration{HttpClient: federation.client}, federation.entity("ta"), resolvecache.New())
	if err != nil {
		t.Fatalf("the fixture is wrong: the anchor's entity configuration cannot be fetched, %v", err)
	}
	if err := verifyTrustAnchor(t.Context(), model.Configuration{TrustAnchors: keys}, federation.entity("ta"), *signed, *anchor); err != nil {
		t.Fatalf("the fixture is wrong: the anchor's entity configuration does not verify on a live request, %v", err)
	}

	for _, ending := range requestEndings {
		t.Run(ending.name, func(t *testing.T) {
			handler := newStallAndRecord("")
			cfg := model.Configuration{TrustAnchors: keys, MaxResolveTime: ending.limit, Logger: slog.New(handler)}
			ctx, cancel := ending.caller(t.Context())
			defer cancel()
			ctx, cancelLimit := WithResolveTimeLimit(ctx, cfg)
			defer cancelLimit()
			<-ctx.Done()
			err := verifyTrustAnchor(ctx, cfg, federation.entity("ta"), *signed, *anchor)
			assertRequestEnding(t, ending, err, handler)
		})
	}
}
