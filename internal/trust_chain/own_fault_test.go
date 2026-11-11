package trust_chain

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type blockingTransport struct {
	next    http.RoundTripper
	blocked string
	err     error
}

func (b blockingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasPrefix(r.URL.Path, "/"+b.blocked+"/") {
		return nil, b.err
	}
	return b.next.RoundTrip(r)
}

func TestBuildTrustChain_AFaultOnOneBranchEndsTheWalkOnlyWhenNoOtherRouteReachesTheAnchor(t *testing.T) {
	besideAGoodRoute := map[string][]string{
		"leaf":    {"blocked", "good"},
		"blocked": {"ta"},
		"good":    {"ta"},
		"ta":      {},
	}
	onlyRoute := map[string][]string{
		"leaf":    {"blocked"},
		"blocked": {"ta"},
		"ta":      {},
	}
	ownTemporary := model.NewTemporarilyUnavailableError("unable to produce the entity configuration at this time")
	ownServer := model.NewServerError("unable to produce the entity configuration at this time")
	peerThrottled := fmt.Errorf("%wpeer throttled", model.ErrTemporarilyUnavailable)
	peerRefusedByPolicy := fmt.Errorf("%wrefused by the consumer's transport policy", model.ErrServerError)

	tests := []struct {
		name      string
		reference string
		hints     map[string][]string
		subject   string
		peerErr   error
		ownErr    error
		want      error
	}{
		{name: "a peer whose transport reports it temporarily unavailable, beside a good route", reference: "10.1", hints: besideAGoodRoute, subject: "leaf", peerErr: peerThrottled},
		{name: "a peer whose transport fails without a class, beside a good route", reference: "10.1", hints: besideAGoodRoute, subject: "leaf", peerErr: errors.New("peer unreachable")},
		{name: "a peer the consumer's transport refuses as a server error, beside a good route", reference: "10.1", hints: besideAGoodRoute, subject: "leaf", peerErr: peerRefusedByPolicy},
		{name: "this server temporarily unable to produce its own entity configuration, beside a good route", reference: "10.1", hints: besideAGoodRoute, subject: "leaf", ownErr: ownTemporary},
		{name: "this server unable to produce its own entity configuration, beside a good route", reference: "10.1", hints: besideAGoodRoute, subject: "leaf", ownErr: ownServer},
		{name: "a peer the consumer's transport refuses as a server error, on the only route", reference: "8.9 server_error", hints: onlyRoute, subject: "leaf", peerErr: peerRefusedByPolicy, want: model.ErrServerError},
		{name: "this server temporarily unable to produce its own entity configuration, on the only route", reference: "8.9 temporarily_unavailable", hints: onlyRoute, subject: "leaf", ownErr: ownTemporary, want: model.ErrTemporarilyUnavailable},
		{name: "this server unable to produce its own entity configuration, on the only route", reference: "8.9 server_error", hints: onlyRoute, subject: "leaf", ownErr: ownServer, want: model.ErrServerError},
		{name: "a peer whose transport reports it temporarily unavailable, on the only route", reference: "8.9 invalid_trust_anchor", hints: onlyRoute, subject: "leaf", peerErr: peerThrottled, want: model.ErrInvalidTrustAnchor},
		{name: "a peer trust anchor as its own subject whose transport reports it temporarily unavailable", reference: "8.9 temporarily_unavailable", hints: besideAGoodRoute, subject: "ta", peerErr: peerThrottled, want: model.ErrTemporarilyUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp := newTopo(t, tc.hints)
			blocked := "blocked"
			if tc.subject == "ta" {
				blocked = "ta"
			}
			client := *tp.server.Client()
			if tc.peerErr != nil {
				client.Transport = blockingTransport{next: tp.server.Client().Transport, blocked: blocked, err: tc.peerErr}
			}
			cache := resolvecache.New()
			if tc.ownErr != nil {
				cache.SetOwn(tp.id["blocked"], func(context.Context) (*string, *model.EntityStatement, error) {
					return nil, nil, tc.ownErr
				}, nil)
			}

			chain, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id[tc.subject], tp.id["ta"], cache)

			if tc.want == nil {
				if err != nil {
					t.Fatalf("[%s] a fault on one branch must not end a walk that has another route, got %v", tc.reference, err)
				}
				if len(chain) != 4 {
					t.Fatalf("expected the chain through the good route, got %d entries", len(chain))
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("[%s] expected %v, got %v", tc.reference, tc.want, err)
			}
			if tc.want != model.ErrInvalidTrustAnchor && errors.Is(err, model.ErrInvalidTrustAnchor) {
				t.Errorf("[%s] a fault that may clear on retry must not be reported as an anchor no route reaches, got %v", tc.reference, err)
			}
		})
	}
}

type hangingTransport struct {
	next    http.RoundTripper
	blocked string
	cancel  context.CancelFunc
}

func (h hangingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(r.URL.Path, "/"+h.blocked+"/") {
		return h.next.RoundTrip(r)
	}
	if h.cancel != nil {
		h.cancel()
	}
	<-r.Context().Done()
	return nil, r.Context().Err()
}

func TestBuildTrustChain_ARememberedFaultGivesWayToTheWalksOwnEnding(t *testing.T) {
	hints := map[string][]string{
		"leaf":    {"blocked", "good"},
		"blocked": {"ta"},
		"good":    {"ta"},
		"ta":      {},
	}
	ownServer := model.NewServerError("unable to produce the entity configuration at this time")

	t.Run("the first of two faults is the answer when no route is found", func(t *testing.T) {
		tp := newTopo(t, hints)
		client := *tp.server.Client()
		client.Transport = blockingTransport{next: tp.server.Client().Transport, blocked: "good", err: fmt.Errorf("%wrefused by the consumer's transport policy", model.ErrServerError)}
		cache := resolvecache.New()
		cache.SetOwn(tp.id["blocked"], func(context.Context) (*string, *model.EntityStatement, error) {
			return nil, nil, model.NewTemporarilyUnavailableError("unable to produce the entity configuration at this time")
		}, nil)

		_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], cache)
		if !errors.Is(err, model.ErrTemporarilyUnavailable) || errors.Is(err, model.ErrServerError) {
			t.Errorf("[8.9 temporarily_unavailable] expected the fault the walk met first, got %v", err)
		}
	})

	t.Run("a configured bound reached after a fault is the answer", func(t *testing.T) {
		tp := newTopo(t, hints)
		client := *tp.server.Client()
		cache := resolvecache.New()
		cache.SetOwn(tp.id["blocked"], func(context.Context) (*string, *model.EntityStatement, error) {
			return nil, nil, ownServer
		}, nil)

		_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client, MaxEntitiesTraversed: 1}, tp.id["leaf"], tp.id["ta"], cache)
		if !errors.Is(err, model.ErrLimitReached) {
			t.Errorf("[18.1] expected the bound the walk reached, got %v", err)
		}
	})

	t.Run("a deadline reached after a fault is the answer", func(t *testing.T) {
		tp := newTopo(t, hints)
		client := *tp.server.Client()
		client.Transport = hangingTransport{next: tp.server.Client().Transport, blocked: "good"}
		cache := resolvecache.New()
		cache.SetOwn(tp.id["blocked"], func(context.Context) (*string, *model.EntityStatement, error) {
			return nil, nil, ownServer
		}, nil)

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		_, _, _, err := BuildTrustChain(ctx, model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], cache)
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, model.ErrServerError) {
			t.Errorf("[8.9 temporarily_unavailable] expected the walk's deadline, got %v", err)
		}
	})

	t.Run("a cancelled request after a fault is the answer", func(t *testing.T) {
		tp := newTopo(t, hints)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		client := *tp.server.Client()
		client.Transport = hangingTransport{next: tp.server.Client().Transport, blocked: "good", cancel: cancel}
		cache := resolvecache.New()
		cache.SetOwn(tp.id["blocked"], func(context.Context) (*string, *model.EntityStatement, error) {
			return nil, nil, ownServer
		}, nil)

		_, _, _, err := BuildTrustChain(ctx, model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], cache)
		if !errors.Is(err, context.Canceled) || errors.Is(err, model.ErrServerError) {
			t.Errorf("expected the cancellation, got %v", err)
		}
	})
}

func TestBuildTrustChain_AFaultIsNeverCachedAsADeadEnd(t *testing.T) {
	topologies := map[string]map[string][]string{
		"the faulty entity reached at two depths": {
			"leaf":    {"blocked", "mid"},
			"mid":     {"blocked"},
			"blocked": {"ta"},
			"ta":      {},
		},
		"the faulty entity reached twice at one depth": {
			"leaf":    {"left", "right"},
			"left":    {"blocked"},
			"right":   {"blocked"},
			"blocked": {"ta"},
			"ta":      {},
		},
	}

	for name, hints := range topologies {
		t.Run(name, func(t *testing.T) {
			tp := newTopo(t, hints)
			client := *tp.server.Client()
			cache := resolvecache.New()
			cache.SetOwn(tp.id["blocked"], func(context.Context) (*string, *model.EntityStatement, error) {
				return nil, nil, model.NewServerError("unable to produce the entity configuration at this time")
			}, nil)

			_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], cache)
			if !errors.Is(err, model.ErrServerError) {
				t.Fatalf("[8.9 server_error] expected this server's fault on every route, got %v", err)
			}
			for node := range hints {
				if node != "ta" && cache.IsDeadEnd(deadEndKey(tp.id[node], tp.id["ta"])) {
					t.Errorf("a route through %s failed for a fault that may clear, so it must not be cached as a route that does not exist", node)
				}
			}
		})
	}
}

func TestChainUpOne_ReturnsTheRememberedFault(t *testing.T) {
	tp := newTopo(t, map[string][]string{
		"leaf":    {"blocked"},
		"blocked": {"ta"},
		"ta":      {},
	})
	client := *tp.server.Client()
	cache := resolvecache.New()
	cache.SetOwn(tp.id["blocked"], func(context.Context) (*string, *model.EntityStatement, error) {
		return nil, nil, model.NewServerError("unable to produce the entity configuration at this time")
	}, nil)

	_, _, _, err := ChainUpOne(t.Context(), model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], nil, nil, nil, cache)
	if !errors.Is(err, model.ErrServerError) {
		t.Errorf("[8.9 server_error] expected this server's fault on the only route, got %v", err)
	}
}

func TestBuildTrustChain_ThisServersOwnStatementIsBuiltOnceWhenItFails(t *testing.T) {
	hints := map[string][]string{"leaf": {"blocked", "a1"}, "blocked": {"ta"}, "ta": {}}
	for i := 1; i <= 8; i++ {
		next := []string{"blocked"}
		if i < 8 {
			next = append(next, fmt.Sprintf("a%d", i+1))
		}
		hints[fmt.Sprintf("a%d", i)] = next
	}
	tp := newTopo(t, hints)
	client := *tp.server.Client()
	cache := resolvecache.New()
	builds := 0
	cache.SetOwn(tp.id["blocked"], func(context.Context) (*string, *model.EntityStatement, error) {
		builds++
		return nil, nil, model.NewServerError("unable to produce the entity configuration at this time")
	}, nil)

	_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], cache)
	if !errors.Is(err, model.ErrServerError) {
		t.Fatalf("[8.9 server_error] expected this server's fault on every route, got %v", err)
	}
	if builds != 1 {
		t.Errorf("expected this server's failing entity configuration built once for the request, built %d times", builds)
	}

	_, _, _, err = BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id["a8"], tp.id["ta"], cache)
	if !errors.Is(err, model.ErrServerError) {
		t.Fatalf("[8.9 server_error] expected the remembered fault on a second walk in the request, got %v", err)
	}
	if builds != 1 {
		t.Errorf("expected a second walk in the same request to reuse the failure, built %d times", builds)
	}
}

func TestBuildTrustChain_TheSubjectsTransportClassIsTheAnswer(t *testing.T) {
	hints := map[string][]string{
		"blocked": {"good"},
		"good":    {"ta"},
		"ta":      {},
	}
	tests := []struct {
		name      string
		reference string
		subject   string
		peerErr   error
		want      error
		notWant   error
	}{
		{name: "a subject the transport reports temporarily unavailable", reference: "8.9 temporarily_unavailable", subject: "blocked", peerErr: fmt.Errorf("%wpeer throttled", model.ErrTemporarilyUnavailable), want: model.ErrTemporarilyUnavailable, notWant: model.ErrNotFound},
		{name: "a subject the transport refuses as an invalid request", reference: "8.9 invalid_request", subject: "blocked", peerErr: fmt.Errorf("%wrefused by policy", model.ErrInvalidRequest), want: model.ErrInvalidRequest, notWant: model.ErrNotFound},
		{name: "a subject the transport fails without a class", reference: "8.1.2 not_found", subject: "blocked", peerErr: errors.New("peer unreachable"), want: model.ErrNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp := newTopo(t, hints)
			client := *tp.server.Client()
			client.Transport = blockingTransport{next: tp.server.Client().Transport, blocked: "blocked", err: tc.peerErr}

			_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id[tc.subject], tp.id["ta"], resolvecache.New())
			if !errors.Is(err, tc.want) {
				t.Fatalf("[%s] the subject has no other route, so the consumer's class is the honest answer: expected %v, got %v", tc.reference, tc.want, err)
			}
			if tc.notWant != nil && errors.Is(err, tc.notWant) {
				t.Errorf("[%s] expected the transport's class alone, got %v", tc.reference, err)
			}
			if strings.Contains(err.Error(), "refused by policy") || strings.Contains(err.Error(), "peer throttled") {
				t.Errorf("[%s] expected this library's own description, not the transport's text, got %q", tc.reference, err.Error())
			}
		})
	}
}

func TestBuildTrustChain_AHopsTransportClassIsNotTheAnswer(t *testing.T) {
	tp := newTopo(t, map[string][]string{
		"leaf":    {"blocked"},
		"blocked": {"ta"},
		"ta":      {},
	})
	client := *tp.server.Client()
	client.Transport = blockingTransport{next: tp.server.Client().Transport, blocked: "blocked", err: fmt.Errorf("%wrefused by policy", model.ErrInvalidRequest)}

	_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], resolvecache.New())
	if !errors.Is(err, model.ErrInvalidTrustAnchor) || errors.Is(err, model.ErrInvalidRequest) {
		t.Errorf("[8.9 invalid_trust_anchor] a hop's refusal is not the caller's invalid request, expected invalid_trust_anchor, got %v", err)
	}
}
