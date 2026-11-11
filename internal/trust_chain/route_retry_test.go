package trust_chain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type refusesToFetch struct {
	next     http.RoundTripper
	refusing map[string]bool
	err      error
	asked    *atomic.Int64
}

func (r refusesToFetch) RoundTrip(request *http.Request) (*http.Response, error) {
	node := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/"), "/fetch")
	if strings.HasSuffix(request.URL.Path, "/fetch") && r.refusing[node] {
		if r.asked != nil {
			r.asked.Add(1)
		}
		if r.err != nil {
			return nil, r.err
		}
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	}
	return r.next.RoundTrip(request)
}

func TestBuildTrustChain_ARouteWhoseSubordinateStatementFailsGivesWayToAnother(t *testing.T) {
	tests := []struct {
		name     string
		hints    map[string][]string
		refusing []string
		ownFails string
		via      string
		want     error
	}{
		{
			name:     "the first hint has not registered the leaf",
			hints:    map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}},
			refusing: []string{"a"},
			via:      "b",
		},
		{
			name:     "an intermediate's first hint has not registered it",
			hints:    map[string][]string{"leaf": {"m"}, "m": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}},
			refusing: []string{"a"},
			via:      "b",
		},
		{
			name:     "this server cannot issue its statement for the first hint",
			hints:    map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}},
			ownFails: "a",
			via:      "b",
		},
		{
			name:     "the only hint has not registered the leaf",
			hints:    map[string][]string{"leaf": {"a"}, "a": {"ta"}, "ta": {}},
			refusing: []string{"a"},
			want:     model.ErrInvalidTrustChain,
		},
		{
			name:     "no hint has registered the leaf",
			hints:    map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}},
			refusing: []string{"a", "b"},
			want:     model.ErrInvalidTrustChain,
		},
		{
			name:     "the first route fails one way and the second another, so the first failure is the answer",
			hints:    map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}},
			refusing: []string{"a"},
			ownFails: "b",
			want:     model.ErrInvalidTrustChain,
		},
		{
			name:     "this server cannot issue its statement for the only hint",
			hints:    map[string][]string{"leaf": {"a"}, "a": {"ta"}, "ta": {}},
			ownFails: "a",
			want:     model.ErrServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp := newTopo(t, tc.hints)
			refusing := map[string]bool{}
			for _, node := range tc.refusing {
				refusing[node] = true
			}
			client := *tp.server.Client()
			client.Transport = refusesToFetch{next: tp.server.Client().Transport, refusing: refusing}
			cache := resolvecache.New()
			if tc.ownFails != "" {
				cache.SetOwn(tp.id[tc.ownFails], nil, func(context.Context, model.EntityStatement, model.EntityIdentifier) (*string, *model.EntityStatement, error) {
					return nil, nil, model.NewServerError("unable to produce the subordinate statement at this time")
				})
			}

			_, parsed, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], cache)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("[10.1] with no route left, expected the first failure, %v, got %v", tc.want, err)
				}
				if tc.want != model.ErrServerError && errors.Is(err, model.ErrServerError) {
					t.Errorf("[10.1] expected the first failure alone, not a later route's, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[10.1] a route whose subordinate statement fails must give way to another route, got %v", err)
			}
			through := false
			for _, statement := range parsed {
				if statement.Iss == tp.id[tc.via] {
					through = true
				}
			}
			if !through {
				t.Errorf("expected the chain to pass through %s", tc.via)
			}
		})
	}
}

type refusesThenHangs struct {
	next     http.RoundTripper
	refusing string
	hanging  string
}

func (r refusesThenHangs) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Path == "/"+r.refusing+"/fetch" {
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	}
	if strings.HasPrefix(request.URL.Path, "/"+r.hanging+"/") {
		<-request.Context().Done()
		return nil, request.Context().Err()
	}
	return r.next.RoundTrip(request)
}

func TestBuildTrustChain_ADeadlineWhileTryingAnotherRouteIsTheAnswer(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}})
	client := *tp.server.Client()
	client.Transport = refusesThenHangs{next: tp.server.Client().Transport, refusing: "a", hanging: "b"}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	_, _, _, err := BuildTrustChain(ctx, model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], resolvecache.New())
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, model.ErrInvalidTrustChain) {
		t.Errorf("[8.9 temporarily_unavailable] a walk that ran out of time looking for another route must say so, not report the first route's failure, got %v", err)
	}
}

func TestBuildTrustChain_ANilCacheStillTriesAnotherRouteAndEnds(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}})
	client := *tp.server.Client()
	asked := &atomic.Int64{}
	client.Transport = refusesToFetch{next: tp.server.Client().Transport, refusing: map[string]bool{"a": true, "b": true}, asked: asked}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	_, _, _, err := BuildTrustChain(ctx, model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], nil)
	if !errors.Is(err, model.ErrInvalidTrustChain) {
		t.Errorf("[10.1] expected the first failure once no route is left, even with no cache supplied, got %v", err)
	}
	if got := asked.Load(); got != 2 {
		t.Errorf("expected each failed link asked once and then remembered, so 2 refused fetches, got %d", got)
	}
}

func TestBuildTrustChain_ALimitTheTransportReportsOnAStatementStopsTheWalk(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}})
	client := *tp.server.Client()
	client.Transport = refusesToFetch{next: tp.server.Client().Transport, refusing: map[string]bool{"a": true}, err: fmt.Errorf("%w%wthe consumer's request budget is spent", model.ErrLimitReached, model.ErrTemporarilyUnavailable)}

	_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], resolvecache.New())
	if !errors.Is(err, model.ErrLimitReached) {
		t.Errorf("[18.1] a limit stops the walk rather than sending it down another route, got %v", err)
	}
}
