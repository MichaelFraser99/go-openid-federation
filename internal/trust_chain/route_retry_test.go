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
	errs     map[string]error
	asked    *atomic.Int64
}

func (r refusesToFetch) RoundTrip(request *http.Request) (*http.Response, error) {
	node := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/"), "/fetch")
	if strings.HasSuffix(request.URL.Path, "/fetch") && r.refusing[node] {
		if r.asked != nil {
			r.asked.Add(1)
		}
		if failure, own := r.errs[node]; own {
			return nil, failure
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
			name:     "a peer refuses the first route and this server fails the second, so this server's fault is the answer",
			hints:    map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}},
			refusing: []string{"a"},
			ownFails: "b",
			want:     model.ErrServerError,
		},
		{
			name:     "this server fails the first route and a peer refuses the second, so this server's fault is the answer",
			hints:    map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}},
			refusing: []string{"b"},
			ownFails: "a",
			want:     model.ErrServerError,
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
				if tc.want == model.ErrServerError && errors.Is(err, model.ErrInvalidTrustChain) {
					t.Errorf("[8.9 server_error] this server's own fault may clear on retry, so it is the answer over a peer's refusal, got %v", err)
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

func TestBuildTrustChain_ADepthRefusalOnALaterWalkLeavesTheFirstFailureAsTheAnswer(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"c"}, "c": {"d"}, "d": {"ta"}, "ta": {}})
	client := *tp.server.Client()
	client.Transport = refusesToFetch{next: tp.server.Client().Transport, refusing: map[string]bool{"a": true}}

	_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client, MaxTrustChainDepth: 3}, tp.id["leaf"], tp.id["ta"], resolvecache.New())
	if !errors.Is(err, model.ErrInvalidTrustChain) || errors.Is(err, model.ErrLimitReached) {
		t.Errorf("[10.1] the depth bound refuses one branch, not the walk, so the first statement failure is the answer, got %v", err)
	}
}

func TestBuildTrustChain_RetriedStatementFetchesAreChargedToTheEntityBudget(t *testing.T) {
	hints := map[string][]string{"leaf": {"m1", "m2", "m3"}, "ta": {}}
	for _, m := range []string{"m1", "m2", "m3"} {
		hints[m] = []string{"i1", "i2", "i3"}
	}
	for _, i := range []string{"i1", "i2", "i3"} {
		hints[i] = []string{"ta"}
	}
	tp := newTopo(t, hints)
	asked := &atomic.Int64{}
	client := *tp.server.Client()
	client.Transport = refusesToFetch{next: tp.server.Client().Transport, refusing: map[string]bool{"i1": true, "i2": true, "i3": true}, asked: asked}

	_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client, MaxEntitiesTraversed: 12}, tp.id["leaf"], tp.id["ta"], resolvecache.New())
	if !errors.Is(err, model.ErrLimitReached) {
		t.Errorf("[18.1] a peer choosing where every retried fetch goes must not be able to spend fetches the entity budget does not count, expected the limit, got %v", err)
	}
	if got := asked.Load(); got >= 9 {
		t.Errorf("expected the budget to stop the retries before every refused link was asked, got %d refused fetches", got)
	}
}

func TestBuildTrustChain_TheFirstRoutesStatementsAreNotChargedToTheEntityBudget(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"a"}, "a": {"b"}, "b": {"ta"}, "ta": {}})

	_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: tp.server.Client(), MaxEntitiesTraversed: 4}, tp.id["leaf"], tp.id["ta"], resolvecache.New())
	if err != nil {
		t.Errorf("[18.1] four entity configurations fit a budget of four, and the first route's statements cost nothing extra, got %v", err)
	}
}

func TestBuildTrustChain_AThrottledSecondRouteIsTheAnswerOverAPeersRefusal(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}})
	client := *tp.server.Client()
	client.Transport = refusesToFetch{
		next:     tp.server.Client().Transport,
		refusing: map[string]bool{"a": true, "b": true},
		errs:     map[string]error{"b": fmt.Errorf("%wthe consumer's transport is throttled", model.ErrTemporarilyUnavailable)},
	}

	_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], resolvecache.New())
	if !errors.Is(err, model.ErrTemporarilyUnavailable) || errors.Is(err, model.ErrInvalidTrustChain) {
		t.Errorf("[8.9 temporarily_unavailable] a route that failed for a condition that may clear is the answer over a peer's refusal, got %v", err)
	}
}

func TestBuildTrustChain_TheRetryBudgetIsExact(t *testing.T) {
	for _, tc := range []struct {
		budget  int
		limited bool
	}{
		{budget: 6},
		{budget: 5, limited: true},
	} {
		t.Run(fmt.Sprint(tc.budget), func(t *testing.T) {
			tp := newTopo(t, map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}})
			client := *tp.server.Client()
			client.Transport = refusesToFetch{next: tp.server.Client().Transport, refusing: map[string]bool{"a": true}}

			_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client, MaxEntitiesTraversed: tc.budget}, tp.id["leaf"], tp.id["ta"], resolvecache.New())
			if tc.limited != errors.Is(err, model.ErrLimitReached) {
				t.Errorf("[18.1] four entity configurations and the retried route's two statements cost six, so a budget of %d must give a limit of %t, got %v", tc.budget, tc.limited, err)
			}
			if !tc.limited && err != nil {
				t.Errorf("[18.1] expected the route through b within a budget of %d, got %v", tc.budget, err)
			}
		})
	}
}

func TestBuildTrustChain_TheFirstOfTwoRetryableFailuresIsTheAnswer(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}})
	client := *tp.server.Client()
	client.Transport = refusesToFetch{
		next:     tp.server.Client().Transport,
		refusing: map[string]bool{"b": true},
		errs:     map[string]error{"b": fmt.Errorf("%wthe consumer's transport is throttled", model.ErrTemporarilyUnavailable)},
	}
	cache := resolvecache.New()
	cache.SetOwn(tp.id["a"], nil, func(context.Context, model.EntityStatement, model.EntityIdentifier) (*string, *model.EntityStatement, error) {
		return nil, nil, model.NewServerError("unable to produce the subordinate statement at this time")
	})

	_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], cache)
	if !errors.Is(err, model.ErrServerError) || errors.Is(err, model.ErrTemporarilyUnavailable) {
		t.Errorf("[8.9 server_error] between two failures that may clear, the first is the answer, got %v", err)
	}
}

func TestBuildTrustChain_ALaterWalksOwnFaultIsTheAnswerOverAPeersRefusal(t *testing.T) {
	tp := newTopo(t, map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}})
	client := *tp.server.Client()
	client.Transport = refusesToFetch{next: tp.server.Client().Transport, refusing: map[string]bool{"a": true}}
	cache := resolvecache.New()
	cache.SetOwn(tp.id["b"], func(context.Context) (*string, *model.EntityStatement, error) {
		return nil, nil, model.NewServerError("unable to produce the entity configuration at this time")
	}, nil)

	_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id["leaf"], tp.id["ta"], cache)
	if !errors.Is(err, model.ErrServerError) || errors.Is(err, model.ErrInvalidTrustChain) {
		t.Errorf("[8.9 server_error] the second walk failed on this server's own fault, which may clear, so it is the answer over the first route's refusal, got %v", err)
	}
}
