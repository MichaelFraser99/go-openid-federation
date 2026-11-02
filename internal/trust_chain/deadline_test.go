package trust_chain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestBuildTrustChain_ThisServersOwnDeadlineIsReportedAsAnIncompleteWalk(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		reference string
		stall     string
	}{
		{name: "a deadline while fetching a subordinate statement", reference: "8.9", stall: "/fetch"},
		{name: "a deadline while fetching an entity configuration", reference: "8.9", stall: "/ta/.well-known/openid-federation"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, tc.stall) {
					<-r.Context().Done()
					return
				}
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				switch {
				case strings.HasSuffix(r.URL.Path, "/leaf/.well-known/openid-federation"):
					id := model.EntityIdentifier(srv.URL + "/leaf")
					_, _ = w.Write([]byte(createEntityStatement(t, id, id, []model.EntityIdentifier{model.EntityIdentifier(srv.URL + "/ta")}, key, true)))
				case strings.HasSuffix(r.URL.Path, "/ta/.well-known/openid-federation"):
					id := model.EntityIdentifier(srv.URL + "/ta")
					_, _ = w.Write([]byte(createEntityStatement(t, id, id, nil, key, true)))
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(srv.Close)

			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			defer cancel()

			_, _, _, err := BuildTrustChain(ctx, model.Configuration{HttpClient: srv.Client()}, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), resolvecache.New())
			if err == nil {
				t.Fatalf("[%s] expected the walk to stop at the deadline", tc.reference)
			}
			if !errors.Is(err, model.ErrTemporarilyUnavailable) {
				t.Errorf("[%s] this server failing to complete its own request is the one thing section 8.9's temporarily_unavailable describes, got %v", tc.reference, err)
			}
			if errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[%s] a deadline this server set is not the caller's chain failing to validate, got %v", tc.reference, err)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("[%s] expected the deadline to be reported rather than masked, got %v", tc.reference, err)
			}
		})
	}
}

type slowFederation struct {
	t      *testing.T
	client *http.Client
	base   string
	key    *rsa.PrivateKey
	hints  map[string][]string
	mu     sync.Mutex
	delays map[string]time.Duration
}

func newSlowFederation(t *testing.T, hints map[string][]string) *slowFederation {
	t.Helper()
	federation := &slowFederation{t: t, key: chainSigningKey(t), hints: hints, delays: map[string]time.Duration{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(federation.serve))
	t.Cleanup(srv.Close)
	federation.client = srv.Client()
	federation.base = srv.URL
	return federation
}

func (f *slowFederation) entity(name string) model.EntityIdentifier {
	return model.EntityIdentifier(f.base + "/" + name)
}

func (f *slowFederation) slow(name string, delay time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delays[name] = delay
}

func (f *slowFederation) serve(w http.ResponseWriter, r *http.Request) {
	name, wellKnown := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/.well-known/openid-federation")
	f.mu.Lock()
	delay := f.delays[name]
	f.mu.Unlock()
	select {
	case <-r.Context().Done():
		return
	case <-time.After(delay):
	}

	now := time.Now().UTC()
	statement := map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": chainJwks(f.t, f.key)}
	switch {
	case wellKnown && name == "ta":
		statement["iss"], statement["sub"] = string(f.entity("ta")), string(f.entity("ta"))
		statement["metadata"] = map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": string(f.entity("ta")) + "/fetch"}}
	case wellKnown && f.hints[name] != nil:
		hints := make([]any, 0, len(f.hints[name]))
		for _, hint := range f.hints[name] {
			hints = append(hints, string(f.entity(hint)))
		}
		statement["iss"], statement["sub"], statement["authority_hints"] = string(f.entity(name)), string(f.entity(name)), hints
	case r.URL.Path == "/ta/fetch":
		statement["iss"], statement["sub"] = string(f.entity("ta")), r.URL.Query().Get("sub")
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	_, _ = w.Write([]byte(chainSignStatement(f.t, f.key, statement)))
}

const (
	requestDeadline    = 300 * time.Millisecond
	peerResponseLimit  = 10 * time.Second
	slowerThanDeadline = 5 * time.Second
	deadlineHeadroom   = 1500 * time.Millisecond
)

func deadlineConfiguration(client *http.Client) model.Configuration {
	return model.Configuration{HttpClient: client, MaxResolveTime: requestDeadline, MaxPeerResponseTime: peerResponseLimit}
}

func assertEndedAtTheRequestDeadline(t *testing.T, elapsed time.Duration, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("[8.9] expected the request to stop at its deadline")
	}
	if !errors.Is(err, model.ErrTemporarilyUnavailable) {
		t.Errorf("[8.9] this server not completing its own request within its deadline is temporarily_unavailable, got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("[8.9] expected the deadline to be reported rather than masked, got %v", err)
	}
	if elapsed < requestDeadline {
		t.Errorf("expected the request to run until its deadline of %s, it ended after %s", requestDeadline, elapsed)
	}
	if elapsed > requestDeadline+deadlineHeadroom {
		t.Errorf("expected the request to end near its deadline of %s, it took %s", requestDeadline, elapsed)
	}
}

func TestBuildTrustChain_TheWholeWalkIsBoundedByTheRequestDeadline(t *testing.T) {
	deadEnds := []string{"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"}
	eachWithinItsBound := map[string]time.Duration{}
	hints := map[string][]string{"leaf": deadEnds}
	for _, deadEnd := range deadEnds {
		eachWithinItsBound[deadEnd] = 100 * time.Millisecond
		hints[deadEnd] = []string{}
	}

	tests := []struct {
		name  string
		hints map[string][]string
		slow  map[string]time.Duration
	}{
		{
			name:  "one peer answering within its own bound but after the request deadline",
			hints: map[string][]string{"leaf": {"ta"}},
			slow:  map[string]time.Duration{"leaf": slowerThanDeadline},
		},
		{
			name:  "many peers each answering within their own bound",
			hints: hints,
			slow:  eachWithinItsBound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			federation := newSlowFederation(t, tc.hints)
			for name, delay := range tc.slow {
				federation.slow(name, delay)
			}

			started := time.Now()
			_, _, _, err := BuildTrustChain(t.Context(), deadlineConfiguration(federation.client), federation.entity("leaf"), federation.entity("ta"), resolvecache.New())
			assertEndedAtTheRequestDeadline(t, time.Since(started), err)
		})
	}
}

func TestResolveMetadata_FetchingAnOmittedAnchorIsBoundedByTheRequestDeadline(t *testing.T) {
	federation := newSlowFederation(t, map[string][]string{"leaf": {"ta"}})
	built, _, _, err := BuildTrustChain(t.Context(), deadlineConfiguration(federation.client), federation.entity("leaf"), federation.entity("ta"), resolvecache.New())
	if err != nil {
		t.Fatalf("the fixture is wrong: the chain does not build, %v", err)
	}
	if _, err := ResolveMetadata(t.Context(), deadlineConfiguration(federation.client), federation.entity("ta"), federation.entity("ta"), built[:2], resolvecache.New()); err != nil {
		t.Fatalf("the fixture is wrong: the chain omitting its anchor does not resolve, %v", err)
	}

	federation.slow("ta", slowerThanDeadline)
	started := time.Now()
	_, err = ResolveMetadata(t.Context(), deadlineConfiguration(federation.client), federation.entity("ta"), federation.entity("ta"), built[:2], resolvecache.New())
	assertEndedAtTheRequestDeadline(t, time.Since(started), err)
}
