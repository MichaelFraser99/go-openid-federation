package trust_chain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func mutuallyHintingGraph(size int) map[string][]string {
	names := make([]string, 0, size)
	for i := range size {
		names = append(names, fmt.Sprintf("n%d", i))
	}
	hints := map[string][]string{}
	for _, node := range names {
		others := make([]string, 0, size-1)
		for _, other := range names {
			if other != node {
				others = append(others, other)
			}
		}
		hints[node] = others
	}
	return hints
}

func TestBuildTrustChain_DenseGraphIsWalkedInBoundedTime(t *testing.T) {
	tests := []struct {
		name  string
		nodes int
	}{
		{name: "nine mutually hinting entities", nodes: 9},
		{name: "twelve mutually hinting entities", nodes: 12},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp := newTopo(t, mutuallyHintingGraph(tc.nodes))
			cfg := model.Configuration{HttpClient: tp.server.Client()}

			start := time.Now()
			_, _, _, err := BuildTrustChain(context.Background(), cfg, tp.id["n0"], model.EntityIdentifier("https://unreachable.example.com"), resolvecache.New())
			elapsed := time.Since(start)

			if err == nil {
				t.Fatal("expected no chain to an unreachable trust anchor")
			}
			if elapsed > 2*time.Second {
				t.Errorf("walk over %d mutually hinting entities took %s, expected under 2s", tc.nodes, elapsed)
			}
			if hits := tp.maxHits(); hits > 1 {
				t.Errorf("expected each entity configuration to be fetched at most once, got %d for one entity", hits)
			}
		})
	}
}

func TestBuildTrustChain_WalkStopsWhenContextIsCancelled(t *testing.T) {
	var served atomic.Int64

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	var identifiers map[string]model.EntityIdentifier
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-federation") {
			http.NotFound(w, r)
			return
		}
		node := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/.well-known/openid-federation")
		self, ok := identifiers[node]
		if !ok {
			http.NotFound(w, r)
			return
		}
		served.Add(1)
		time.Sleep(60 * time.Millisecond)

		hints := make([]model.EntityIdentifier, 0, len(identifiers))
		for name, id := range identifiers {
			if name != node {
				hints = append(hints, id)
			}
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		w.Write([]byte(createEntityStatement(t, self, self, hints, key, true))) //nolint:errcheck
	}))
	t.Cleanup(server.Close)

	identifiers = map[string]model.EntityIdentifier{}
	for i := range 12 {
		name := fmt.Sprintf("n%d", i)
		identifiers[name] = model.EntityIdentifier(fmt.Sprintf("%s/%s", server.URL, name))
	}

	cfg := model.Configuration{HttpClient: server.Client()}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, _, err = BuildTrustChain(ctx, cfg, identifiers["n0"], model.EntityIdentifier("https://unreachable.example.com"), resolvecache.New())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the cancelled walk to fail")
	}
	if elapsed > time.Second {
		t.Errorf("walk continued for %s after the context was cancelled", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "context") {
		t.Errorf("expected a context error, got %v", err)
	}
}
