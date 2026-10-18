package trust_chain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func hintGraphServer(t *testing.T, hints map[string][]string) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/.well-known/openid-federation")
		hs, ok := hints[node]
		if !ok || !strings.HasSuffix(r.URL.Path, "/.well-known/openid-federation") {
			http.NotFound(w, r)
			return
		}
		ids := make([]model.EntityIdentifier, 0, len(hs))
		for _, h := range hs {
			ids = append(ids, model.EntityIdentifier(srv.URL+"/"+h))
		}
		self := model.EntityIdentifier(srv.URL + "/" + node)
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		w.Write([]byte(createEntityStatement(t, self, self, ids, key, true))) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestChainUpOne_NodeTooDeepOnOnePathIsStillTriedOnAShorterOne(t *testing.T) {
	srv := hintGraphServer(t, map[string][]string{
		"leaf": {"a", "c"},
		"a":    {"c"},
		"c":    {"ta"},
		"ta":   nil,
	})
	cfg := model.Configuration{HttpClient: srv.Client(), MaxTrustChainDepth: 3}
	_, route, _, err := ChainUpOne(context.Background(), cfg, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, resolvecache.New(), map[DeadEnd]struct{}{})
	if err != nil || len(route) == 0 {
		t.Fatalf("expected the chain leaf -> c -> ta, got route of %d entries, err %v", len(route), err)
	}
}

func TestBuildTrustChain_DefaultLimitBoundsSubordinateStatements(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		switch {
		case strings.HasSuffix(r.URL.Path, "/leaf/.well-known/openid-federation"):
			id := model.EntityIdentifier(srv.URL + "/leaf")
			w.Write([]byte(createEntityStatement(t, id, id, []model.EntityIdentifier{model.EntityIdentifier(srv.URL + "/ta")}, key, true))) //nolint:errcheck
		case strings.HasSuffix(r.URL.Path, "/ta/.well-known/openid-federation"):
			id := model.EntityIdentifier(srv.URL + "/ta")
			w.Write([]byte(createEntityStatement(t, id, id, nil, key, true))) //nolint:errcheck
		case strings.HasSuffix(r.URL.Path, "/fetch"):
			chunk := []byte(strings.Repeat("A", 4096))
			for range 64 << 10 {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	_, _, _, err = BuildTrustChain(context.Background(), model.Configuration{HttpClient: srv.Client()}, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), resolvecache.New())
	if err == nil || !strings.Contains(err.Error(), "response limit") {
		t.Fatalf("expected the default response limit to refuse the fetch, got %v", err)
	}
}
