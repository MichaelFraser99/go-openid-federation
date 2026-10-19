package trust_chain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestBuildTrustChain_CancellationIsNotAChainFailure(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		switch {
		case strings.HasSuffix(r.URL.Path, "/leaf/.well-known/openid-federation"):
			id := model.EntityIdentifier(srv.URL + "/leaf")
			_, _ = w.Write([]byte(createEntityStatement(t, id, id, []model.EntityIdentifier{model.EntityIdentifier(srv.URL + "/ta")}, key, true)))
		case strings.HasSuffix(r.URL.Path, "/ta/.well-known/openid-federation"):
			id := model.EntityIdentifier(srv.URL + "/ta")
			_, _ = w.Write([]byte(createEntityStatement(t, id, id, nil, key, true)))
		case strings.HasSuffix(r.URL.Path, "/fetch"):
			cancel()
			http.Error(w, "gone", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	_, _, _, err = BuildTrustChain(ctx, model.Configuration{HttpClient: srv.Client()}, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), resolvecache.New())
	if err == nil {
		t.Fatal("expected a cancelled walk to fail")
	}
	if !errors.Is(err, model.ErrTemporarilyUnavailable) {
		t.Fatalf("expected a cancelled walk to be temporarily unavailable rather than a chain failure, got %v", err)
	}
	if errors.Is(err, model.ErrInvalidTrustChain) {
		t.Fatalf("a cancelled walk must not be reported as an invalid trust chain, got %v", err)
	}
}
