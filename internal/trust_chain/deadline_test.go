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
