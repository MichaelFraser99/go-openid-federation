package entity_configuration

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func stallingPeer(t *testing.T, writeHeaders bool) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if writeHeaders {
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	return server
}

func TestRetrieve_APeerThatNeverAnswersDoesNotHoldTheRequest(t *testing.T) {
	tests := map[string]struct {
		reference    string
		writeHeaders bool
	}{
		"a peer that accepts and never responds": {reference: "8.2", writeHeaders: false},
		"a peer that sends headers then stalls":  {reference: "8.2", writeHeaders: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			server := stallingPeer(t, tc.writeHeaders)
			cfg := model.Configuration{
				HttpClient:          server.Client(),
				MaxPeerResponseTime: 50 * time.Millisecond,
			}

			done := make(chan error, 1)
			go func() {
				_, _, err := Retrieve(t.Context(), cfg, model.EntityIdentifier(server.URL), nil)
				done <- err
			}()

			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("[%s] a peer that never answers must not produce a statement", tc.reference)
				}
				if !errors.Is(err, context.DeadlineExceeded) && !isTimeout(err) && !strings.Contains(err.Error(), "context deadline exceeded") {
					t.Errorf("[%s] the refusal must name the deadline this resolver set rather than something else, got %v", tc.reference, err)
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("[%s] the fetch never returned, so a peer that accepts a connection and stays silent holds this request open", tc.reference)
			}
		})
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func TestRetrieve_TheDeadlineDoesNotReplaceTheCallersOwn(t *testing.T) {
	server := stallingPeer(t, false)
	cfg := model.Configuration{
		HttpClient:          server.Client(),
		MaxPeerResponseTime: time.Hour,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, _, err := Retrieve(ctx, cfg, model.EntityIdentifier(server.URL), nil)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("[8.2] a cancelled caller must not get a statement")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("[8.2] the per-peer deadline must not outlive the caller's own, so a cancelled request must return")
	}
}

func TestConfiguration_ThePeerDeadlineIsOnByDefault(t *testing.T) {
	var cfg model.Configuration
	if cfg.PeerResponseTimeLimit() != model.DefaultMaxPeerResponseTime {
		t.Errorf("expected a peer to be bounded in time by default, got %v", cfg.PeerResponseTimeLimit())
	}

	tests := map[string]time.Duration{"zero applies the default": 0, "negative applies the default": -time.Second}
	for name, configured := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{MaxPeerResponseTime: configured}
			if cfg.PeerResponseTimeLimit() != model.DefaultMaxPeerResponseTime {
				t.Errorf("expected the default, got %v", cfg.PeerResponseTimeLimit())
			}
		})
	}
}
