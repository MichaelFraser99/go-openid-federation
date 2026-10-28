package entity_configuration

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type bodyEndingCleanlyAtDeadline struct {
	prefix []byte
	done   <-chan struct{}
}

func (b *bodyEndingCleanlyAtDeadline) Read(p []byte) (int, error) {
	if len(b.prefix) > 0 {
		n := copy(p, b.prefix)
		b.prefix = b.prefix[n:]
		return n, nil
	}
	<-b.done
	return 0, io.EOF
}

func (b *bodyEndingCleanlyAtDeadline) Close() error { return nil }

type transportEndingBodiesCleanlyAtDeadline struct{ prefix string }

func (tr transportEndingBodiesCleanlyAtDeadline) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/entity-statement+jwt"}},
		Body:       &bodyEndingCleanlyAtDeadline{prefix: []byte(tr.prefix), done: r.Context().Done()},
		Request:    r,
	}, nil
}

func TestRetrieve_ABodyThatOutlivesThePeerDeadlineIsNotTrusted(t *testing.T) {
	tests := map[string]string{
		"no bytes before the deadline":                        "",
		"part of a statement before the deadline":             "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3BlZXIu",
		"a complete looking compact form before the deadline": "eyJhbGciOiJFUzI1NiJ9.e30.c2ln",
	}

	for name, prefix := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{
				HttpClient:          &http.Client{Transport: transportEndingBodiesCleanlyAtDeadline{prefix: prefix}},
				MaxPeerResponseTime: 50 * time.Millisecond,
			}

			_, _, err := Retrieve(t.Context(), cfg, "https://peer.example.com", nil)
			if err == nil {
				t.Fatal("[8.2] a body the peer was still sending when the deadline passed is not a complete statement")
			}
			if !strings.Contains(err.Error(), "peer deadline") {
				t.Errorf("[8.2] a peer that ran out its deadline must be refused for the deadline, not for what it had sent so far, got %v", err)
			}
		})
	}
}

func TestRetrieve_ACallerCancellationIsNotReportedAsThePeersDeadline(t *testing.T) {
	cfg := model.Configuration{
		HttpClient:          &http.Client{Transport: transportEndingBodiesCleanlyAtDeadline{}},
		MaxPeerResponseTime: time.Hour,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	_, _, err := Retrieve(ctx, cfg, "https://peer.example.com", nil)
	if err == nil {
		t.Fatal("expected the caller's cancellation to end the fetch")
	}
	if strings.Contains(err.Error(), "peer deadline") {
		t.Errorf("[8.9] the caller's own deadline ended this fetch, not the peer's, got %v", err)
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("expected the refusal to carry the caller's context error, got %v", err)
	}
}
