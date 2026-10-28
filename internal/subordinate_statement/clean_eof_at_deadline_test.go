package subordinate_statement

import (
	"context"
	"errors"
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

func TestRetrieve_AFetchBodyThatOutlivesThePeerDeadlineIsAPeerFault(t *testing.T) {
	tests := map[string]string{
		"no bytes before the deadline":            "",
		"part of a statement before the deadline": "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3BlZXIu",
	}

	for name, prefix := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{
				HttpClient:          &http.Client{Transport: transportEndingBodiesCleanlyAtDeadline{prefix: prefix}},
				MaxPeerResponseTime: 50 * time.Millisecond,
			}

			_, err := retrieveWithin(t, t.Context(), cfg, issuerWithFetchEndpoint(t, "https://ta.example.com/fetch"))
			if !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[8.9] a peer that ran out its deadline is a fault in the chain, got %v", err)
			}
			if errors.Is(err, model.ErrTemporarilyUnavailable) {
				t.Errorf("[8.9] temporarily_unavailable is this server's own deadline only, got %v", err)
			}
			if err != nil && !strings.Contains(err.Error(), "peer deadline") {
				t.Errorf("[8.9] the refusal must name the deadline rather than what the peer had sent so far, got %v", err)
			}
		})
	}
}

func TestRetrieve_AFetchBodyCutShortByTheCallerIsNotAPeerFault(t *testing.T) {
	cfg := model.Configuration{
		HttpClient:          &http.Client{Transport: transportEndingBodiesCleanlyAtDeadline{}},
		MaxPeerResponseTime: time.Hour,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	_, err := retrieveWithin(t, ctx, cfg, issuerWithFetchEndpoint(t, "https://ta.example.com/fetch"))
	if !errors.Is(err, model.ErrTemporarilyUnavailable) {
		t.Errorf("[8.9] the caller's own deadline is temporarily_unavailable, got %v", err)
	}
	if errors.Is(err, model.ErrInvalidTrustChain) {
		t.Errorf("[8.9] a caller that gave up is not a fault in the peer's chain, got %v", err)
	}
}
