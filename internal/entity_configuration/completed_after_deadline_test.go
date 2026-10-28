package entity_configuration

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

type transportCompletingAfterTheRequestEnds struct {
	status int
	header http.Header
}

func (tr transportCompletingAfterTheRequestEnds) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return &http.Response{StatusCode: tr.status, Header: tr.header, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

var completionsAfterTheRequestEnds = map[string]transportCompletingAfterTheRequestEnds{
	"an empty 200 with no Content-Type":        {status: http.StatusOK, header: http.Header{}},
	"an empty 200 with the right Content-Type": {status: http.StatusOK, header: http.Header{"Content-Type": {"application/entity-statement+jwt"}}},
	"a 503": {status: http.StatusServiceUnavailable, header: http.Header{}},
}

func TestRetrieve_AResponseCompletedAfterThePeerDeadlineIsRefusedForTheDeadline(t *testing.T) {
	for name, transport := range completionsAfterTheRequestEnds {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{HttpClient: &http.Client{Transport: transport}, MaxPeerResponseTime: 50 * time.Millisecond}

			_, _, err := Retrieve(t.Context(), cfg, "https://peer.example.com", nil)
			if err == nil {
				t.Fatal("[8.2] a response that arrived after the peer deadline is not a statement")
			}
			if !strings.Contains(err.Error(), "peer deadline") {
				t.Errorf("[8.2] the refusal must name the deadline rather than what arrived after it, got %v", err)
			}
		})
	}
}

func TestRetrieve_AResponseCompletedAfterTheCallersDeadlineIsNotThePeersDeadline(t *testing.T) {
	for name, transport := range completionsAfterTheRequestEnds {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{HttpClient: &http.Client{Transport: transport}, MaxPeerResponseTime: time.Hour}
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()

			_, _, err := Retrieve(ctx, cfg, "https://peer.example.com", nil)
			if err == nil {
				t.Fatal("expected the caller's deadline to end the fetch")
			}
			if strings.Contains(err.Error(), "peer deadline") {
				t.Errorf("[8.9] the caller's own deadline ended this fetch, not the peer's, got %v", err)
			}
			if !strings.Contains(err.Error(), "stopped fetching") {
				t.Errorf("[8.9] the refusal must say this server stopped, rather than describe what the peer sent afterwards, got %v", err)
			}
		})
	}
}

type transportFailingAfterTheRequestEnds struct{}

func (transportFailingAfterTheRequestEnds) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, errors.New("connection reset by peer")
}

func TestRetrieve_ATransportErrorAfterTheDeadlineIsReportedAsTheDeadline(t *testing.T) {
	tests := map[string]struct {
		peerDeadline   time.Duration
		callerDeadline time.Duration
		says           string
		mustNotSay     string
	}{
		"the peer's deadline ended the fetch":   {peerDeadline: 50 * time.Millisecond, callerDeadline: time.Hour, says: "peer deadline", mustNotSay: "connection reset"},
		"the caller's deadline ended the fetch": {peerDeadline: time.Hour, callerDeadline: 50 * time.Millisecond, says: "stopped fetching", mustNotSay: "peer deadline"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{HttpClient: &http.Client{Transport: transportFailingAfterTheRequestEnds{}}, MaxPeerResponseTime: test.peerDeadline}
			ctx, cancel := context.WithTimeout(t.Context(), test.callerDeadline)
			defer cancel()

			_, _, err := Retrieve(ctx, cfg, "https://peer.example.com", nil)
			if err == nil {
				t.Fatal("expected the fetch to be refused")
			}
			if !strings.Contains(err.Error(), test.says) {
				t.Errorf("[8.9] the refusal must name the context that ended, %q, got %v", test.says, err)
			}
			if strings.Contains(err.Error(), test.mustNotSay) {
				t.Errorf("[8.9] the refusal must not name %q, got %v", test.mustNotSay, err)
			}
		})
	}
}
