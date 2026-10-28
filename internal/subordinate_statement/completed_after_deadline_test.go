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

func TestRetrieve_AResponseCompletedAfterTheCallersDeadlineIsNotAPeerFault(t *testing.T) {
	for name, transport := range completionsAfterTheRequestEnds {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{HttpClient: &http.Client{Transport: transport}, MaxPeerResponseTime: time.Hour}
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()

			_, err := retrieveWithin(t, ctx, cfg, issuerWithFetchEndpoint(t, "https://ta.example.com/fetch"))
			if !errors.Is(err, model.ErrTemporarilyUnavailable) {
				t.Errorf("[8.9] the caller's own deadline ended this fetch, so it is temporarily_unavailable whatever the peer sent afterwards, got %v", err)
			}
			if errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[8.9] a response that arrived after this server gave up says nothing about the peer's chain, got %v", err)
			}
		})
	}
}

func TestRetrieve_AResponseCompletedAfterThePeerDeadlineIsRefusedForTheDeadline(t *testing.T) {
	for name, transport := range completionsAfterTheRequestEnds {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{HttpClient: &http.Client{Transport: transport}, MaxPeerResponseTime: 50 * time.Millisecond}

			_, err := retrieveWithin(t, t.Context(), cfg, issuerWithFetchEndpoint(t, "https://ta.example.com/fetch"))
			if !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[8.9] a peer that ran out its deadline is a fault in the chain, got %v", err)
			}
			if errors.Is(err, model.ErrTemporarilyUnavailable) {
				t.Errorf("[8.9] temporarily_unavailable is this server's own deadline only, got %v", err)
			}
			if err != nil && !strings.Contains(err.Error(), "peer deadline") {
				t.Errorf("[8.9] the refusal must name the deadline rather than what arrived after it, got %v", err)
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
		class          error
		notClass       error
	}{
		"the peer's deadline ended the fetch":   {peerDeadline: 50 * time.Millisecond, callerDeadline: time.Hour, class: model.ErrInvalidTrustChain, notClass: model.ErrTemporarilyUnavailable},
		"the caller's deadline ended the fetch": {peerDeadline: time.Hour, callerDeadline: 50 * time.Millisecond, class: model.ErrTemporarilyUnavailable, notClass: model.ErrInvalidTrustChain},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{HttpClient: &http.Client{Transport: transportFailingAfterTheRequestEnds{}}, MaxPeerResponseTime: test.peerDeadline}
			ctx, cancel := context.WithTimeout(t.Context(), test.callerDeadline)
			defer cancel()

			_, err := retrieveWithin(t, ctx, cfg, issuerWithFetchEndpoint(t, "https://ta.example.com/fetch"))
			if !errors.Is(err, test.class) {
				t.Errorf("[8.9] expected %v, got %v", test.class, err)
			}
			if errors.Is(err, test.notClass) {
				t.Errorf("[8.9] must not be %v, got %v", test.notClass, err)
			}
			if test.class == model.ErrInvalidTrustChain && (err == nil || !strings.Contains(err.Error(), "peer deadline")) {
				t.Errorf("[8.9] the refusal must name the peer deadline rather than the transport error, got %v", err)
			}
		})
	}
}
