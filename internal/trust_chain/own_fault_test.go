package trust_chain

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type blockingTransport struct {
	next    http.RoundTripper
	blocked string
	err     error
}

func (b blockingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasPrefix(r.URL.Path, "/"+b.blocked+"/") {
		return nil, b.err
	}
	return b.next.RoundTrip(r)
}

func TestBuildTrustChain_OnlyThisServersOwnFaultEndsTheWalk(t *testing.T) {
	hints := map[string][]string{
		"leaf":    {"blocked", "good"},
		"blocked": {"ta"},
		"good":    {"ta"},
		"ta":      {},
	}

	tests := []struct {
		name      string
		reference string
		subject   string
		peerErr   error
		ownErr    error
		want      error
	}{
		{
			name:      "a peer whose transport reports it temporarily unavailable, beside a good route",
			reference: "10.1",
			subject:   "leaf",
			peerErr:   fmt.Errorf("%wpeer throttled", model.ErrTemporarilyUnavailable),
		},
		{
			name:      "a peer whose transport fails without a class, beside a good route",
			reference: "10.1",
			subject:   "leaf",
			peerErr:   errors.New("peer unreachable"),
		},
		{
			name:      "this server temporarily unable to produce its own entity configuration, beside a good route",
			reference: "8.9 temporarily_unavailable",
			subject:   "leaf",
			ownErr:    model.NewTemporarilyUnavailableError("unable to produce the entity configuration at this time"),
			want:      model.ErrTemporarilyUnavailable,
		},
		{
			name:      "this server unable to produce its own entity configuration, beside a good route",
			reference: "8.9 server_error",
			subject:   "leaf",
			ownErr:    model.NewServerError("unable to produce the entity configuration at this time"),
			want:      model.ErrServerError,
		},
		{
			name:      "a peer trust anchor as its own subject whose transport reports it temporarily unavailable",
			reference: "8.9 temporarily_unavailable",
			subject:   "ta",
			peerErr:   fmt.Errorf("%wpeer throttled", model.ErrTemporarilyUnavailable),
			want:      model.ErrTemporarilyUnavailable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp := newTopo(t, hints)
			blocked := "blocked"
			if tc.subject == "ta" {
				blocked = "ta"
			}
			client := *tp.server.Client()
			if tc.peerErr != nil {
				client.Transport = blockingTransport{next: tp.server.Client().Transport, blocked: blocked, err: tc.peerErr}
			}
			cache := resolvecache.New()
			if tc.ownErr != nil {
				cache.SetOwn(tp.id["blocked"], func(context.Context) (*string, *model.EntityStatement, error) {
					return nil, nil, tc.ownErr
				}, nil)
			}

			_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: &client}, tp.id[tc.subject], tp.id["ta"], cache)

			if tc.want == nil {
				if err != nil {
					t.Fatalf("[%s] one failing peer must not end a walk that has another route, got %v", tc.reference, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("[%s] expected %v, got %v", tc.reference, tc.want, err)
			}
		})
	}
}
