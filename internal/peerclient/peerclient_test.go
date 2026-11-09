package peerclient

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestHTTPSOnly_RefusesARedirectOffHTTPSAndKeepsTheClientsOwnPolicy(t *testing.T) {
	errConsumer := errors.New("the consumer's own redirect policy refused")
	refusesEverything := func(*http.Request, []*http.Request) error { return errConsumer }
	allowsEverything := func(*http.Request, []*http.Request) error { return nil }
	hops := func(n int) []*http.Request { return make([]*http.Request, n) }

	tests := []struct {
		name     string
		policy   func(*http.Request, []*http.Request) error
		target   string
		via      []*http.Request
		expected error
	}{
		{name: "an https redirect under the default policy", target: "https://peer.example.com/next", via: hops(1)},
		{name: "the ninth https redirect under the default policy", target: "https://peer.example.com/next", via: hops(9)},
		{name: "the tenth https redirect under the default policy", target: "https://peer.example.com/next", via: hops(10), expected: errors.New("stopped after 10 redirects")},
		{name: "a plain http redirect under the default policy", target: "http://peer.example.com/next", via: hops(1), expected: ErrRedirectOffHTTPS},
		{name: "a plain http redirect under a policy that allows everything", policy: allowsEverything, target: "http://peer.example.com/next", via: hops(1), expected: ErrRedirectOffHTTPS},
		{name: "an https redirect under a policy that allows everything", policy: allowsEverything, target: "https://peer.example.com/next", via: hops(50)},
		{name: "an https redirect under a policy that refuses everything", policy: refusesEverything, target: "https://peer.example.com/next", via: hops(1), expected: errConsumer},
		{name: "a redirect to another scheme", target: "ftp://peer.example.com/next", via: hops(1), expected: ErrRedirectOffHTTPS},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{CheckRedirect: tc.policy, Timeout: time.Minute}
			restricted := HTTPSOnly(client)

			target, err := url.Parse(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			got := restricted.CheckRedirect(&http.Request{URL: target}, tc.via)
			if tc.expected == nil && got != nil {
				t.Errorf("expected the redirect to be followed, got %v", got)
			}
			if tc.expected != nil && (got == nil || got.Error() != tc.expected.Error()) {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
			if restricted.Timeout != client.Timeout {
				t.Errorf("expected the consumer's client settings to be kept, got a timeout of %v", restricted.Timeout)
			}
			if tc.policy == nil && client.CheckRedirect != nil {
				t.Error("the consumer's client is shared, so it must be left unchanged")
			}
		})
	}
}
