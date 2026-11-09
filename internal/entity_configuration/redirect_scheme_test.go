package entity_configuration

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type redirectingPeer map[string]string

const plaintextRequest = "a request sent without https"

func (p redirectingPeer) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" {
		p[plaintextRequest] = r.URL.String()
	}
	answer, ok := p[r.URL.String()]
	if !ok {
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	}
	if strings.Contains(answer, "://") {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {answer}}, Body: http.NoBody, Request: r}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/entity-statement+jwt"}},
		Body:       io.NopCloser(strings.NewReader(answer)),
		Request:    r,
	}, nil
}

func TestRetrieve_AStatementIsAcceptedOnlyWhenItsFinalHopIsHTTPS(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")
	const wellKnown = "https://leaf.example.com/.well-known/openid-federation"

	key := headerJwkKey(t)
	statement := signStatementWithKey(t, key, map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"}, map[string]any{
		"iss":      string(leaf),
		"sub":      string(leaf),
		"iat":      time.Now().Add(-time.Minute).UTC().Unix(),
		"exp":      time.Now().Add(time.Hour).UTC().Unix(),
		"jwks":     map[string]any{"keys": []any{headerJwkPublicJwk(t, key.Public(), "leaf")}},
		"metadata": map[string]any{},
	})

	tests := []struct {
		name     string
		peer     redirectingPeer
		accepted bool
	}{
		{name: "served at the identifier", peer: redirectingPeer{wellKnown: statement}, accepted: true},
		{name: "redirected to another https path", peer: redirectingPeer{wellKnown: "https://leaf.example.com/served", "https://leaf.example.com/served": statement}, accepted: true},
		{name: "redirected to plain http on the same host", peer: redirectingPeer{wellKnown: "http://leaf.example.com/served", "http://leaf.example.com/served": statement}},
		{name: "redirected to plain http on another host", peer: redirectingPeer{wellKnown: "http://cache.example.net/served", "http://cache.example.net/served": statement}},
		{name: "redirected through https and then to plain http", peer: redirectingPeer{wellKnown: "https://leaf.example.com/hop", "https://leaf.example.com/hop": "http://leaf.example.com/served", "http://leaf.example.com/served": statement}},
		{name: "redirected to an upper-case HTTP scheme", peer: redirectingPeer{wellKnown: "HTTP://leaf.example.com/served", "http://leaf.example.com/served": statement}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.Configuration{HttpClient: &http.Client{Transport: tc.peer}}
			_, parsed, err := Retrieve(t.Context(), cfg, leaf, nil)
			if tc.accepted && (err != nil || parsed == nil) {
				t.Fatalf("[9] a statement fetched over https must be accepted, got %v", err)
			}
			if sent, ok := tc.peer[plaintextRequest]; ok {
				t.Errorf("[1.2] a redirect off https must be refused before it is followed, but %s was requested", sent)
			}
			if !tc.accepted && err == nil {
				t.Fatal("[1.2, 9] a statement whose final hop was not https was not fetched from the https identifier, so it must be refused")
			}
		})
	}
}
