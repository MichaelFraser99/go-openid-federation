package subordinate_statement

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type redirectingFetchEndpoint map[string]string

const plaintextRequest = "a request sent without https"

func (p redirectingFetchEndpoint) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" {
		p[plaintextRequest] = r.URL.String()
	}
	answer, ok := p[r.URL.Scheme+"://"+r.URL.Host+r.URL.Path]
	if !ok {
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	}
	if strings.Contains(answer, "://") {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {answer + "?" + r.URL.RawQuery}}, Body: http.NoBody, Request: r}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/entity-statement+jwt"}},
		Body:       io.NopCloser(strings.NewReader(answer)),
		Request:    r,
	}, nil
}

func TestRetrieve_AStatementIsAcceptedOnlyWhenItsFinalHopIsHTTPS(t *testing.T) {
	const (
		anchor   = model.EntityIdentifier("https://ta.example.com")
		leaf     = model.EntityIdentifier("https://leaf.example.com")
		endpoint = "https://ta.example.com/fetch"
	)

	anchorKey := testKey(t)
	leafKey := testKey(t)
	issuer := testIssuerStatement(t, anchor, testPublicJwk(t, anchorKey.Public(), "ta"))
	issuer.Metadata = &model.Metadata{FederationMetadata: &model.FederationMetadata{"federation_fetch_endpoint": endpoint}}
	statement := testSign(t, anchorKey, map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"}, map[string]any{
		"iss":  string(anchor),
		"sub":  string(leaf),
		"iat":  time.Now().Add(-time.Minute).UTC().Unix(),
		"exp":  time.Now().Add(time.Hour).UTC().Unix(),
		"jwks": map[string]any{"keys": []any{testPublicJwk(t, leafKey.Public(), "leaf")}},
	})

	tests := []struct {
		name     string
		peer     redirectingFetchEndpoint
		accepted bool
	}{
		{name: "served at the fetch endpoint", peer: redirectingFetchEndpoint{endpoint: statement}, accepted: true},
		{name: "redirected to another https path", peer: redirectingFetchEndpoint{endpoint: "https://ta.example.com/served", "https://ta.example.com/served": statement}, accepted: true},
		{name: "redirected to plain http on the same host", peer: redirectingFetchEndpoint{endpoint: "http://ta.example.com/served", "http://ta.example.com/served": statement}},
		{name: "redirected to plain http on another host", peer: redirectingFetchEndpoint{endpoint: "http://cache.example.net/served", "http://cache.example.net/served": statement}},
		{name: "redirected through https and then to plain http", peer: redirectingFetchEndpoint{endpoint: "https://ta.example.com/hop", "https://ta.example.com/hop": "http://ta.example.com/served", "http://ta.example.com/served": statement}},
		{name: "redirected to an upper-case HTTP scheme", peer: redirectingFetchEndpoint{endpoint: "HTTP://ta.example.com/served", "http://ta.example.com/served": statement}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.Configuration{HttpClient: &http.Client{Transport: tc.peer}}
			_, parsed, err := Retrieve(t.Context(), cfg, issuer, leaf)
			if tc.accepted && (err != nil || parsed == nil) {
				t.Fatalf("[8.1] a statement fetched over https must be accepted, got %v", err)
			}
			if sent, ok := tc.peer[plaintextRequest]; ok {
				t.Errorf("[1.2] a redirect off https must be refused before it is followed, but %s was requested", sent)
			}
			if !tc.accepted && err == nil {
				t.Fatal("[5.1.1, 8.1] a statement whose final hop was not https was not fetched from the https fetch endpoint, so it must be refused")
			}
		})
	}
}
