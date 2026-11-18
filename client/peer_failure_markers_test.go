package client

import (
	"crypto/rsa"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type peerFederation struct {
	t        *testing.T
	base     string
	client   *http.Client
	key      *rsa.PrivateKey
	hang     map[string]bool
	stall    map[string]bool
	missing  map[string]bool
	claims   map[string]map[string]any
	fetchURL string
}

func newPeerFederation(t *testing.T, key *rsa.PrivateKey) *peerFederation {
	t.Helper()
	federation := &peerFederation{t: t, key: key, hang: map[string]bool{}, stall: map[string]bool{}, missing: map[string]bool{}, claims: map[string]map[string]any{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(federation.serve))
	t.Cleanup(srv.Close)
	federation.client = srv.Client()
	federation.base = srv.URL
	return federation
}

func (f *peerFederation) id(name string) string {
	return f.base + "/" + name
}

func (f *peerFederation) statement(name string) string {
	now := time.Now().UTC()
	body := map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": map[string]any{"keys": []any{bindingJwk(f.t, f.key.Public())}}, "metadata": map[string]any{}}
	switch name {
	case "leaf":
		body["iss"], body["sub"], body["authority_hints"] = f.id("leaf"), f.id("leaf"), []any{f.id("ta")}
	case "ta":
		fetch := f.id("ta") + "/fetch"
		if f.fetchURL != "" {
			fetch = f.fetchURL
		}
		body["iss"], body["sub"] = f.id("ta"), f.id("ta")
		body["metadata"] = map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": fetch}}
	case "ta>leaf":
		body["iss"], body["sub"] = f.id("ta"), f.id("leaf")
		delete(body, "metadata")
	}
	for claim, value := range f.claims[name] {
		body[claim] = value
	}
	return bindingSign(f.t, f.key, body)
}

func (f *peerFederation) serve(w http.ResponseWriter, r *http.Request) {
	var name string
	switch r.URL.Path {
	case "/leaf/.well-known/openid-federation":
		name = "leaf"
	case "/ta/.well-known/openid-federation":
		name = "ta"
	case "/ta/fetch":
		if r.URL.Query().Get("sub") != f.id("leaf") {
			http.NotFound(w, r)
			return
		}
		name = "ta>leaf"
	default:
		http.NotFound(w, r)
		return
	}
	if f.hang[name] {
		<-r.Context().Done()
		return
	}
	if f.stall[name] {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(f.statement(name)[:10]))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return
	}
	if f.missing[name] {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	_, _ = w.Write([]byte(f.statement(name)))
}

func closedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve an address: %v", err)
	}
	address := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatalf("failed to release the address: %v", err)
	}
	return "https://" + address
}

func expiredAt(at time.Duration) map[string]any {
	exp := time.Now().UTC().Add(at)
	return map[string]any{"iat": exp.Add(-10 * time.Minute).Unix(), "exp": exp.Unix()}
}

var peerFailureMarkers = map[string]error{"ErrPeerUnreachable": model.ErrPeerUnreachable, "ErrPeerTimeout": model.ErrPeerTimeout, "ErrExpired": model.ErrExpired}

func assertPeerFailure(t *testing.T, err error, class error, marker string, description string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected the request to be refused")
	}
	if !errors.Is(err, class) {
		t.Errorf("the marker must not change the class of the error, expected %v, got %v", class, err)
	}
	for name, sentinel := range peerFailureMarkers {
		if got := errors.Is(err, sentinel); got != (name == marker) {
			t.Errorf("expected errors.Is(err, model.%s) to be %t, got %t for %q", name, name == marker, got, err.Error())
		}
	}
	if description != "" && err.Error() != description {
		t.Errorf("the marker must not change the error's text, expected %q, got %q", description, err.Error())
	}
	for _, leaked := range []string{"dial", "refused", "deadline", "timeout", "context", "EOF"} {
		if strings.Contains(err.Error(), leaked) {
			t.Errorf("a transport error's own text must not reach the error, found %q in %q", leaked, err.Error())
		}
	}
}

func TestClient_BuildTrustChain_TellsAPeerThatAnsweredFromOneThatDidNot(t *testing.T) {
	key := bindingKey(t)
	const statementUnusable = "failed to retrieve a usable subordinate statement for an entity in the trust chain"

	tests := []struct {
		name        string
		setup       func(f *peerFederation)
		subject     func(f *peerFederation) string
		class       error
		marker      string
		description func(subject string) string
	}{
		{
			name:        "the subject answers 404",
			setup:       func(f *peerFederation) { f.missing["leaf"] = true },
			class:       model.ErrNotFound,
			description: func(subject string) string { return "failed to retrieve entity configuration for " + subject },
		},
		{
			name:        "the subject cannot be reached",
			subject:     func(f *peerFederation) string { return closedAddress(t) + "/leaf" },
			class:       model.ErrNotFound,
			marker:      "ErrPeerUnreachable",
			description: func(subject string) string { return "failed to retrieve entity configuration for " + subject },
		},
		{
			name:        "the subject does not answer within the peer response time",
			setup:       func(f *peerFederation) { f.hang["leaf"] = true },
			class:       model.ErrNotFound,
			marker:      "ErrPeerTimeout",
			description: func(subject string) string { return "failed to retrieve entity configuration for " + subject },
		},
		{
			name:        "the anchor's fetch endpoint answers 404",
			setup:       func(f *peerFederation) { f.missing["ta>leaf"] = true },
			class:       model.ErrInvalidTrustChain,
			description: func(string) string { return statementUnusable },
		},
		{
			name:        "the anchor's fetch endpoint cannot be reached",
			setup:       func(f *peerFederation) { f.fetchURL = closedAddress(t) + "/fetch" },
			class:       model.ErrInvalidTrustChain,
			marker:      "ErrPeerUnreachable",
			description: func(string) string { return statementUnusable },
		},
		{
			name:        "the anchor's fetch endpoint does not answer within the peer response time",
			setup:       func(f *peerFederation) { f.hang["ta>leaf"] = true },
			class:       model.ErrInvalidTrustChain,
			marker:      "ErrPeerTimeout",
			description: func(string) string { return statementUnusable },
		},
		{
			name:        "the anchor's fetch endpoint stops answering part way through the statement",
			setup:       func(f *peerFederation) { f.stall["ta>leaf"] = true },
			class:       model.ErrInvalidTrustChain,
			marker:      "ErrPeerTimeout",
			description: func(string) string { return statementUnusable },
		},
		{
			name:        "the subject stops answering part way through its entity configuration",
			setup:       func(f *peerFederation) { f.stall["leaf"] = true },
			class:       model.ErrNotFound,
			marker:      "ErrPeerTimeout",
			description: func(subject string) string { return "failed to retrieve entity configuration for " + subject },
		},
		{
			name:        "the subject's entity configuration has expired",
			setup:       func(f *peerFederation) { f.claims["leaf"] = expiredAt(-5 * time.Minute) },
			class:       model.ErrInvalidTrustChain,
			marker:      "ErrExpired",
			description: func(subject string) string { return "entity configuration for " + subject + " failed validation" },
		},
		{
			name:        "the subject's entity configuration is invalid for another reason",
			setup:       func(f *peerFederation) { f.claims["leaf"] = map[string]any{"iss": "https://elsewhere.example.com"} },
			class:       model.ErrInvalidTrustChain,
			description: func(subject string) string { return "entity configuration for " + subject + " failed validation" },
		},
		{
			name:        "the anchor's statement about the subject has expired",
			setup:       func(f *peerFederation) { f.claims["ta>leaf"] = expiredAt(-5 * time.Minute) },
			class:       model.ErrInvalidTrustChain,
			marker:      "ErrExpired",
			description: func(string) string { return statementUnusable },
		},
		{
			name:   "the chain expires inside the clock skew leeway",
			setup:  func(f *peerFederation) { f.claims["ta>leaf"] = expiredAt(-5 * time.Second) },
			class:  model.ErrInvalidTrustChain,
			marker: "ErrExpired",
			description: func(string) string {
				return "trust chain expiry is not in the future, so no resolve response can be issued for it"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newPeerFederation(t, key)
			if tc.setup != nil {
				tc.setup(f)
			}
			subject := f.id("leaf")
			if tc.subject != nil {
				subject = tc.subject(f)
			}
			c := New(model.ClientConfiguration{Configuration: model.Configuration{HttpClient: f.client, MaxPeerResponseTime: 300 * time.Millisecond}})

			_, _, _, err := c.BuildTrustChain(t.Context(), subject, f.id("ta"))
			assertPeerFailure(t, err, tc.class, tc.marker, tc.description(subject))
		})
	}
}

func TestClient_ResolveMetadata_TellsAnExpiredOrUnreachableChainFromAnInvalidOne(t *testing.T) {
	key := bindingKey(t)

	tests := []struct {
		name        string
		setup       func(f *peerFederation)
		chain       func(f *peerFederation) []string
		trusting    bool
		class       error
		marker      string
		description string
	}{
		{
			name:  "a supplied subordinate statement has expired",
			setup: func(f *peerFederation) { f.claims["ta>leaf"] = expiredAt(-5 * time.Minute) },
			chain: func(f *peerFederation) []string {
				return []string{f.statement("leaf"), f.statement("ta>leaf"), f.statement("ta")}
			},
			trusting:    true,
			class:       model.ErrInvalidTrustChain,
			marker:      "ErrExpired",
			description: "trust chain entry 1 is not a valid subordinate statement",
		},
		{
			name: "a supplied subordinate statement is signed by another key",
			chain: func(f *peerFederation) []string {
				other := newPeerFederation(t, bindingKey(t))
				other.base = f.base
				return []string{f.statement("leaf"), other.statement("ta>leaf"), f.statement("ta")}
			},
			trusting:    true,
			class:       model.ErrInvalidTrustChain,
			description: "trust chain entry 1 is not a valid subordinate statement",
		},
		{
			name:  "the supplied chain expires inside the clock skew leeway",
			setup: func(f *peerFederation) { f.claims["ta>leaf"] = expiredAt(-5 * time.Second) },
			chain: func(f *peerFederation) []string {
				return []string{f.statement("leaf"), f.statement("ta>leaf"), f.statement("ta")}
			},
			trusting:    true,
			class:       model.ErrInvalidTrustChain,
			marker:      "ErrExpired",
			description: "trust chain expiry is not in the future, so no resolve response can be issued for it",
		},
		{
			name:        "the omitted anchor answers 404",
			setup:       func(f *peerFederation) { f.missing["ta"] = true },
			chain:       func(f *peerFederation) []string { return []string{f.statement("leaf"), f.statement("ta>leaf")} },
			class:       model.ErrInvalidTrustAnchor,
			description: "the entity configuration of the requested trust anchor could not be retrieved",
		},
		{
			name:        "the omitted anchor cannot be reached",
			setup:       func(f *peerFederation) { f.base = closedAddress(t) },
			chain:       func(f *peerFederation) []string { return []string{f.statement("leaf"), f.statement("ta>leaf")} },
			class:       model.ErrInvalidTrustAnchor,
			marker:      "ErrPeerUnreachable",
			description: "the entity configuration of the requested trust anchor could not be retrieved",
		},
		{
			name:        "the omitted anchor does not answer within the peer response time",
			setup:       func(f *peerFederation) { f.hang["ta"] = true },
			chain:       func(f *peerFederation) []string { return []string{f.statement("leaf"), f.statement("ta>leaf")} },
			class:       model.ErrInvalidTrustAnchor,
			marker:      "ErrPeerTimeout",
			description: "the entity configuration of the requested trust anchor could not be retrieved",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newPeerFederation(t, key)
			if tc.setup != nil {
				tc.setup(f)
			}
			c := New(model.ClientConfiguration{Configuration: model.Configuration{HttpClient: f.client, MaxPeerResponseTime: 300 * time.Millisecond}})

			var err error
			if tc.trusting {
				_, err = resolveTrustingSuppliedAnchor(t, c, t.Context(), f.id("leaf"), f.id("ta"), tc.chain(f))
			} else {
				_, err = c.ResolveMetadata(t.Context(), f.id("leaf"), f.id("ta"), tc.chain(f))
			}
			assertPeerFailure(t, err, tc.class, tc.marker, tc.description)
		})
	}
}
