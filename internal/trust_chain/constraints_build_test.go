package trust_chain

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type federationClaims struct {
	leaf, subordinate, anchor map[string]any
}

func federationWithClaims(t *testing.T, host string, claims federationClaims) (*http.Client, model.EntityIdentifier, model.EntityIdentifier) {
	t.Helper()
	leafKey, anchorKey := chainSigningKey(t), chainSigningKey(t)
	var base string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaf, anchor := base+"/leaf", base+"/ta"
		now := time.Now().UTC()
		body := func(iss, sub string, key any) map[string]any {
			return map[string]any{"iss": iss, "sub": sub, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": key}
		}
		var token string
		switch {
		case r.URL.Path == "/leaf/.well-known/openid-federation":
			statement := body(leaf, leaf, chainJwks(t, leafKey))
			statement["authority_hints"] = []any{anchor}
			statement["metadata"] = map[string]any{"federation_entity": map[string]any{"contacts": []any{"leaf@example.com"}}}
			for claim, value := range claims.leaf {
				statement[claim] = value
			}
			token = chainSignStatement(t, leafKey, statement)
		case r.URL.Path == "/ta/.well-known/openid-federation":
			statement := body(anchor, anchor, chainJwks(t, anchorKey))
			statement["metadata"] = map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": anchor + "/fetch"}}
			for claim, value := range claims.anchor {
				statement[claim] = value
			}
			token = chainSignStatement(t, anchorKey, statement)
		case r.URL.Path == "/ta/fetch" && r.URL.Query().Get("sub") == leaf:
			statement := body(anchor, leaf, chainJwks(t, leafKey))
			for claim, value := range claims.subordinate {
				statement[claim] = value
			}
			token = chainSignStatement(t, anchorKey, statement)
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(srv.Close)

	address, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	base = "https://" + net.JoinHostPort(host, address.Port())
	client := srv.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address.Host)
	}
	client.Transport = transport
	return client, model.EntityIdentifier(base + "/leaf"), model.EntityIdentifier(base + "/ta")
}

func TestBuildTrustChain_EnforcesConstraints(t *testing.T) {
	tests := map[string]struct {
		host        string
		constraints map[string]any
		expectErr   string
	}{
		"no constraints":                         {host: "example.com"},
		"a path length the chain satisfies":      {host: "example.com", constraints: map[string]any{"max_path_length": 0}},
		"a host permission the chain satisfies":  {host: "example.com", constraints: map[string]any{"naming_constraints": map[string]any{"permitted": []any{"example.com"}}}},
		"an exclusion elsewhere":                 {host: "example.com", constraints: map[string]any{"naming_constraints": map[string]any{"excluded": []any{".evil.example"}}}},
		"an excluded host":                       {host: "example.com", constraints: map[string]any{"naming_constraints": map[string]any{"excluded": []any{"example.com"}}}, expectErr: "is outside the naming constraints"},
		"a domain that does not cover its apex":  {host: "example.com", constraints: map[string]any{"naming_constraints": map[string]any{"permitted": []any{".example.com"}}}, expectErr: "is outside the naming constraints"},
		"an address under any naming constraint": {host: "127.0.0.1", constraints: map[string]any{"naming_constraints": map[string]any{"excluded": []any{".evil.example"}}}, expectErr: "is outside the naming constraints"},
		"an address with no naming constraint":   {host: "127.0.0.1", constraints: map[string]any{"max_path_length": 0}},
		"malformed constraints":                  {host: "example.com", constraints: map[string]any{"max_path_length": -1}, expectErr: "failed to retrieve a usable subordinate statement"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{}
			if tc.constraints != nil {
				claims["constraints"] = tc.constraints
			}
			client, leaf, anchor := federationWithClaims(t, tc.host, federationClaims{subordinate: claims})
			_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: client}, leaf, anchor, resolvecache.New())
			assertConstraintVerdict(t, "10.2", err, tc.expectErr)
		})
	}
}
