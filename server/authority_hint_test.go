package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_AddAuthorityHint_PublishesEachSuperiorOnce(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	tests := []struct {
		name      string
		configure []model.EntityIdentifier
		add       []model.EntityIdentifier
		expect    []model.EntityIdentifier
	}{
		{
			name:   "the same hint added twice",
			add:    []model.EntityIdentifier{"https://authority.example.com", "https://authority.example.com"},
			expect: []model.EntityIdentifier{"https://authority.example.com"},
		},
		{
			name:      "a hint added that was already configured",
			configure: []model.EntityIdentifier{"https://authority.example.com"},
			add:       []model.EntityIdentifier{"https://authority.example.com"},
			expect:    []model.EntityIdentifier{"https://authority.example.com"},
		},
		{
			name:   "a repeated hint between two distinct ones",
			add:    []model.EntityIdentifier{"https://a.example.com", "https://b.example.com", "https://a.example.com"},
			expect: []model.EntityIdentifier{"https://a.example.com", "https://b.example.com"},
		},
		{
			name:   "two spellings the read path keeps apart",
			add:    []model.EntityIdentifier{"https://authority.example.com", "https://authority.example.com/"},
			expect: []model.EntityIdentifier{"https://authority.example.com", "https://authority.example.com/"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := mustNewServer(t, model.ServerConfiguration{
				EntityIdentifier:            "https://leaf.example.com",
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "leaf"},
				EntityConfiguration:         model.EntityStatement{Iss: "https://leaf.example.com"},
				EntityConfigurationLifetime: time.Hour,
				AuthorityHints:              tc.configure,
			})
			for _, hint := range tc.add {
				if err := server.AddAuthorityHint(hint); err != nil {
					t.Fatalf("[3.1.2] expected a superior's entity identifier to be added, got %v", err)
				}
			}
			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)

			response, err := ts.Client().Get(ts.URL + "/.well-known/openid-federation")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("expected the entity configuration, got %d %s", response.StatusCode, raw)
			}
			parts := strings.Split(string(raw), ".")
			if len(parts) != 3 {
				t.Fatalf("[3.1] expected a compact JWS, got %s", raw)
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("failed to decode the entity configuration: %v", err)
			}
			var claims struct {
				AuthorityHints []model.EntityIdentifier `json:"authority_hints"`
			}
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatalf("failed to read the entity configuration: %v", err)
			}

			if !slices.Equal(claims.AuthorityHints, tc.expect) {
				t.Errorf("[3.1.2] authority_hints lists the entity identifiers of the immediate superiors, each once, expected %v, got %v", tc.expect, claims.AuthorityHints)
			}
			if !slices.Equal(server.AuthorityHints(), tc.expect) {
				t.Errorf("[3.1.2] expected AuthorityHints() to report %v, got %v", tc.expect, server.AuthorityHints())
			}
		})
	}
}

func TestServer_AddAuthorityHint_RefusesAHintThatIsNotAnotherEntitysIdentifier(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	const own = "https://leaf.example.com/fed"

	tests := []struct {
		name      string
		reference string
		hint      model.EntityIdentifier
		expectErr string
	}{
		{name: "a superior's entity identifier", reference: "3.1.2", hint: "https://authority.example.com"},
		{name: "a superior on the same host as this server", reference: "3.1.2", hint: "https://leaf.example.com/authority"},
		{name: "an http identifier", reference: "1.2", hint: "http://SECRETHOST.example.com", expectErr: "AuthorityHint is not an entity identifier"},
		{name: "an empty identifier", reference: "1.2", hint: "", expectErr: "AuthorityHint is not an entity identifier"},
		{name: "an identifier carrying a fragment", reference: "1.2", hint: "https://SECRETHOST.example.com#fragment", expectErr: "AuthorityHint is not an entity identifier"},
		{name: "an identifier carrying a query", reference: "1.2", hint: "https://SECRETHOST.example.com?query", expectErr: "AuthorityHint is not an entity identifier"},
		{name: "a value that is not a URL", reference: "1.2", hint: "SECRETHOST", expectErr: "AuthorityHint is not an entity identifier"},
		{name: "this server's own identifier", reference: "3.1.2", hint: own, expectErr: "AuthorityHint names this server"},
		{name: "this server's own identifier in another spelling", reference: "3.1.2", hint: "https://LEAF.example.com:443/fed/", expectErr: "AuthorityHint names this server"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := mustNewServer(t, model.ServerConfiguration{
				EntityIdentifier:            own,
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "leaf"},
				EntityConfigurationLifetime: time.Hour,
				AuthorityHints:              []model.EntityIdentifier{"https://configured.example.com"},
			})

			err := server.AddAuthorityHint(tc.hint)

			expect := []model.EntityIdentifier{"https://configured.example.com"}
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the hint to be added, got %v", tc.reference, err)
				}
				expect = append(expect, tc.hint)
			} else {
				if err == nil {
					t.Fatalf("[%s] authority_hints holds the entity identifiers of the immediate superiors, so %q must be refused", tc.reference, tc.hint)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
				}
				if (tc.hint != "" && strings.Contains(err.Error(), string(tc.hint))) || strings.Contains(err.Error(), "SECRETHOST") {
					t.Errorf("[%s] expected the refusal not to echo the hint, got %v", tc.reference, err)
				}
			}
			if !slices.Equal(server.AuthorityHints(), expect) {
				t.Errorf("[%s] expected AuthorityHints() to report %v, got %v", tc.reference, expect, server.AuthorityHints())
			}

			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)
			response, err := ts.Client().Get(ts.URL + "/.well-known/openid-federation")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != http.StatusOK {
				raw, _ := io.ReadAll(response.Body)
				t.Errorf("[%s] expected the entity configuration to stay available, got %d %s", tc.reference, response.StatusCode, raw)
			}
		})
	}
}
