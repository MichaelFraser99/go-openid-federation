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
			server := NewServer(model.ServerConfiguration{
				EntityIdentifier:            "https://leaf.example.com",
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "leaf"},
				EntityConfiguration:         model.EntityStatement{Iss: "https://leaf.example.com"},
				EntityConfigurationLifetime: time.Hour,
				AuthorityHints:              tc.configure,
			})
			for _, hint := range tc.add {
				server.AddAuthorityHint(hint)
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
