package trust_marks

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type trustMarkFederation struct {
	server *httptest.Server
	keys   map[string]*rsa.PrivateKey
	id     map[string]model.EntityIdentifier
}

func (f *trustMarkFederation) client() *http.Client {
	return f.server.Client()
}

func federationPublicJwk(t *testing.T, pub crypto.PublicKey, kid string) map[string]any {
	t.Helper()
	publicJWK, err := jwk.PublicJwk(pub)
	if err != nil {
		t.Fatalf("failed to build public jwk: %v", err)
	}
	(*publicJWK)["kid"] = kid
	(*publicJWK)["alg"] = "RS256"
	return *publicJWK
}

func federationSign(t *testing.T, signer crypto.Signer, kid string, body map[string]any) string {
	t.Helper()
	head := map[string]any{"kid": kid, "typ": "entity-statement+jwt", "alg": "RS256"}
	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: josemodel.RS256})
	if err != nil {
		t.Fatalf("failed to sign statement: %v", err)
	}
	return *token
}

func newTrustMarkFederation(t *testing.T, issuers ...string) *trustMarkFederation {
	t.Helper()

	fed := &trustMarkFederation{
		keys: map[string]*rsa.PrivateKey{},
		id:   map[string]model.EntityIdentifier{},
	}

	nodes := append([]string{"trust_anchor"}, issuers...)
	for _, node := range nodes {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate key for %q: %v", node, err)
		}
		fed.keys[node] = key
	}

	nodeByIdentifier := func(identifier string) string {
		for node, id := range fed.id {
			if string(id) == identifier {
				return node
			}
		}
		return ""
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if strings.HasSuffix(path, "/.well-known/openid-federation") {
			node := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/.well-known/openid-federation")
			key, ok := fed.keys[node]
			if !ok {
				http.NotFound(w, r)
				return
			}

			body := map[string]any{
				"iss":      string(fed.id[node]),
				"sub":      string(fed.id[node]),
				"iat":      time.Now().UTC().Unix(),
				"exp":      time.Now().Add(time.Hour).UTC().Unix(),
				"jwks":     map[string]any{"keys": []any{federationPublicJwk(t, key.Public(), "test-key")}},
				"metadata": map[string]any{},
			}
			if node == "trust_anchor" {
				body["metadata"] = map[string]any{
					"federation_entity": map[string]any{
						"federation_fetch_endpoint": fmt.Sprintf("%s/trust_anchor/fetch", fed.server.URL),
					},
				}
			} else {
				body["authority_hints"] = []string{string(fed.id["trust_anchor"])}
			}

			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(federationSign(t, key, "test-key", body))) //nolint:errcheck
			return
		}

		if path == "/trust_anchor/fetch" {
			subject := r.URL.Query().Get("sub")
			node := nodeByIdentifier(subject)
			if node == "" || node == "trust_anchor" {
				http.NotFound(w, r)
				return
			}
			body := map[string]any{
				"iss":  string(fed.id["trust_anchor"]),
				"sub":  subject,
				"iat":  time.Now().UTC().Unix(),
				"exp":  time.Now().Add(time.Hour).UTC().Unix(),
				"jwks": map[string]any{"keys": []any{federationPublicJwk(t, fed.keys[node].Public(), "test-key")}},
			}
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(federationSign(t, fed.keys["trust_anchor"], "test-key", body))) //nolint:errcheck
			return
		}

		http.NotFound(w, r)
	})

	fed.server = httptest.NewTLSServer(handler)
	t.Cleanup(fed.server.Close)

	for _, node := range nodes {
		fed.id[node] = model.EntityIdentifier(fmt.Sprintf("%s/%s", fed.server.URL, node))
	}
	return fed
}

func federationTrustMark(t *testing.T, signer crypto.Signer, kid, iss, trustMarkType, sub string) string {
	t.Helper()
	head := map[string]any{"kid": kid, "typ": "trust-mark+jwt", "alg": "RS256"}
	body := map[string]any{
		"iss":             iss,
		"sub":             sub,
		"trust_mark_type": trustMarkType,
		"iat":             time.Now().UTC().Unix(),
		"exp":             time.Now().Add(time.Hour).UTC().Unix(),
	}
	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: josemodel.RS256})
	if err != nil {
		t.Fatalf("failed to create trust mark: %v", err)
	}
	return *token
}

func TestFilterByTrusted_AppliesTrustMarkValidationRules(t *testing.T) {
	fed := newTrustMarkFederation(t, "issuer", "rogue")

	const (
		subject       = model.EntityIdentifier("https://subject.example.com")
		otherSubject  = "https://someone-else.example.com"
		accreditedTM  = "https://tm.example.com/accredited"
		unaccredited  = "https://tm.example.com/unaccredited"
		openTrustMark = "https://tm.example.com/open"
	)

	issuerKey, issuerID := fed.keys["issuer"], fed.id["issuer"]
	rogueKey := fed.keys["rogue"]

	tests := []struct {
		name          string
		holder        model.TrustMarkHolder
		trustMarkType string
		issuers       []model.EntityIdentifier
		expectKept    bool
	}{
		{
			name: "a correctly issued trust mark is kept",
			holder: model.TrustMarkHolder{
				TrustMarkType: accreditedTM,
				TrustMark:     federationTrustMark(t, issuerKey, "test-key", string(issuerID), accreditedTM, string(subject)),
			},
			trustMarkType: accreditedTM,
			issuers:       []model.EntityIdentifier{issuerID},
			expectKept:    true,
		},
		{
			name: "an empty issuer list lets any issuer with a trust chain issue",
			holder: model.TrustMarkHolder{
				TrustMarkType: openTrustMark,
				TrustMark:     federationTrustMark(t, issuerKey, "test-key", string(issuerID), openTrustMark, string(subject)),
			},
			trustMarkType: openTrustMark,
			issuers:       []model.EntityIdentifier{},
			expectKept:    true,
		},
		{
			name: "a trust mark issued to another subject is dropped",
			holder: model.TrustMarkHolder{
				TrustMarkType: accreditedTM,
				TrustMark:     federationTrustMark(t, issuerKey, "test-key", string(issuerID), accreditedTM, otherSubject),
			},
			trustMarkType: accreditedTM,
			issuers:       []model.EntityIdentifier{issuerID},
			expectKept:    false,
		},
		{
			name: "a holder type that differs from the signed type is dropped",
			holder: model.TrustMarkHolder{
				TrustMarkType: accreditedTM,
				TrustMark:     federationTrustMark(t, issuerKey, "test-key", string(issuerID), unaccredited, string(subject)),
			},
			trustMarkType: accreditedTM,
			issuers:       []model.EntityIdentifier{issuerID},
			expectKept:    false,
		},
		{
			name: "a trust mark with a kid the issuer does not publish is dropped",
			holder: model.TrustMarkHolder{
				TrustMarkType: accreditedTM,
				TrustMark:     federationTrustMark(t, issuerKey, "not-a-published-kid", string(issuerID), accreditedTM, string(subject)),
			},
			trustMarkType: accreditedTM,
			issuers:       []model.EntityIdentifier{issuerID},
			expectKept:    false,
		},
		{
			name: "an issuer outside the federation is dropped for an open type",
			holder: model.TrustMarkHolder{
				TrustMarkType: openTrustMark,
				TrustMark:     federationTrustMark(t, rogueKey, "test-key", "https://rogue.example.net", openTrustMark, string(subject)),
			},
			trustMarkType: openTrustMark,
			issuers:       []model.EntityIdentifier{},
			expectKept:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolved := &model.ResolveResponse{
				Sub:        subject,
				Exp:        time.Now().Add(24 * time.Hour).UTC().Unix(),
				TrustMarks: []model.TrustMarkHolder{tc.holder},
			}
			trustAnchorConfiguration := model.EntityStatement{
				Sub:              fed.id["trust_anchor"],
				TrustMarkIssuers: map[string][]model.EntityIdentifier{tc.trustMarkType: tc.issuers},
			}

			cfg := model.Configuration{HttpClient: fed.client()}
			if err := FilterByTrusted(t.Context(), cfg, resolved, trustAnchorConfiguration, nil); err != nil {
				t.Fatalf("expected no error from filtering, got %v", err)
			}

			kept := len(resolved.TrustMarks) == 1
			if kept != tc.expectKept {
				t.Fatalf("expected kept=%t, got %d trust marks", tc.expectKept, len(resolved.TrustMarks))
			}
		})
	}
}
