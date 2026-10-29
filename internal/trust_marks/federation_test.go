package trust_marks

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type federationNode struct {
	name string

	notSubordinate bool
	extraECKey     bool
}

type trustMarkFederation struct {
	server *httptest.Server
	keys   map[string]*rsa.PrivateKey
	extra  map[string]*rsa.PrivateKey
	id     map[string]model.EntityIdentifier

	wellKnown map[string]string
	statement map[string]string
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
	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to sign statement: %v", err)
	}
	return *token
}

func newTrustMarkFederation(t *testing.T, nodes ...federationNode) *trustMarkFederation {
	t.Helper()

	fed := &trustMarkFederation{
		keys:      map[string]*rsa.PrivateKey{},
		extra:     map[string]*rsa.PrivateKey{},
		id:        map[string]model.EntityIdentifier{},
		wellKnown: map[string]string{},
		statement: map[string]string{},
	}

	all := append([]federationNode{{name: "trust_anchor"}}, nodes...)
	for _, node := range all {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate key for %q: %v", node.name, err)
		}
		fed.keys[node.name] = key
		if node.extraECKey {
			extra, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to generate extra key for %q: %v", node.name, err)
			}
			fed.extra[node.name] = extra
		}
	}

	server := httptest.NewUnstartedServer(nil)
	base := fmt.Sprintf("https://%s", server.Listener.Addr().String())
	for _, node := range all {
		fed.id[node.name] = model.EntityIdentifier(fmt.Sprintf("%s/%s", base, node.name))
	}

	for _, node := range all {
		key := fed.keys[node.name]
		ecKeys := []any{federationPublicJwk(t, key.Public(), "test-key")}
		if extra, ok := fed.extra[node.name]; ok {
			ecKeys = append(ecKeys, federationPublicJwk(t, extra.Public(), "tm-key"))
		}

		body := map[string]any{
			"iss":      string(fed.id[node.name]),
			"sub":      string(fed.id[node.name]),
			"iat":      time.Now().UTC().Unix(),
			"exp":      time.Now().Add(time.Hour).UTC().Unix(),
			"jwks":     map[string]any{"keys": ecKeys},
			"metadata": map[string]any{},
		}
		if node.name == "trust_anchor" {
			body["metadata"] = map[string]any{
				"federation_entity": map[string]any{
					"federation_fetch_endpoint": fmt.Sprintf("%s/trust_anchor/fetch", base),
				},
			}
		} else {
			body["authority_hints"] = []string{string(fed.id["trust_anchor"])}
		}
		fed.wellKnown[node.name] = federationSign(t, key, "test-key", body)

		if node.name == "trust_anchor" || node.notSubordinate {
			continue
		}
		fed.statement[node.name] = federationSign(t, fed.keys["trust_anchor"], "test-key", map[string]any{
			"iss":  string(fed.id["trust_anchor"]),
			"sub":  string(fed.id[node.name]),
			"iat":  time.Now().UTC().Unix(),
			"exp":  time.Now().Add(time.Hour).UTC().Unix(),
			"jwks": map[string]any{"keys": []any{federationPublicJwk(t, fed.keys[node.name].Public(), "test-key")}},
		})
	}

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-federation") {
			node := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/.well-known/openid-federation")
			signed, ok := fed.wellKnown[node]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(signed)) //nolint:errcheck
			return
		}

		if r.URL.Path == "/trust_anchor/fetch" {
			subject := r.URL.Query().Get("sub")
			for node, id := range fed.id {
				if string(id) != subject {
					continue
				}
				signed, ok := fed.statement[node]
				if !ok {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				w.Write([]byte(signed)) //nolint:errcheck
				return
			}
			http.NotFound(w, r)
			return
		}

		http.NotFound(w, r)
	})
	server.StartTLS()
	t.Cleanup(server.Close)
	fed.server = server

	if server.URL != base {
		t.Fatalf("expected the served base URL to stay %q, got %q", base, server.URL)
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
	if key, ok := signer.(*rsa.PrivateKey); ok {
		return rawRSAToken(t, key, head, body)
	}
	token, err := jwt.New(signer, head, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to create trust mark: %v", err)
	}
	return *token
}

func TestFilterByTrusted_AppliesTrustMarkValidationRules(t *testing.T) {
	fed := newTrustMarkFederation(t,
		federationNode{name: "issuer", extraECKey: true},
		federationNode{name: "stranger", notSubordinate: true},
	)

	const (
		subject       = model.EntityIdentifier("https://subject.example.com")
		otherSubject  = "https://someone-else.example.com"
		accreditedTM  = "https://tm.example.com/accredited"
		unaccredited  = "https://tm.example.com/unaccredited"
		openTrustMark = "https://tm.example.com/open"
	)

	issuerKey, issuerID := fed.keys["issuer"], fed.id["issuer"]
	issuerTrustMarkKey := fed.extra["issuer"]
	strangerKey, strangerID := fed.keys["stranger"], fed.id["stranger"]
	anchorKey, anchorID := fed.keys["trust_anchor"], fed.id["trust_anchor"]

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
			name: "a key published only in the issuer's entity configuration is accepted",
			holder: model.TrustMarkHolder{
				TrustMarkType: accreditedTM,
				TrustMark:     federationTrustMark(t, issuerTrustMarkKey, "tm-key", string(issuerID), accreditedTM, string(subject)),
			},
			trustMarkType: accreditedTM,
			issuers:       []model.EntityIdentifier{issuerID},
			expectKept:    true,
		},
		{
			name: "an issuer with no subordinate statement from the trust anchor is dropped",
			holder: model.TrustMarkHolder{
				TrustMarkType: accreditedTM,
				TrustMark:     federationTrustMark(t, strangerKey, "test-key", string(strangerID), accreditedTM, string(subject)),
			},
			trustMarkType: accreditedTM,
			issuers:       []model.EntityIdentifier{strangerID},
			expectKept:    false,
		},
		{
			name: "the trust anchor may issue trust marks about a subject itself",
			holder: model.TrustMarkHolder{
				TrustMarkType: accreditedTM,
				TrustMark:     federationTrustMark(t, anchorKey, "test-key", string(anchorID), accreditedTM, string(subject)),
			},
			trustMarkType: accreditedTM,
			issuers:       []model.EntityIdentifier{anchorID},
			expectKept:    true,
		},
		{
			name: "an empty issuer list lets any federation member issue",
			holder: model.TrustMarkHolder{
				TrustMarkType: openTrustMark,
				TrustMark:     federationTrustMark(t, issuerKey, "test-key", string(issuerID), openTrustMark, string(subject)),
			},
			trustMarkType: openTrustMark,
			issuers:       []model.EntityIdentifier{},
			expectKept:    true,
		},
		{
			name: "an empty issuer list still requires federation membership",
			holder: model.TrustMarkHolder{
				TrustMarkType: openTrustMark,
				TrustMark:     federationTrustMark(t, strangerKey, "test-key", string(strangerID), openTrustMark, string(subject)),
			},
			trustMarkType: openTrustMark,
			issuers:       []model.EntityIdentifier{},
			expectKept:    false,
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolved := &model.ResolveResponse{
				Sub:        subject,
				Exp:        time.Now().Add(24 * time.Hour).UTC().Unix(),
				TrustMarks: []model.TrustMarkHolder{tc.holder},
			}
			trustAnchorConfiguration := model.EntityStatement{
				Sub:              anchorID,
				JWKs:             josemodel.Jwks{Keys: []map[string]any{federationPublicJwk(t, anchorKey.Public(), "test-key")}},
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

func TestFilterByTrusted_EstablishesTrustInEachIssuerOnce(t *testing.T) {
	fed := newTrustMarkFederation(t, federationNode{name: "issuer"})

	const (
		subject      = model.EntityIdentifier("https://subject.example.com")
		accreditedTM = "https://tm.employer.example/accredited"
	)

	issuerKey, issuerID := fed.keys["issuer"], fed.id["issuer"]

	var fetches int
	counting := fed.client()
	counting.Transport = &countingTransport{inner: counting.Transport, path: "/trust_anchor/fetch", count: &fetches}

	marks := make([]model.TrustMarkHolder, 0, 20)
	for range 20 {
		marks = append(marks, model.TrustMarkHolder{
			TrustMarkType: accreditedTM,
			TrustMark:     federationTrustMark(t, issuerKey, "test-key", string(issuerID), accreditedTM, string(subject)),
		})
	}

	resolved := &model.ResolveResponse{
		Sub:        subject,
		Exp:        time.Now().Add(24 * time.Hour).UTC().Unix(),
		TrustMarks: marks,
	}
	trustAnchorConfiguration := model.EntityStatement{
		Sub:              fed.id["trust_anchor"],
		TrustMarkIssuers: map[string][]model.EntityIdentifier{accreditedTM: {issuerID}},
	}

	cfg := model.Configuration{HttpClient: counting}
	if err := FilterByTrusted(t.Context(), cfg, resolved, trustAnchorConfiguration, nil); err != nil {
		t.Fatalf("expected no error from filtering, got %v", err)
	}

	if len(resolved.TrustMarks) != 20 {
		t.Fatalf("expected all 20 trust marks to be kept, got %d", len(resolved.TrustMarks))
	}
	if fetches != 1 {
		t.Errorf("expected one subordinate statement fetch for one issuer, got %d", fetches)
	}
}

func TestFilterByTrusted_RefusesMoreIssuersThanTheLimit(t *testing.T) {
	fed := newTrustMarkFederation(t, federationNode{name: "issuer"})

	const (
		subject       = model.EntityIdentifier("https://subject.example.com")
		openTrustMark = "https://tm.example.com/open"
	)

	tests := []struct {
		name      string
		issuers   int
		limit     int
		expectErr bool
	}{
		{name: "within the limit", issuers: 4, limit: 8, expectErr: false},
		{name: "exactly at the limit", issuers: 4, limit: 4, expectErr: false},
		{name: "beyond the limit", issuers: 5, limit: 4, expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var fetches int
			counting := fed.client()
			counting.Transport = &countingTransport{inner: counting.Transport, path: "/.well-known/openid-federation", count: &fetches}

			marks := make([]model.TrustMarkHolder, 0, tc.issuers)
			for i := range tc.issuers {
				marks = append(marks, model.TrustMarkHolder{
					TrustMarkType: openTrustMark,
					TrustMark:     federationTrustMark(t, fed.keys["issuer"], "test-key", fmt.Sprintf("https://attacker-%d.example.com", i), openTrustMark, string(subject)),
				})
			}

			resolved := &model.ResolveResponse{
				Sub:        subject,
				Exp:        time.Now().Add(24 * time.Hour).UTC().Unix(),
				TrustMarks: marks,
			}
			trustAnchorConfiguration := model.EntityStatement{
				Sub:              fed.id["trust_anchor"],
				TrustMarkIssuers: map[string][]model.EntityIdentifier{openTrustMark: {}},
			}

			cfg := model.Configuration{HttpClient: counting, MaxTrustMarkIssuers: tc.limit}
			err := FilterByTrusted(t.Context(), cfg, resolved, trustAnchorConfiguration, nil)

			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected the limit to be reported rather than marks silently dropped")
				}
				if !errors.Is(err, model.ErrInvalidSubject) {
					t.Errorf("[8.9] a subject presenting more issuers than this resolver will verify is a subject it cannot serve, not a fault of its own, got %v", err)
				}
				if errors.Is(err, model.ErrServerError) {
					t.Error("[8.9] a peer chooses how many trust marks to publish, so the refusal must not be a server_error")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if fetches > tc.limit {
				t.Errorf("expected at most %d issuer lookups, got %d", tc.limit, fetches)
			}
		})
	}
}

type countingTransport struct {
	inner http.RoundTripper
	path  string
	count *int
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, c.path) {
		*c.count++
	}
	return c.inner.RoundTrip(r)
}
