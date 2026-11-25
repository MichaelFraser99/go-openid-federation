package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const unlistedMarkType = "https://tm.example.com/unlisted"

type unlistedEntity struct {
	hints     []string
	registers []string
	marks     []string
}

type unlistedNode struct {
	listener *httptest.Server
	mux      *http.ServeMux
	signer   josemodel.Signer
	key      map[string]any
	server   *Server
}

type unlistedFederation struct {
	t     *testing.T
	nodes map[string]*unlistedNode
}

func newUnlistedFederation(t *testing.T, entities map[string]unlistedEntity) *unlistedFederation {
	t.Helper()
	f := &unlistedFederation{t: t, nodes: map[string]*unlistedNode{}}
	for name := range entities {
		mux := http.NewServeMux()
		listener := httptest.NewTLSServer(mux)
		t.Cleanup(listener.Close)
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		f.nodes[name] = &unlistedNode{listener: listener, mux: mux, signer: signer, key: f.publicKey(signer, name)}
	}
	return f
}

func (f *unlistedFederation) publicKey(signer josemodel.Signer, kid string) map[string]any {
	key, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		f.t.Fatalf("failed to read a public key: %v", err)
	}
	(*key)["kid"] = kid
	return *key
}

func (f *unlistedFederation) id(name string) model.EntityIdentifier {
	return model.EntityIdentifier(f.nodes[name].listener.URL)
}

func (f *unlistedFederation) ids(names []string) []model.EntityIdentifier {
	identifiers := make([]model.EntityIdentifier, 0, len(names))
	for _, name := range names {
		identifiers = append(identifiers, f.id(name))
	}
	return identifiers
}

func (f *unlistedFederation) configured(exempt map[string][]string) map[model.EntityIdentifier][]model.EntityIdentifier {
	if exempt == nil {
		return nil
	}
	configured := map[model.EntityIdentifier][]model.EntityIdentifier{}
	for entity, superiors := range exempt {
		configured[f.id(entity)] = f.ids(superiors)
	}
	return configured
}

func (f *unlistedFederation) trustMark(issuer, subject string) string {
	now := time.Now().UTC()
	token, err := jwt.New(f.nodes[issuer].signer, map[string]any{"kid": issuer, "typ": "trust-mark+jwt", "alg": "ES256"}, map[string]any{
		"iss": string(f.id(issuer)), "sub": string(f.id(subject)), "trust_mark_type": unlistedMarkType, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	}, jwt.Opts{Algorithm: jwa.ES256})
	if err != nil {
		f.t.Fatalf("failed to sign a trust mark: %v", err)
	}
	return *token
}

func (f *unlistedFederation) start(name string, entity unlistedEntity, cfg model.ServerConfiguration) *Server {
	f.t.Helper()
	node := f.nodes[name]
	cfg.SignerConfiguration = model.SignerConfiguration{Algorithm: "ES256", Signer: node.signer, KeyID: name}
	cfg.EntityIdentifier = f.id(name)
	cfg.HttpClient = node.listener.Client()
	cfg.EntityConfigurationLifetime = 10 * time.Minute
	cfg.AuthorityHints = f.ids(entity.hints)
	cfg.EntityConfiguration.Metadata = &model.Metadata{FederationMetadata: &model.FederationMetadata{"organization_name": name}}
	for _, issuer := range entity.marks {
		cfg.TrustMarks = append(cfg.TrustMarks, model.TrustMarkHolder{TrustMarkType: unlistedMarkType, TrustMark: f.trustMark(issuer, name)})
	}
	if name != "wallet" {
		if cfg.IntermediateConfiguration == nil {
			cfg.IntermediateConfiguration = &model.IntermediateConfiguration{}
		}
		cfg.IntermediateConfiguration.SubordinateStatementLifetime = 10 * time.Minute
	}
	server := mustNewServer(f.t, cfg)
	server.Configure(node.mux)
	node.server = server
	return server
}

func (f *unlistedFederation) register(superior, subject string, registration *model.SubordinateConfiguration) {
	if registration == nil {
		registration = &model.SubordinateConfiguration{}
	}
	if len(registration.JWKs.Keys) == 0 {
		registration.JWKs = josemodel.Jwks{Keys: []map[string]any{f.nodes[subject].key}}
	}
	f.nodes[superior].server.cfg.IntermediateConfiguration.AddSubordinate(f.id(subject), registration)
}

func startUnlistedFederation(t *testing.T, entities map[string]unlistedEntity, exempt map[string][]string, anchor model.ServerConfiguration) *unlistedFederation {
	t.Helper()
	f := newUnlistedFederation(t, entities)
	anchor.Experimental.UnlistedSuperiors = f.configured(exempt)
	for name, entity := range entities {
		cfg := model.ServerConfiguration{}
		if name == "ta" {
			cfg = anchor
			cfg.EntityConfiguration.TrustMarkIssuers = map[string][]model.EntityIdentifier{}
			for _, holder := range entities {
				for _, issuer := range holder.marks {
					cfg.EntityConfiguration.TrustMarkIssuers[unlistedMarkType] = append(cfg.EntityConfiguration.TrustMarkIssuers[unlistedMarkType], f.id(issuer))
				}
			}
		}
		f.start(name, entity, cfg)
	}
	for name, entity := range entities {
		for _, subject := range entity.registers {
			f.register(name, subject, nil)
		}
	}
	return f
}

func (f *unlistedFederation) get(path string) (int, string) {
	f.t.Helper()
	response, err := f.nodes["ta"].listener.Client().Get(string(f.id("ta")) + path)
	if err != nil {
		f.t.Fatalf("request failed: %v", err)
	}
	return readUnlisted(f.t, response)
}

func readUnlisted(t *testing.T, response *http.Response) (int, string) {
	t.Helper()
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the response: %v", err)
	}
	return response.StatusCode, string(raw)
}

func unlistedClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode the payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("failed to parse the payload: %v", err)
	}
	return claims
}

func (f *unlistedFederation) resolve(subject string) (int, map[string]any) {
	f.t.Helper()
	status, body := f.get("/resolve?sub=" + url.QueryEscape(string(f.id(subject))) + "&trust_anchor=" + url.QueryEscape(string(f.id("ta"))))
	if status != http.StatusOK {
		var refusal map[string]any
		_ = json.Unmarshal([]byte(body), &refusal)
		return status, refusal
	}
	return status, unlistedClaims(f.t, body)
}

func TestServer_Resolve_UnlistedSuperiors(t *testing.T) {
	type outcome struct {
		status       int
		organization string
		marks        int
	}
	refused := outcome{status: http.StatusNotFound}

	tests := []struct {
		name     string
		entities map[string]unlistedEntity
		exempt   map[string][]string
		setup    func(f *unlistedFederation)
		subject  string
		on, off  outcome
	}{
		{
			name:     "a wallet listing no superior, registered by the anchor directly",
			entities: map[string]unlistedEntity{"wallet": {}, "ta": {registers: []string{"wallet"}}},
			exempt:   map[string][]string{"wallet": {"ta"}},
			on:       outcome{status: http.StatusOK, organization: "wallet"},
			off:      refused,
		},
		{
			name:     "a wallet listing another ecosystem's anchor, registered by this anchor directly",
			entities: map[string]unlistedEntity{"wallet": {hints: []string{"eco"}}, "eco": {registers: []string{"wallet"}}, "ta": {registers: []string{"wallet"}}},
			exempt:   map[string][]string{"wallet": {"ta"}},
			on:       outcome{status: http.StatusOK, organization: "wallet"},
			off:      refused,
		},
		{
			name:     "a wallet registered by an intermediate under the anchor",
			entities: map[string]unlistedEntity{"wallet": {}, "im": {hints: []string{"ta"}, registers: []string{"wallet"}}, "ta": {registers: []string{"im"}}},
			exempt:   map[string][]string{"wallet": {"im"}},
			on:       outcome{status: http.StatusOK, organization: "wallet"},
			off:      refused,
		},
		{
			name:     "two configured superiors where only the second registers the wallet",
			entities: map[string]unlistedEntity{"wallet": {}, "x": {hints: []string{"ta"}}, "im": {hints: []string{"ta"}, registers: []string{"wallet"}}, "ta": {registers: []string{"x", "im"}}},
			exempt:   map[string][]string{"wallet": {"x", "im"}},
			on:       outcome{status: http.StatusOK, organization: "wallet"},
			off:      refused,
		},
		{
			name:     "an exempt intermediate the wallet lists, registered by the anchor without listing it",
			entities: map[string]unlistedEntity{"wallet": {hints: []string{"im"}}, "im": {registers: []string{"wallet"}}, "ta": {registers: []string{"im"}}},
			exempt:   map[string][]string{"im": {"ta"}},
			on:       outcome{status: http.StatusOK, organization: "wallet"},
			off:      refused,
		},
		{
			name:     "the same topology for an entity that is not configured",
			entities: map[string]unlistedEntity{"wallet": {}, "other": {}, "ta": {registers: []string{"wallet", "other"}}},
			exempt:   map[string][]string{"other": {"ta"}},
			on:       refused,
			off:      refused,
		},
		{
			name:     "a configured wallet whose only registering superior is not in its configured list",
			entities: map[string]unlistedEntity{"wallet": {}, "im": {hints: []string{"ta"}}, "ta": {registers: []string{"wallet", "im"}}},
			exempt:   map[string][]string{"wallet": {"im"}},
			on:       outcome{status: http.StatusBadRequest},
			off:      refused,
		},
		{
			name:     "a rogue superior outside the configured list registers the wallet with metadata of its own",
			entities: map[string]unlistedEntity{"wallet": {}, "rogue": {hints: []string{"ta"}}, "ta": {registers: []string{"wallet", "rogue"}}},
			exempt:   map[string][]string{"wallet": {"ta"}},
			setup: func(f *unlistedFederation) {
				f.register("rogue", "wallet", &model.SubordinateConfiguration{Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{"organization_name": "rogue"}}})
			},
			on:  outcome{status: http.StatusOK, organization: "wallet"},
			off: refused,
		},
		{
			name:     "a rogue superior outside the configured list is the only one registering the wallet",
			entities: map[string]unlistedEntity{"wallet": {}, "rogue": {hints: []string{"ta"}}, "ta": {registers: []string{"rogue"}}},
			exempt:   map[string][]string{"wallet": {"ta"}},
			setup: func(f *unlistedFederation) {
				f.register("rogue", "wallet", &model.SubordinateConfiguration{Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{"organization_name": "rogue"}}})
			},
			on:  outcome{status: http.StatusBadRequest},
			off: refused,
		},
		{
			name:     "the configured superior registers a key the wallet does not sign with",
			entities: map[string]unlistedEntity{"wallet": {}, "ta": {}},
			exempt:   map[string][]string{"wallet": {"ta"}},
			setup: func(f *unlistedFederation) {
				other, err := jws.GetSigner(jwa.ES256, nil)
				if err != nil {
					f.t.Fatalf("failed to build a signer: %v", err)
				}
				f.register("ta", "wallet", &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{f.publicKey(other, "wallet")}}})
			},
			on:  outcome{status: http.StatusBadRequest},
			off: refused,
		},
		{
			name:     "a trust mark issuer that lists no superior, registered by the anchor directly",
			entities: map[string]unlistedEntity{"wallet": {hints: []string{"ta"}, marks: []string{"issuer"}}, "issuer": {hints: []string{}}, "ta": {registers: []string{"wallet", "issuer"}}},
			exempt:   map[string][]string{"issuer": {"ta"}},
			on:       outcome{status: http.StatusOK, organization: "wallet", marks: 1},
			off:      outcome{status: http.StatusOK, organization: "wallet"},
		},
	}

	for _, tc := range tests {
		for _, mode := range []string{"on", "off"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				exempt, want := map[string][]string(nil), tc.off
				if mode == "on" {
					exempt, want = tc.exempt, tc.on
				}
				f := startUnlistedFederation(t, tc.entities, exempt, model.ServerConfiguration{})
				if tc.setup != nil {
					tc.setup(f)
				}

				status, body := f.resolve("wallet")

				if status != want.status {
					t.Fatalf("expected %d, got %d %v", want.status, status, body)
				}
				if status != http.StatusOK {
					return
				}
				federation, _ := body["metadata"].(map[string]any)["federation_entity"].(map[string]any)
				if federation["organization_name"] != want.organization {
					t.Errorf("expected the wallet's own organization_name %q, got %v", want.organization, federation["organization_name"])
				}
				marks, _ := body["trust_marks"].([]any)
				if len(marks) != want.marks {
					t.Errorf("expected %d trust marks, got %d", want.marks, len(marks))
				}
			})
		}
	}
}

type unlistedListing struct{ subjects []model.EntityIdentifier }

func (l unlistedListing) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	entries := make([]map[string]any, 0, len(l.subjects))
	for _, subject := range l.subjects {
		entries = append(entries, map[string]any{"id": string(subject)})
	}
	return &model.ExtendedListingResponse{ImmediateSubordinateEntities: entries}, nil
}

func (l unlistedListing) GetSubordinateStatus(_ context.Context, subject model.EntityIdentifier) (*model.SubordinateStatusResponse, error) {
	if !slices.Contains(l.subjects, subject) {
		return nil, model.NewNotFoundError("unknown entity identifier")
	}
	return &model.SubordinateStatusResponse{Events: []model.SubordinateStatusEvent{}}, nil
}

type unlistedMarks struct {
	f       *unlistedFederation
	subject model.EntityIdentifier
}

func (m unlistedMarks) GetTrustMarkStatus(context.Context, string) (*string, error) {
	status := "active"
	return &status, nil
}

func (m unlistedMarks) IssueTrustMark(_ context.Context, trustMarkType string, subject model.EntityIdentifier) (*string, error) {
	if trustMarkType != unlistedMarkType || subject != m.subject {
		return nil, model.NewNotFoundError("unknown trust mark")
	}
	mark := m.f.trustMark("ta", "wallet")
	return &mark, nil
}

func (m unlistedMarks) ListTrustMarks(context.Context, string, *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	return []model.EntityIdentifier{m.subject}, nil
}

func TestServer_EveryEndpointServesAnExemptSubordinate(t *testing.T) {
	entities := map[string]unlistedEntity{"wallet": {}, "ta": {registers: []string{"wallet"}}}

	tests := []struct {
		name   string
		call   func(f *unlistedFederation) (int, string)
		status map[string]int
		check  func(t *testing.T, f *unlistedFederation, body string)
	}{
		{
			name:   "/.well-known/openid-federation of the anchor",
			call:   func(f *unlistedFederation) (int, string) { return f.get("/.well-known/openid-federation") },
			status: map[string]int{"on": http.StatusOK, "off": http.StatusOK},
			check: func(t *testing.T, f *unlistedFederation, body string) {
				if claims := unlistedClaims(t, body); claims["sub"] != string(f.id("ta")) || claims["authority_hints"] != nil {
					t.Errorf("expected the anchor's own entity configuration, got %v", claims)
				}
			},
		},
		{
			name: "/.well-known/openid-federation of the wallet",
			call: func(f *unlistedFederation) (int, string) {
				response, err := f.nodes["wallet"].listener.Client().Get(string(f.id("wallet")) + "/.well-known/openid-federation")
				if err != nil {
					f.t.Fatalf("request failed: %v", err)
				}
				return readUnlisted(f.t, response)
			},
			status: map[string]int{"on": http.StatusOK, "off": http.StatusOK},
			check: func(t *testing.T, f *unlistedFederation, body string) {
				if claims := unlistedClaims(t, body); claims["sub"] != string(f.id("wallet")) || claims["authority_hints"] != nil {
					t.Errorf("expected the wallet's entity configuration with no authority_hints, got %v", claims)
				}
			},
		},
		{
			name: "/fetch",
			call: func(f *unlistedFederation) (int, string) {
				return f.get("/fetch?sub=" + url.QueryEscape(string(f.id("wallet"))))
			},
			status: map[string]int{"on": http.StatusOK, "off": http.StatusOK},
			check: func(t *testing.T, f *unlistedFederation, body string) {
				if claims := unlistedClaims(t, body); claims["iss"] != string(f.id("ta")) || claims["sub"] != string(f.id("wallet")) {
					t.Errorf("expected the anchor's statement about the wallet, got %v", claims)
				}
			},
		},
		{
			name:   "/list",
			call:   func(f *unlistedFederation) (int, string) { return f.get("/list") },
			status: map[string]int{"on": http.StatusOK, "off": http.StatusOK},
			check: func(t *testing.T, f *unlistedFederation, body string) {
				var listed []string
				if err := json.Unmarshal([]byte(body), &listed); err != nil || !slices.Equal(listed, []string{string(f.id("wallet"))}) {
					t.Errorf("expected the wallet listed, got %s", body)
				}
			},
		},
		{
			name:   "/extended-list",
			call:   func(f *unlistedFederation) (int, string) { return f.get("/extended-list") },
			status: map[string]int{"on": http.StatusOK, "off": http.StatusOK},
			check: func(t *testing.T, f *unlistedFederation, body string) {
				var listed model.ExtendedListingResponse
				if err := json.Unmarshal([]byte(body), &listed); err != nil || len(listed.ImmediateSubordinateEntities) != 1 || listed.ImmediateSubordinateEntities[0]["id"] != string(f.id("wallet")) {
					t.Errorf("expected the wallet listed, got %s", body)
				}
			},
		},
		{
			name: "/subordinate-status",
			call: func(f *unlistedFederation) (int, string) {
				return f.get("/subordinate-status?sub=" + url.QueryEscape(string(f.id("wallet"))))
			},
			status: map[string]int{"on": http.StatusOK, "off": http.StatusOK},
			check: func(t *testing.T, f *unlistedFederation, body string) {
				if claims := unlistedClaims(t, body); claims["sub"] != string(f.id("wallet")) {
					t.Errorf("expected a status about the wallet, got %v", claims)
				}
			},
		},
		{
			name: "/trust-mark",
			call: func(f *unlistedFederation) (int, string) {
				return f.get("/trust-mark?trust_mark_type=" + url.QueryEscape(unlistedMarkType) + "&sub=" + url.QueryEscape(string(f.id("wallet"))))
			},
			status: map[string]int{"on": http.StatusOK, "off": http.StatusOK},
			check: func(t *testing.T, f *unlistedFederation, body string) {
				if claims := unlistedClaims(t, body); claims["sub"] != string(f.id("wallet")) {
					t.Errorf("expected a trust mark about the wallet, got %v", claims)
				}
			},
		},
		{
			name: "/trust-mark-list",
			call: func(f *unlistedFederation) (int, string) {
				return f.get("/trust-mark-list?trust_mark_type=" + url.QueryEscape(unlistedMarkType))
			},
			status: map[string]int{"on": http.StatusOK, "off": http.StatusOK},
			check: func(t *testing.T, f *unlistedFederation, body string) {
				var listed []string
				if err := json.Unmarshal([]byte(body), &listed); err != nil || !slices.Equal(listed, []string{string(f.id("wallet"))}) {
					t.Errorf("expected the wallet listed, got %s", body)
				}
			},
		},
		{
			name: "/trust-mark-status",
			call: func(f *unlistedFederation) (int, string) {
				response, err := f.nodes["ta"].listener.Client().PostForm(string(f.id("ta"))+"/trust-mark-status", url.Values{"trust_mark": {f.trustMark("ta", "wallet")}})
				if err != nil {
					f.t.Fatalf("request failed: %v", err)
				}
				return readUnlisted(f.t, response)
			},
			status: map[string]int{"on": http.StatusOK, "off": http.StatusOK},
			check: func(t *testing.T, f *unlistedFederation, body string) {
				if claims := unlistedClaims(t, body); claims["status"] != "active" {
					t.Errorf("expected the mark active, got %v", claims)
				}
			},
		},
		{
			name: "/resolve",
			call: func(f *unlistedFederation) (int, string) {
				return f.get("/resolve?sub=" + url.QueryEscape(string(f.id("wallet"))) + "&trust_anchor=" + url.QueryEscape(string(f.id("ta"))))
			},
			status: map[string]int{"on": http.StatusOK, "off": http.StatusNotFound},
			check: func(t *testing.T, f *unlistedFederation, body string) {
				if claims := unlistedClaims(t, body); claims["sub"] != string(f.id("wallet")) {
					t.Errorf("expected the wallet resolved, got %v", claims)
				}
			},
		},
	}

	for _, tc := range tests {
		for _, mode := range []string{"on", "off"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				var exempt map[string][]string
				if mode == "on" {
					exempt = map[string][]string{"wallet": {"ta"}}
				}
				f := newUnlistedFederation(t, entities)
				wallet := f.id("wallet")
				anchor := model.ServerConfiguration{
					Extensions: model.Extensions{
						ExtendedListing:   model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: unlistedListing{subjects: []model.EntityIdentifier{wallet}}},
						SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: unlistedListing{subjects: []model.EntityIdentifier{wallet}}},
					},
					TrustMarkRetriever: unlistedMarks{f: f, subject: wallet},
				}
				anchor.Experimental.UnlistedSuperiors = f.configured(exempt)
				f.start("wallet", entities["wallet"], model.ServerConfiguration{})
				f.start("ta", entities["ta"], anchor)
				f.register("ta", "wallet", nil)

				status, body := tc.call(f)

				if status != tc.status[mode] {
					t.Fatalf("expected %d, got %d %s", tc.status[mode], status, body)
				}
				if status == http.StatusOK {
					tc.check(t, f, body)
				}
			})
		}
	}
}
