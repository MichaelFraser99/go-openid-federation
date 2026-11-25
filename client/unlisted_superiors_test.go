package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/server"
)

type unlistedNode struct {
	listener     *httptest.Server
	key          map[string]any
	intermediate *model.IntermediateConfiguration
}

type unlistedFederation struct {
	t        *testing.T
	nodes    map[string]*unlistedNode
	requests *atomic.Int64
}

func startUnlistedFederation(t *testing.T, hints map[string][]string, registers map[string][]string) *unlistedFederation {
	t.Helper()
	f := &unlistedFederation{t: t, nodes: map[string]*unlistedNode{}, requests: &atomic.Int64{}}
	muxes := map[string]*http.ServeMux{}
	for name := range hints {
		mux := http.NewServeMux()
		listener := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.requests.Add(1)
			mux.ServeHTTP(w, r)
		}))
		t.Cleanup(listener.Close)
		muxes[name] = mux
		f.nodes[name] = &unlistedNode{listener: listener}
	}
	for name, superiors := range hints {
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		key, err := jwk.PublicJwk(signer.Public())
		if err != nil {
			t.Fatalf("failed to read a public key: %v", err)
		}
		(*key)["kid"] = name
		node := f.nodes[name]
		node.key = *key
		if name != "wallet" {
			node.intermediate = &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute}
		}
		entity, err := server.NewServer(model.ServerConfiguration{
			Configuration:               model.Configuration{HttpClient: node.listener.Client()},
			SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: name},
			EntityIdentifier:            f.id(name),
			EntityConfigurationLifetime: 10 * time.Minute,
			AuthorityHints:              f.ids(superiors),
			EntityConfiguration:         model.EntityStatement{Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{"organization_name": name}}},
			IntermediateConfiguration:   node.intermediate,
		})
		if err != nil {
			t.Fatalf("failed to start %s: %v", name, err)
		}
		entity.Configure(muxes[name])
	}
	for superior, subjects := range registers {
		for _, subject := range subjects {
			f.register(superior, subject, f.nodes[subject].key)
		}
	}
	return f
}

func (f *unlistedFederation) register(superior, subject string, key map[string]any) {
	f.nodes[superior].intermediate.AddSubordinate(f.id(subject), &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{key}}})
}

func (f *unlistedFederation) id(name string) model.EntityIdentifier {
	return model.EntityIdentifier(f.nodes[name].listener.URL)
}

func (f *unlistedFederation) ids(names []string) []model.EntityIdentifier {
	identifiers := []model.EntityIdentifier{}
	for _, name := range names {
		identifiers = append(identifiers, f.id(name))
	}
	return identifiers
}

func (f *unlistedFederation) client(exempt map[string][]string) *Client {
	cfg := model.Configuration{HttpClient: f.nodes["ta"].listener.Client()}
	if exempt != nil {
		cfg.Experimental.UnlistedSuperiors = map[model.EntityIdentifier][]model.EntityIdentifier{}
		for entity, superiors := range exempt {
			cfg.Experimental.UnlistedSuperiors[f.id(entity)] = f.ids(superiors)
		}
	}
	return New(model.ClientConfiguration{Configuration: cfg})
}

func TestClient_BuildTrustChain_UnlistedSuperiors(t *testing.T) {
	tests := []struct {
		name      string
		hints     map[string][]string
		registers map[string][]string
		exempt    map[string][]string
		setup     func(f *unlistedFederation)
		issuers   []string
		err       error
	}{
		{
			name:      "configured: a wallet listing no superior, registered by the anchor",
			hints:     map[string][]string{"wallet": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			exempt:    map[string][]string{"wallet": {"ta"}},
			issuers:   []string{"ta"},
		},
		{
			name:      "not configured: a wallet listing no superior, registered by the anchor",
			hints:     map[string][]string{"wallet": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			err:       model.ErrInvalidTrustAnchor,
		},
		{
			name:      "configured: a wallet registered by an intermediate under the anchor",
			hints:     map[string][]string{"wallet": {}, "im": {"ta"}, "ta": {}},
			registers: map[string][]string{"im": {"wallet"}, "ta": {"im"}},
			exempt:    map[string][]string{"wallet": {"im"}},
			issuers:   []string{"im", "ta"},
		},
		{
			name:      "not configured: a wallet registered by an intermediate under the anchor",
			hints:     map[string][]string{"wallet": {}, "im": {"ta"}, "ta": {}},
			registers: map[string][]string{"im": {"wallet"}, "ta": {"im"}},
			err:       model.ErrInvalidTrustAnchor,
		},
		{
			name:      "configured: an exempt intermediate",
			hints:     map[string][]string{"wallet": {"im"}, "im": {}, "ta": {}},
			registers: map[string][]string{"im": {"wallet"}, "ta": {"im"}},
			exempt:    map[string][]string{"im": {"ta"}},
			issuers:   []string{"im", "ta"},
		},
		{
			name:      "configured with a superior that does not register the wallet",
			hints:     map[string][]string{"wallet": {}, "im": {"ta"}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet", "im"}},
			exempt:    map[string][]string{"wallet": {"im"}},
			err:       model.ErrInvalidTrustChain,
		},
		{
			name:      "configured, and the superior registers a key the wallet does not sign with",
			hints:     map[string][]string{"wallet": {}, "ta": {}},
			registers: map[string][]string{},
			exempt:    map[string][]string{"wallet": {"ta"}},
			setup: func(f *unlistedFederation) {
				other, err := jws.GetSigner(jwa.ES256, nil)
				if err != nil {
					f.t.Fatalf("failed to build a signer: %v", err)
				}
				key, err := jwk.PublicJwk(other.Public())
				if err != nil {
					f.t.Fatalf("failed to read a public key: %v", err)
				}
				(*key)["kid"] = "wallet"
				f.register("ta", "wallet", *key)
			},
			err: model.ErrInvalidTrustChain,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := startUnlistedFederation(t, tc.hints, tc.registers)
			if tc.setup != nil {
				tc.setup(f)
			}

			_, chain, _, err := f.client(tc.exempt).BuildTrustChain(t.Context(), string(f.id("wallet")), string(f.id("ta")))

			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("expected %v, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected a chain, got %v", err)
			}
			var issuers []model.EntityIdentifier
			for _, statement := range chain[1 : len(chain)-1] {
				issuers = append(issuers, statement.Iss)
			}
			if want := f.ids(tc.issuers); !slices.Equal(issuers, want) {
				t.Errorf("expected the statements issued by %v, got %v", want, issuers)
			}
		})
	}
}

func TestClient_ResolveMetadata_ASuppliedChainThroughAnUnlistedSuperior(t *testing.T) {
	tests := []struct {
		name   string
		exempt map[string][]string
		err    error
	}{
		{name: "the wallet is configured with the issuer of its statement", exempt: map[string][]string{"wallet": {"ta"}}},
		{name: "nothing is configured", err: model.ErrInvalidTrustChain},
		{name: "the wallet is configured with another superior", exempt: map[string][]string{"wallet": {"im"}}, err: model.ErrInvalidTrustChain},
		{name: "another entity is configured with the issuer", exempt: map[string][]string{"im": {"ta"}}, err: model.ErrInvalidTrustChain},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := startUnlistedFederation(t, map[string][]string{"wallet": {}, "im": {"ta"}, "ta": {}}, map[string][]string{"ta": {"wallet", "im"}})
			chain, _, _, err := f.client(map[string][]string{"wallet": {"ta"}}).BuildTrustChain(t.Context(), string(f.id("wallet")), string(f.id("ta")))
			if err != nil {
				t.Fatalf("failed to build the chain to supply: %v", err)
			}

			for _, supplied := range [][]string{chain, chain[:len(chain)-1]} {
				metadata, err := f.client(tc.exempt).ResolveMetadata(t.Context(), string(f.id("wallet")), string(f.id("ta")), supplied)
				if tc.err != nil {
					if !errors.Is(err, tc.err) || !strings.Contains(err.Error(), "authority_hints") {
						t.Errorf("[3.2] expected %v naming authority_hints for a chain of %d entries, got %v", tc.err, len(supplied), err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("expected a chain of %d entries to resolve, got %v", len(supplied), err)
				}
				if name := (*metadata.FederationMetadata)["organization_name"]; name != "wallet" {
					t.Errorf("expected the wallet's metadata, got %v", name)
				}
			}
		})
	}
}

func TestClient_AMalformedUnlistedSuperiorsConfigurationIsRefusedBeforeAnyRequest(t *testing.T) {
	calls := map[string]func(c *Client, f *unlistedFederation) error{
		"BuildTrustChain": func(c *Client, f *unlistedFederation) error {
			_, _, _, err := c.BuildTrustChain(t.Context(), string(f.id("wallet")), string(f.id("ta")))
			return err
		},
		"ResolveMetadata": func(c *Client, f *unlistedFederation) error {
			_, err := c.ResolveMetadata(t.Context(), string(f.id("wallet")), string(f.id("ta")), []string{"a.b.c", "a.b.c"})
			return err
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			f := startUnlistedFederation(t, map[string][]string{"wallet": {"ta"}, "ta": {}}, map[string][]string{"ta": {"wallet"}})
			c := f.client(map[string][]string{"wallet": {"wallet"}})
			f.requests.Store(0)

			err := call(c, f)

			if !errors.Is(err, model.ErrServerError) || !strings.Contains(err.Error(), "Experimental.UnlistedSuperiors") {
				t.Errorf("expected server_error naming Experimental.UnlistedSuperiors, got %v", err)
			}
			if sent := f.requests.Load(); sent != 0 {
				t.Errorf("expected no request before the configuration is refused, %d were sent", sent)
			}
		})
	}
}
