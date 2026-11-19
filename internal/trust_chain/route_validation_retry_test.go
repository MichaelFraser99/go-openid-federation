package trust_chain

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type routeFederation struct {
	t              *testing.T
	base           string
	client         *http.Client
	key            *rsa.PrivateKey
	rogue          *rsa.PrivateKey
	hints          map[string][]string
	claims         map[string]map[string]any
	rogueSigned    map[string]bool
	publishesRogue map[string]bool
	mu             sync.Mutex
	asked          map[string]int
}

func newRouteFederation(t *testing.T, key, rogue *rsa.PrivateKey, hints map[string][]string) *routeFederation {
	t.Helper()
	federation := &routeFederation{
		t:              t,
		key:            key,
		rogue:          rogue,
		hints:          hints,
		claims:         map[string]map[string]any{},
		rogueSigned:    map[string]bool{},
		publishesRogue: map[string]bool{},
		asked:          map[string]int{},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(federation.serve))
	t.Cleanup(srv.Close)
	federation.client = srv.Client()
	federation.base = srv.URL
	return federation
}

func (f *routeFederation) entity(name string) model.EntityIdentifier {
	return model.EntityIdentifier(f.base + "/" + name)
}

func (f *routeFederation) bothKeys() map[string]any {
	rogue, err := jwk.PublicJwk(f.rogue.Public())
	if err != nil {
		f.t.Fatalf("failed to create the rogue jwk: %v", err)
	}
	(*rogue)["kid"] = "rogue"
	keys := chainJwks(f.t, f.key)
	keys["keys"] = append(keys["keys"].([]any), *rogue)
	return keys
}

func (f *routeFederation) timesAsked(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asked[name]
}

func (f *routeFederation) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	now := time.Now().UTC()
	statement := map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": chainJwks(f.t, f.key)}
	var name string
	if node, wellKnown := strings.CutSuffix(path, "/.well-known/openid-federation"); wellKnown && f.hints[node] != nil {
		name = node
		statement["iss"], statement["sub"] = string(f.entity(node)), string(f.entity(node))
		statement["metadata"] = map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": string(f.entity(node)) + "/fetch"}}
		if hints := f.hints[node]; len(hints) > 0 {
			listed := make([]any, 0, len(hints))
			for _, hint := range hints {
				listed = append(listed, string(f.entity(hint)))
			}
			statement["authority_hints"] = listed
		}
		if f.publishesRogue[node] {
			statement["jwks"] = f.bothKeys()
		}
	} else if node, fetch := strings.CutSuffix(path, "/fetch"); fetch && f.hints[node] != nil {
		subject := strings.TrimPrefix(r.URL.Query().Get("sub"), f.base+"/")
		if !slices.Contains(f.hints[subject], node) {
			http.NotFound(w, r)
			return
		}
		name = node + ">" + subject
		statement["iss"], statement["sub"] = string(f.entity(node)), string(f.entity(subject))
	} else {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	f.asked[name]++
	f.mu.Unlock()
	for claim, value := range f.claims[name] {
		statement[claim] = value
	}
	signer, kid := f.key, "chain-key"
	if f.rogueSigned[name] {
		signer, kid = f.rogue, "rogue"
	}
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	_, _ = w.Write([]byte(chainSignStatementWithKid(f.t, signer, kid, statement)))
}

func expiringInsideTheLeeway() map[string]any {
	return expiringAt(time.Now().UTC().Add(-5 * time.Second).Unix())
}

func expiringAt(exp int64) map[string]any {
	return map[string]any{"iat": exp - 300, "exp": exp}
}

func excludingEveryAddress() map[string]any {
	return map[string]any{"constraints": map[string]any{"naming_constraints": map[string]any{"excluded": []any{".elsewhere.example"}}}}
}

func noIntermediatesBelow() map[string]any {
	return atMostIntermediatesBelow(0)
}

func atMostIntermediatesBelow(limit int) map[string]any {
	return map[string]any{"constraints": map[string]any{"max_path_length": limit}}
}

func (f *routeFederation) rogueKeyOnly() map[string]any {
	rogue, err := jwk.PublicJwk(f.rogue.Public())
	if err != nil {
		f.t.Fatalf("failed to create the rogue jwk: %v", err)
	}
	(*rogue)["kid"] = "chain-key"
	return map[string]any{"keys": []any{*rogue}}
}

func TestBuildTrustChain_ARouteThatFailsValidationGivesWayToAnother(t *testing.T) {
	key, rogue := chainSigningKey(t), chainSigningKey(t)
	twoRoutes := map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}}
	sharedIntermediate := map[string][]string{"leaf": {"m"}, "m": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}}

	tests := []struct {
		name      string
		reference string
		hints     map[string][]string
		setup     func(f *routeFederation)
		via       string
		avoids    string
		refused   string
	}{
		{
			name:      "the anchor's statement about the first hint sets a naming constraint the subject is outside",
			reference: "6.2.2",
			hints:     twoRoutes,
			setup:     func(f *routeFederation) { f.claims["ta>a"] = excludingEveryAddress() },
			via:       "b",
		},
		{
			name:      "the anchor's statement about the first hint allows no intermediate below it",
			reference: "6.2.1",
			hints:     twoRoutes,
			setup:     func(f *routeFederation) { f.claims["ta>a"] = noIntermediatesBelow() },
			via:       "b",
		},
		{
			name:      "the first hint's statement about the subject sets a naming constraint the subject is outside",
			reference: "6.2.2",
			hints:     twoRoutes,
			setup:     func(f *routeFederation) { f.claims["a>leaf"] = excludingEveryAddress() },
			via:       "b",
		},
		{
			name:      "the first hint signs its statement about the subject with a key its superior does not register for it",
			reference: "10.2",
			hints:     twoRoutes,
			setup: func(f *routeFederation) {
				f.publishesRogue["a"] = true
				f.rogueSigned["a>leaf"] = true
			},
			via: "b",
		},
		{
			name:      "the subject signs its entity configuration with a key only the second hint registers",
			reference: "10.2",
			hints:     twoRoutes,
			setup: func(f *routeFederation) {
				f.publishesRogue["leaf"] = true
				f.rogueSigned["leaf"] = true
				f.claims["b>leaf"] = map[string]any{"jwks": f.bothKeys()}
			},
			via: "b",
		},
		{
			name:      "the first hint's statement about the subject expires inside the clock skew leeway",
			reference: "10.2",
			hints:     twoRoutes,
			setup:     func(f *routeFederation) { f.claims["a>leaf"] = expiringInsideTheLeeway() },
			via:       "b",
		},
		{
			name:      "the first hint's entity configuration expires inside the clock skew leeway",
			reference: "10.2",
			hints:     twoRoutes,
			setup:     func(f *routeFederation) { f.claims["a"] = expiringInsideTheLeeway() },
			via:       "b",
		},
		{
			name:      "the anchor's statement about one of an intermediate's superiors expires inside the clock skew leeway",
			reference: "10.2",
			hints:     sharedIntermediate,
			setup:     func(f *routeFederation) { f.claims["ta>a"] = expiringInsideTheLeeway() },
			via:       "b",
		},
		{
			name:      "an intermediate signs its statement about one subordinate with a key its superior does not register",
			reference: "10.2",
			hints:     map[string][]string{"leaf": {"m1", "m2"}, "m1": {"x"}, "m2": {"x"}, "x": {"ta"}, "ta": {}},
			setup: func(f *routeFederation) {
				f.publishesRogue["x"] = true
				f.rogueSigned["x>m1"] = true
			},
			via: "m2",
		},
		{
			name:      "the subject's only superior has one superior whose statement about it is signed with a key the anchor does not register",
			reference: "10.2",
			hints:     map[string][]string{"leaf": {"m"}, "m": {"x", "y"}, "x": {"ta"}, "y": {"ta"}, "ta": {}},
			setup: func(f *routeFederation) {
				f.publishesRogue["x"] = true
				f.rogueSigned["x>m"] = true
			},
			via: "y",
		},
		{
			name:      "the anchor's statement about an intermediate two levels up allows no intermediates below it, and the intermediate has another superior",
			reference: "6.2.1",
			hints:     map[string][]string{"leaf": {"m"}, "m": {"a"}, "a": {"ta", "c"}, "c": {"ta"}, "ta": {}},
			setup:     func(f *routeFederation) { f.claims["ta>a"] = noIntermediatesBelow() },
			via:       "c",
		},
		{
			name:      "the anchor's statement about an intermediate two levels up sets a naming constraint, and the intermediate has another superior",
			reference: "6.2.2",
			hints:     map[string][]string{"leaf": {"m"}, "m": {"a"}, "a": {"ta", "c"}, "c": {"ta"}, "ta": {}},
			setup:     func(f *routeFederation) { f.claims["ta>a"] = excludingEveryAddress() },
			via:       "c",
		},
		{
			name:      "the first hint registers a key for the subject that the subject does not sign with, and the second hint reaches the anchor through the first",
			reference: "10.2",
			hints:     map[string][]string{"leaf": {"a", "b"}, "b": {"a"}, "a": {"ta"}, "ta": {}},
			setup:     func(f *routeFederation) { f.claims["a>leaf"] = map[string]any{"jwks": f.rogueKeyOnly()} },
			via:       "b",
		},
		{
			name:      "an intermediate signs its statement about the subject's superior with a key only its second superior registers",
			reference: "10.2",
			hints:     map[string][]string{"leaf": {"m"}, "m": {"x"}, "x": {"p", "q"}, "p": {"ta"}, "q": {"ta"}, "ta": {}},
			setup: func(f *routeFederation) {
				f.publishesRogue["x"] = true
				f.rogueSigned["x>m"] = true
				f.claims["q>x"] = map[string]any{"jwks": f.bothKeys()}
			},
			via:    "q",
			avoids: "p",
		},
		{
			name:      "an intermediate signs its statement about the subject with a key only its second superior registers",
			reference: "10.2",
			hints:     map[string][]string{"leaf": {"x"}, "x": {"p", "q"}, "p": {"ta"}, "q": {"ta"}, "ta": {}},
			setup: func(f *routeFederation) {
				f.publishesRogue["x"] = true
				f.rogueSigned["x>leaf"] = true
				f.claims["q>x"] = map[string]any{"jwks": f.bothKeys()}
			},
			via:    "q",
			avoids: "p",
		},
		{
			name:      "the anchor's statement about an intermediate allows one intermediate below it, and the subject also reaches that intermediate directly",
			reference: "6.2.1",
			hints:     map[string][]string{"leaf": {"m", "a"}, "m": {"a"}, "a": {"ta"}, "ta": {}},
			setup:     func(f *routeFederation) { f.claims["ta>a"] = atMostIntermediatesBelow(1) },
			via:       "a",
			avoids:    "m",
		},
		{
			name:      "the anchor's statement about an intermediate allows two intermediates below it, and a shorter route shares every link above the subject's first superior",
			reference: "6.2.1",
			hints:     map[string][]string{"leaf": {"x", "m"}, "x": {"m"}, "m": {"a"}, "a": {"ta"}, "ta": {}},
			setup:     func(f *routeFederation) { f.claims["ta>a"] = atMostIntermediatesBelow(2) },
			via:       "m",
			avoids:    "x",
		},
		{
			name:      "the only route's intermediate signs its statement about the subject's superior with a key its superior does not register",
			reference: "10.2",
			hints:     map[string][]string{"leaf": {"m"}, "m": {"x"}, "x": {"p"}, "p": {"ta"}, "ta": {}},
			setup: func(f *routeFederation) {
				f.publishesRogue["x"] = true
				f.rogueSigned["x>m"] = true
			},
			refused: "entry 2 in the trust chain is not signed by a key published for it in the statement above it",
		},
		{
			name:      "every route through the anchor's statement about an intermediate has more intermediates than it allows",
			reference: "6.2.1",
			hints:     map[string][]string{"leaf": {"x", "m"}, "x": {"m"}, "m": {"a"}, "a": {"ta"}, "ta": {}},
			setup:     func(f *routeFederation) { f.claims["ta>a"] = atMostIntermediatesBelow(1) },
			refused:   "allows at most 1 intermediates below it",
		},
		{
			name:      "the anchor's statement about the first hint sets a naming constraint the subject is outside and a max_path_length the route meets",
			reference: "6.2.2",
			hints:     twoRoutes,
			setup: func(f *routeFederation) {
				f.claims["ta>a"] = map[string]any{"constraints": map[string]any{"max_path_length": 1, "naming_constraints": map[string]any{"excluded": []any{".elsewhere.example"}}}}
			},
			via: "b",
		},
		{
			name:      "the only route sets a naming constraint the subject is outside",
			reference: "6.2.2",
			hints:     map[string][]string{"leaf": {"a"}, "a": {"ta"}, "ta": {}},
			setup:     func(f *routeFederation) { f.claims["ta>a"] = excludingEveryAddress() },
			refused:   "is outside the naming constraints set by",
		},
		{
			name:      "every route allows no intermediate below the anchor's statement",
			reference: "6.2.1",
			hints:     twoRoutes,
			setup: func(f *routeFederation) {
				f.claims["ta>a"] = noIntermediatesBelow()
				f.claims["ta>b"] = noIntermediatesBelow()
			},
			refused: "allows at most 0 intermediates below it",
		},
		{
			name:      "the only route's link is signed with a key its superior does not register",
			reference: "10.2",
			hints:     map[string][]string{"leaf": {"a"}, "a": {"ta"}, "ta": {}},
			setup: func(f *routeFederation) {
				f.publishesRogue["a"] = true
				f.rogueSigned["a>leaf"] = true
			},
			refused: "entry 1 in the trust chain is not signed by a key published for it in the statement above it",
		},
		{
			name:      "the only route's statement expires inside the clock skew leeway",
			reference: "10.2",
			hints:     map[string][]string{"leaf": {"a"}, "a": {"ta"}, "ta": {}},
			setup:     func(f *routeFederation) { f.claims["a>leaf"] = expiringInsideTheLeeway() },
			refused:   "trust chain expiry is not in the future",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteFederation(t, key, rogue, tc.hints)
			tc.setup(f)

			_, parsed, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: f.client}, f.entity("leaf"), f.entity("ta"), resolvecache.New())
			if tc.refused != "" {
				if !errors.Is(err, model.ErrInvalidTrustChain) || !strings.Contains(err.Error(), tc.refused) {
					t.Errorf("[%s] with no valid route left, the first route's own failure is the answer, expected invalid_trust_chain naming %q, got %v", tc.reference, tc.refused, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s, 10.3] a route that fails validation must give way to another route that is valid, got %v", tc.reference, err)
			}
			through := false
			for _, statement := range parsed[1 : len(parsed)-1] {
				if statement.Iss == f.entity(tc.via) || statement.Sub == f.entity(tc.via) {
					through = true
				}
			}
			if !through {
				t.Errorf("[%s] expected the chain to pass through %s", tc.reference, tc.via)
			}
			for _, statement := range parsed {
				if tc.avoids != "" && (statement.Iss == f.entity(tc.avoids) || statement.Sub == f.entity(tc.avoids)) {
					t.Errorf("[%s] expected the chain to avoid %s, which only a route that fails validation passes through", tc.reference, tc.avoids)
				}
			}
		})
	}
}

func TestBuildTrustChain_AFailureNoOtherRouteCanAvoidEndsTheWalk(t *testing.T) {
	key, rogue := chainSigningKey(t), chainSigningKey(t)
	twoRoutes := map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}}

	tests := []struct {
		name      string
		reference string
		setup     func(f *routeFederation)
		anchors   func(f *routeFederation) map[model.EntityIdentifier]josemodel.Jwks
		want      error
	}{
		{
			name:      "the subject's own entity configuration expires inside the clock skew leeway",
			reference: "10.2",
			setup:     func(f *routeFederation) { f.claims["leaf"] = expiringInsideTheLeeway() },
			want:      model.ErrInvalidTrustChain,
		},
		{
			name:      "the anchor's entity configuration expires inside the clock skew leeway",
			reference: "10.2",
			setup:     func(f *routeFederation) { f.claims["ta"] = expiringInsideTheLeeway() },
			want:      model.ErrInvalidTrustChain,
		},
		{
			name:      "the subject's own entity configuration expires inside the clock skew leeway at the same second as the first hint's",
			reference: "10.2",
			setup: func(f *routeFederation) {
				exp := time.Now().UTC().Add(-5 * time.Second).Unix()
				f.claims["leaf"], f.claims["a"] = expiringAt(exp), expiringAt(exp)
			},
			want: model.ErrInvalidTrustChain,
		},
		{
			name:      "the anchor's entity configuration expires inside the clock skew leeway at the same second as the first hint's",
			reference: "10.2",
			setup: func(f *routeFederation) {
				exp := time.Now().UTC().Add(-5 * time.Second).Unix()
				f.claims["ta"], f.claims["a"] = expiringAt(exp), expiringAt(exp)
			},
			want: model.ErrInvalidTrustChain,
		},
		{
			name:      "the anchor's entity configuration is not signed by a key configured for it",
			reference: "10.2",
			setup:     func(f *routeFederation) {},
			anchors: func(f *routeFederation) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{f.entity("ta"): anchorKeySet(t, f.rogue.Public(), map[string]any{"kid": "chain-key"})}
			},
			want: model.ErrInvalidTrustAnchor,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteFederation(t, key, rogue, twoRoutes)
			tc.setup(f)
			cfg := model.Configuration{HttpClient: f.client}
			if tc.anchors != nil {
				cfg.TrustAnchors = tc.anchors(f)
			}

			_, _, _, err := BuildTrustChain(t.Context(), cfg, f.entity("leaf"), f.entity("ta"), resolvecache.New())
			if !errors.Is(err, tc.want) {
				t.Errorf("[%s] expected %v, got %v", tc.reference, tc.want, err)
			}
			for _, statement := range []string{"b", "b>leaf"} {
				if asked := f.timesAsked(statement); asked != 0 {
					t.Errorf("[%s] the failure is on every route, so no other route is worth walking, but %s was asked %d times", tc.reference, statement, asked)
				}
			}
		})
	}
}

func TestBuildTrustChain_ARouteRefusedForOneSubjectStaysOpenToTheNextWalkInTheRequest(t *testing.T) {
	f := newRouteFederation(t, chainSigningKey(t), chainSigningKey(t), map[string][]string{"leaf": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}})
	f.claims["ta>a"] = noIntermediatesBelow()
	cache := resolvecache.New()
	cfg := model.Configuration{HttpClient: f.client}

	if _, _, _, err := BuildTrustChain(t.Context(), cfg, f.entity("leaf"), f.entity("ta"), cache); err != nil {
		t.Fatalf("[6.2.1, 10.3] the route through a has one intermediate below a statement that allows none, so the route through b is the answer, got %v", err)
	}
	if _, _, _, err := BuildTrustChain(t.Context(), cfg, f.entity("a"), f.entity("ta"), cache); err != nil {
		t.Errorf("[6.2.1] a's own chain has no intermediate below the anchor's statement about it, so a walk sharing the request's cache must still find it, got %v", err)
	}
}

func TestBuildTrustChain_RetryingRoutesThatFailValidationIsBoundedByTheEntityBudget(t *testing.T) {
	hints := map[string][]string{"leaf": {"a1", "a2", "a3", "a4", "a5"}, "ta": {}}
	for _, hint := range hints["leaf"] {
		hints[hint] = []string{"ta"}
	}

	tests := []struct {
		name    string
		budget  int
		limited bool
	}{
		{name: "a budget that covers every route", budget: 100},
		{name: "a budget that runs out on the third route", budget: 6, limited: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteFederation(t, chainSigningKey(t), chainSigningKey(t), hints)
			for _, hint := range hints["leaf"] {
				f.claims["ta>"+hint] = noIntermediatesBelow()
			}

			_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: f.client, MaxEntitiesTraversed: tc.budget}, f.entity("leaf"), f.entity("ta"), resolvecache.New())
			if tc.limited {
				if !errors.Is(err, model.ErrLimitReached) {
					t.Errorf("[18.1] three entity configurations, then one more and two retried statements per route, exceed a budget of %d on the third route, got %v", tc.budget, err)
				}
				if asked := f.timesAsked("ta>a3"); asked != 0 {
					t.Errorf("[18.1] expected the budget to stop the walk before the third route's statements were fetched, got %d", asked)
				}
				return
			}
			if !errors.Is(err, model.ErrInvalidTrustChain) || !strings.Contains(err.Error(), "allows at most 0 intermediates below it") {
				t.Errorf("[6.2.1] every route fails, so the first route's failure is the answer, got %v", err)
			}
			for _, hint := range hints["leaf"] {
				if asked := f.timesAsked("ta>" + hint); asked != 1 {
					t.Errorf("expected each route tried once, the anchor's statement about %s was asked %d times", hint, asked)
				}
			}
		})
	}
}
