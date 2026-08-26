package trust_chain

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type topo struct {
	server     *httptest.Server
	keys       map[string]*rsa.PrivateKey
	id         map[string]model.EntityIdentifier
	mu         sync.Mutex
	hits       map[string]int
	errorNodes map[string]bool
}

func newTopo(t *testing.T, hints map[string][]string) *topo {
	t.Helper()

	tp := &topo{
		keys: map[string]*rsa.PrivateKey{},
		id:   map[string]model.EntityIdentifier{},
		hits: map[string]int{},
	}
	for node := range hints {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate key for %q: %v", node, err)
		}
		tp.keys[node] = key
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if strings.HasSuffix(path, "/.well-known/openid-federation") {
			node := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/.well-known/openid-federation")
			key, ok := tp.keys[node]
			if !ok {
				http.NotFound(w, r)
				return
			}
			tp.mu.Lock()
			tp.hits[node]++
			tp.mu.Unlock()

			if tp.errorNodes[node] {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			authorityHints := make([]model.EntityIdentifier, 0, len(hints[node]))
			for _, hint := range hints[node] {
				authorityHints = append(authorityHints, tp.id[hint])
			}
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(createEntityStatement(t, tp.id[node], tp.id[node], authorityHints, key, true))) //nolint:errcheck
			return
		}

		if strings.HasSuffix(path, "/fetch") {
			node := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/fetch")
			key, ok := tp.keys[node]
			if !ok {
				http.NotFound(w, r)
				return
			}
			subject := r.URL.Query().Get("sub")
			var subjectKey *rsa.PrivateKey
			for name, id := range tp.id {
				if string(id) == subject {
					subjectKey = tp.keys[name]
				}
			}
			if subjectKey == nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(createSubordinateStatement(t, tp.id[node], model.EntityIdentifier(subject), key, subjectKey.Public()))) //nolint:errcheck
			return
		}

		http.NotFound(w, r)
	})

	tp.server = httptest.NewTLSServer(handler)
	t.Cleanup(tp.server.Close)

	for node := range hints {
		tp.id[node] = model.EntityIdentifier(fmt.Sprintf("%s/%s", tp.server.URL, node))
	}
	return tp
}

func (tp *topo) maxHits() int {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	max := 0
	for _, v := range tp.hits {
		if v > max {
			max = v
		}
	}
	return max
}

func (tp *topo) totalHits() int {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	total := 0
	for _, v := range tp.hits {
		total += v
	}
	return total
}

const unreachableTrustAnchor = model.EntityIdentifier("https://unreachable.example.test/")

func TestBuildTrustChain_BoundsWalk(t *testing.T) {
	tests := map[string]struct {
		hints         map[string][]string
		leaf          string
		wantMaxHits   int
		wantTotalHits int
	}{
		"diamond shares one intermediate": {
			hints: map[string][]string{
				"leaf": {"a", "b"},
				"a":    {"m"},
				"b":    {"m"},
				"m":    {},
			},
			leaf:          "leaf",
			wantMaxHits:   1,
			wantTotalHits: 4,
		},
		"layered dag shares whole lower tier": {
			hints: map[string][]string{
				"leaf": {"a", "b"},
				"a":    {"c", "d"},
				"b":    {"c", "d"},
				"c":    {"e"},
				"d":    {"e"},
				"e":    {},
			},
			leaf:          "leaf",
			wantMaxHits:   1,
			wantTotalHits: 6,
		},
		"wide fan-out to shared leaf tier": {
			hints: map[string][]string{
				"leaf": {"a", "b", "c"},
				"a":    {"x", "y"},
				"b":    {"x", "y"},
				"c":    {"x", "y"},
				"x":    {},
				"y":    {},
			},
			leaf:          "leaf",
			wantMaxHits:   1,
			wantTotalHits: 6,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tp := newTopo(t, tt.hints)
			cfg := model.Configuration{HttpClient: tp.server.Client()}

			chain, _, _, err := BuildTrustChain(t.Context(), cfg, tp.id[tt.leaf], unreachableTrustAnchor, nil)
			if err == nil {
				t.Fatalf("expected error for unreachable trust anchor, got chain of length %d", len(chain))
			}
			if got := tp.maxHits(); got > tt.wantMaxHits {
				t.Errorf("max fetches for a single entity = %d, want <= %d (shared subtree re-walked)", got, tt.wantMaxHits)
			}
			if got := tp.totalHits(); got != tt.wantTotalHits {
				t.Errorf("total entity-configuration fetches = %d, want %d", got, tt.wantTotalHits)
			}
		})
	}
}

func TestBuildTrustChain_BoundsFailingNodeFetches(t *testing.T) {
	hints := map[string][]string{
		"leaf":   {"a", "b"},
		"a":      {"broken"},
		"b":      {"broken"},
		"broken": {},
	}

	tp := newTopo(t, hints)
	tp.errorNodes = map[string]bool{"broken": true}
	cfg := model.Configuration{HttpClient: tp.server.Client()}

	_, _, _, err := BuildTrustChain(t.Context(), cfg, tp.id["leaf"], unreachableTrustAnchor, nil)
	if err == nil {
		t.Fatal("expected error for unreachable trust anchor")
	}
	if got := tp.hits["broken"]; got != 1 {
		t.Errorf("failing shared node fetched %d times, want 1 (fetch failure not memoised as a dead end)", got)
	}
}

func TestBuildTrustChain_TerminatesOnCycles(t *testing.T) {
	tests := map[string]struct {
		hints map[string][]string
		leaf  string
	}{
		"two node cycle": {
			hints: map[string][]string{
				"leaf": {"a"},
				"a":    {"b"},
				"b":    {"a"},
			},
			leaf: "leaf",
		},
		"shared node reachable through a cycle": {
			hints: map[string][]string{
				"leaf": {"x", "y"},
				"x":    {"s"},
				"y":    {"s"},
				"s":    {"x"},
			},
			leaf: "leaf",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tp := newTopo(t, tt.hints)
			cfg := model.Configuration{HttpClient: tp.server.Client()}

			chain, _, _, err := BuildTrustChain(t.Context(), cfg, tp.id[tt.leaf], unreachableTrustAnchor, nil)
			if err == nil {
				t.Fatalf("expected error for unreachable trust anchor, got chain of length %d", len(chain))
			}
			if err.Error() != "unable to build trust chain from specified 'sub' to specified 'trust_anchor'" {
				t.Errorf("incorrect error thrown: %s", err.Error())
			}
			nodes := len(tt.hints)
			if got := tp.totalHits(); got > nodes*nodes {
				t.Errorf("total fetches = %d exceeds O(n^2)=%d, walk not bounded", got, nodes*nodes)
			}
		})
	}
}

func TestBuildTrustChain_FindsChainWhenOneExists(t *testing.T) {
	tests := map[string]struct {
		hints       map[string][]string
		leaf        string
		trustAnchor string
	}{
		"diamond both paths valid": {
			hints: map[string][]string{
				"leaf": {"i1", "i2"},
				"i1":   {"ta"},
				"i2":   {"ta"},
				"ta":   {},
			},
			leaf:        "leaf",
			trustAnchor: "ta",
		},
		"dead sibling explored before live branch": {
			hints: map[string][]string{
				"leaf": {"dead", "live"},
				"dead": {"d2"},
				"d2":   {},
				"live": {"ta"},
				"ta":   {},
			},
			leaf:        "leaf",
			trustAnchor: "ta",
		},
		"cycle present but real route exists": {
			hints: map[string][]string{
				"leaf": {"a"},
				"a":    {"b", "ta"},
				"b":    {"a"},
				"ta":   {},
			},
			leaf:        "leaf",
			trustAnchor: "ta",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tp := newTopo(t, tt.hints)
			cfg := model.Configuration{HttpClient: tp.server.Client()}

			chain, parsed, _, err := BuildTrustChain(t.Context(), cfg, tp.id[tt.leaf], tp.id[tt.trustAnchor], resolvecache.New())
			if err != nil {
				t.Fatalf("expected a chain to be found, got error %q", err.Error())
			}
			if len(chain) < 3 {
				t.Errorf("expected chain of at least 3 entries (leaf, subordinate statement, anchor), got %d", len(chain))
			}
			if len(parsed) == 0 {
				t.Error("expected parsed chain to be non-empty")
			}
		})
	}
}

func TestBuildTrustChain_MaxDepth(t *testing.T) {
	hints := map[string][]string{
		"leaf": {"n1"},
		"n1":   {"n2"},
		"n2":   {"n3"},
		"n3":   {"n4"},
		"n4":   {},
	}

	tests := map[string]struct {
		maxDepth  int
		wantChain bool
	}{
		"unlimited by default reaches deep anchor": {
			maxDepth:  0,
			wantChain: true,
		},
		"shallow limit refuses to descend": {
			maxDepth:  2,
			wantChain: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tp := newTopo(t, hints)
			cfg := model.Configuration{HttpClient: tp.server.Client(), MaxTrustChainDepth: tt.maxDepth}

			_, _, _, err := BuildTrustChain(t.Context(), cfg, tp.id["leaf"], tp.id["n4"], resolvecache.New())
			if tt.wantChain && err != nil {
				t.Fatalf("expected a chain, got error %q", err.Error())
			}
			if !tt.wantChain && err == nil {
				t.Fatal("expected depth limit to prevent a chain, got one")
			}
		})
	}
}
