package trust_chain

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func excludingTheBadDomain() map[string]any {
	return map[string]any{"constraints": map[string]any{"naming_constraints": map[string]any{"excluded": []any{".bad.example"}}}}
}

func hostsFor(hints map[string][]string, bad ...string) map[string]string {
	hosts := map[string]string{}
	for name := range hints {
		hosts[name] = name + ".example"
	}
	for _, name := range bad {
		hosts[name] = name + ".bad.example"
	}
	return hosts
}

func TestBuildTrustChain_ANamingConstraintRefusesOnlyTheRoutesThroughAnEntityOutsideIt(t *testing.T) {
	key, rogue := chainSigningKey(t), chainSigningKey(t)

	tests := []struct {
		name    string
		hints   map[string][]string
		bad     []string
		setter  string
		via     string
		avoids  string
		outside string
	}{
		{
			name:   "the subject's first superior is outside a constraint the anchor sets on a superior the subject also hints at directly",
			hints:  map[string][]string{"leaf": {"m", "x"}, "m": {"x"}, "x": {"ta"}, "ta": {}},
			bad:    []string{"m"},
			setter: "ta>x",
			via:    "x",
			avoids: "m",
		},
		{
			name:   "the subject hints at the constrained superior before the superior outside the constraint",
			hints:  map[string][]string{"leaf": {"x", "m"}, "m": {"x"}, "x": {"ta"}, "ta": {}},
			bad:    []string{"m"},
			setter: "ta>x",
			via:    "x",
			avoids: "m",
		},
		{
			name:   "an entity outside the constraint and the route that avoids it reach the same intermediate at the same depth",
			hints:  map[string][]string{"leaf": {"e", "y"}, "e": {"n"}, "y": {"n"}, "n": {"x"}, "x": {"ta"}, "ta": {}},
			bad:    []string{"e"},
			setter: "ta>x",
			via:    "y",
			avoids: "e",
		},
		{
			name:   "an entity outside the constraint and the route that avoids it reach the same intermediate two levels below the constrained one",
			hints:  map[string][]string{"leaf": {"e", "y"}, "e": {"n1"}, "y": {"z"}, "n1": {"n2"}, "z": {"n2"}, "n2": {"x"}, "x": {"ta"}, "ta": {}},
			bad:    []string{"e"},
			setter: "ta>x",
			via:    "y",
			avoids: "e",
		},
		{
			name:   "the intermediate between the entity outside the constraint and the constrained superior also hints at a superior that reaches no anchor",
			hints:  map[string][]string{"leaf": {"e", "y"}, "e": {"n"}, "y": {"n"}, "n": {"x", "w"}, "w": {}, "x": {"ta"}, "ta": {}},
			bad:    []string{"e"},
			setter: "ta>x",
			via:    "y",
			avoids: "e",
		},
		{
			name:   "an intermediate's statement about its subordinate constrains an entity below it that another route avoids",
			hints:  map[string][]string{"leaf": {"m", "y"}, "m": {"n"}, "y": {"n"}, "n": {"x"}, "x": {"ta"}, "ta": {}},
			bad:    []string{"m"},
			setter: "x>n",
			via:    "y",
			avoids: "m",
		},
		{
			name:    "the only route passes through an entity outside the constraint",
			hints:   map[string][]string{"leaf": {"m"}, "m": {"x"}, "x": {"ta"}, "ta": {}},
			bad:     []string{"m"},
			setter:  "ta>x",
			outside: "m",
		},
		{
			name:    "every route through the constrained superior passes through an entity outside the constraint",
			hints:   map[string][]string{"leaf": {"m1", "m2"}, "m1": {"x"}, "m2": {"x"}, "x": {"ta"}, "ta": {}},
			bad:     []string{"m1", "m2"},
			setter:  "ta>x",
			outside: "m1",
		},
		{
			name:    "the constrained superior is itself outside the constraint",
			hints:   map[string][]string{"leaf": {"m1", "m2"}, "m1": {"x"}, "m2": {"x"}, "x": {"ta"}, "ta": {}},
			bad:     []string{"x"},
			setter:  "ta>x",
			outside: "x",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteFederation(t, key, rogue, tc.hints)
			f.onHosts(hostsFor(tc.hints, tc.bad...))
			f.claims[tc.setter] = excludingTheBadDomain()
			setter := f.entity(tc.setter[:strings.Index(tc.setter, ">")])

			_, parsed, _, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: f.client}, f.entity("leaf"), f.entity("ta"), resolvecache.New())
			if tc.outside != "" {
				want := fmt.Sprintf("the entity identifier %s is outside the naming constraints set by %s", f.entity(tc.outside), setter)
				if !errors.Is(err, model.ErrInvalidTrustChain) || !strings.Contains(err.Error(), want) {
					t.Errorf("[6.2.2] no route avoids an entity outside the constraint, so the first route's failure is the answer, expected invalid_trust_chain with %q, got %v", want, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[6.2.2, 10.3] the constraint covers the entities below the statement that sets it, so a route through the same statement that avoids %s is valid, got %v", tc.avoids, err)
			}
			through := false
			for _, statement := range parsed {
				through = through || statement.Sub == f.entity(tc.via)
				if statement.Iss == f.entity(tc.avoids) || statement.Sub == f.entity(tc.avoids) {
					t.Errorf("[6.2.2] expected the chain to avoid %s, which is outside the constraint", tc.avoids)
				}
			}
			if !through {
				t.Errorf("[6.2.2] expected the chain to pass through %s", tc.via)
			}
		})
	}
}

func TestBuildTrustChain_ASubjectOutsideANamingConstraintAboveManyRoutesIsRefusedForTheConstraint(t *testing.T) {
	const levels = 8
	hints := map[string][]string{"x": {"ta"}, "ta": {}}
	below := []string{"leaf"}
	for level := 1; level <= levels; level++ {
		pair := []string{fmt.Sprintf("a%d", level), fmt.Sprintf("b%d", level)}
		for _, name := range below {
			hints[name] = pair
		}
		below = pair
	}
	for _, name := range below {
		hints[name] = []string{"x"}
	}
	f := newRouteFederation(t, chainSigningKey(t), chainSigningKey(t), hints)
	f.onHosts(hostsFor(hints, "leaf"))
	f.claims["ta>x"] = excludingTheBadDomain()
	cfg := model.Configuration{HttpClient: f.client, MaxTrustChainDepth: levels + 3, MaxEntitiesTraversed: len(hints) + 4}

	_, _, _, err := BuildTrustChain(t.Context(), cfg, f.entity("leaf"), f.entity("ta"), resolvecache.New())
	want := fmt.Sprintf("the entity identifier %s is outside the naming constraints set by %s", f.entity("leaf"), f.entity("ta"))
	if !errors.Is(err, model.ErrInvalidTrustChain) || !strings.Contains(err.Error(), want) {
		t.Errorf("[6.2.2, 18.1] every route carries the subject, so no route is valid and the constraint is the answer, not the walk budget; expected invalid_trust_chain with %q, got %v", want, err)
	}
}

func TestConstraintRefusal_ANamingFailureRefusesTheLinkOnlyBeneathTheEntityOutsideIt(t *testing.T) {
	entity := func(name string) model.EntityIdentifier {
		return model.EntityIdentifier("https://" + name + ".example")
	}
	configuration := func(name string) model.EntityStatement {
		return model.EntityStatement{Iss: entity(name), Sub: entity(name)}
	}
	about := func(issuer, subject string) model.EntityStatement {
		return model.EntityStatement{Iss: entity(issuer), Sub: entity(subject), Constraints: &model.Constraints{NamingConstraints: &model.NamingConstraints{Excluded: []string{".bad.example"}}}}
	}
	pathThrough := func(names ...string) []model.EntityStatement {
		path := make([]model.EntityStatement, 0, len(names))
		for _, name := range names {
			path = append(path, configuration(name))
		}
		return path
	}
	route := pathThrough("leaf", "e", "n", "x", "ta")
	chain := []model.EntityStatement{configuration("leaf"), about("e", "leaf"), about("n", "e"), about("x", "n"), about("ta", "x"), configuration("ta")}
	link := resolvecache.Link{Issuer: entity("ta"), Subject: entity("x")}

	tests := []struct {
		name      string
		outside   int
		path      []model.EntityStatement
		refused   bool
		dependsOn int
	}{
		{name: "a route through the entity outside the constraint", outside: 2, path: pathThrough("leaf", "e", "n", "x"), refused: true, dependsOn: 1},
		{name: "a route through the same link that avoids the entity", outside: 2, path: pathThrough("leaf", "y", "n", "x")},
		{name: "a shorter route through the same link that avoids the entity", outside: 2, path: pathThrough("leaf", "x")},
		{name: "a route through an entity directly below the constrained one", outside: 3, path: pathThrough("leaf", "y", "n", "x"), refused: true, dependsOn: 2},
		{name: "the subject's own entity configuration outside the constraint", outside: 0, path: pathThrough("leaf", "y", "x"), refused: true, dependsOn: independentOfPath},
		{name: "the subject outside the constraint the first statement about it is judged on", outside: 1, path: pathThrough("leaf", "x"), refused: true, dependsOn: independentOfPath},
		{name: "the constrained entity itself outside the constraint", outside: 4, path: pathThrough("leaf", "y", "x"), refused: true, dependsOn: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			refusal := constraintRefusal(route, chain, 4, tc.outside)
			if refusal == nil || refusal.link != link {
				t.Fatalf("[6.2.2] the constraint is set by the anchor's statement about x, so that link is the one refused, got %+v", refusal)
			}
			walk := newWalkMemo(map[resolvecache.Link][]routeRefusal{link: {*refusal}})
			refused, dependsOn := walk.refuses(link, tc.path)
			if refused != tc.refused {
				t.Errorf("[6.2.2] the constraint covers the entities below the statement that sets it, so the link is refused only on a route through %s, expected refused %v, got %v", chain[tc.outside].Sub, tc.refused, refused)
			}
			if refused && dependsOn != tc.dependsOn {
				t.Errorf("a refusal that holds only beneath %s must not be remembered for walks that arrive another way, expected it to depend on path entry %d, got %d", chain[tc.outside].Sub, tc.dependsOn, dependsOn)
			}
		})
	}
}
