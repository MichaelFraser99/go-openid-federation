package trust_chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type unlistedOutcome struct {
	issuers []string
	err     error
}

func unlistedSuperiors(f *routeFederation, exempt map[string][]string) map[model.EntityIdentifier][]model.EntityIdentifier {
	if exempt == nil {
		return nil
	}
	configured := map[model.EntityIdentifier][]model.EntityIdentifier{}
	for entity, superiors := range exempt {
		configured[f.entity(entity)] = []model.EntityIdentifier{}
		for _, superior := range superiors {
			configured[f.entity(entity)] = append(configured[f.entity(entity)], f.entity(superior))
		}
	}
	return configured
}

func chainIssuers(f *routeFederation, chain []model.EntityStatement) []string {
	names := map[model.EntityIdentifier]string{}
	for name := range f.hints {
		names[f.entity(name)] = name
	}
	var issuers []string
	for _, statement := range chain[1 : len(chain)-1] {
		issuers = append(issuers, names[statement.Iss])
	}
	return issuers
}

func newUnlistedFederation(t *testing.T, hints, registers map[string][]string) *routeFederation {
	t.Helper()
	f := newRouteFederation(t, chainSigningKey(t), chainSigningKey(t), hints)
	f.registers = registers
	f.onHosts(hostsFor(hints))
	return f
}

func TestBuildTrustChain_UnlistedSuperiorsAreTriedOnlyForConfiguredEntities(t *testing.T) {
	refusedByWalk := unlistedOutcome{err: model.ErrInvalidTrustAnchor}

	tests := []struct {
		name        string
		hints       map[string][]string
		registers   map[string][]string
		exempt      map[string][]string
		setup       func(f *routeFederation)
		cfg         model.Configuration
		on, off     unlistedOutcome
		neverAsked  []string
		askedOnceOn string
	}{
		{
			name:      "a wallet listing no superior, registered by the anchor directly",
			hints:     map[string][]string{"wallet": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			exempt:    map[string][]string{"wallet": {"ta"}},
			on:        unlistedOutcome{issuers: []string{"ta"}},
			off:       refusedByWalk,
		},
		{
			name:      "a wallet listing only another ecosystem's anchor, registered by this anchor directly",
			hints:     map[string][]string{"wallet": {"eco"}, "eco": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			exempt:    map[string][]string{"wallet": {"ta"}},
			on:        unlistedOutcome{issuers: []string{"ta"}},
			off:       refusedByWalk,
		},
		{
			name:      "a wallet registered by an intermediate under the anchor",
			hints:     map[string][]string{"wallet": {}, "im": {"ta"}, "ta": {}},
			registers: map[string][]string{"im": {"wallet"}},
			exempt:    map[string][]string{"wallet": {"im"}},
			on:        unlistedOutcome{issuers: []string{"im", "ta"}},
			off:       refusedByWalk,
		},
		{
			name:      "two configured superiors where only the second registers the wallet",
			hints:     map[string][]string{"wallet": {}, "x": {"ta"}, "im": {"ta"}, "ta": {}},
			registers: map[string][]string{"im": {"wallet"}},
			exempt:    map[string][]string{"wallet": {"x", "im"}},
			on:        unlistedOutcome{issuers: []string{"im", "ta"}},
			off:       refusedByWalk,
		},
		{
			name:      "an exempt intermediate the wallet lists, registered by the anchor without listing it",
			hints:     map[string][]string{"wallet": {"im"}, "im": {}, "ta": {}},
			registers: map[string][]string{"ta": {"im"}},
			exempt:    map[string][]string{"im": {"ta"}},
			on:        unlistedOutcome{issuers: []string{"im", "ta"}},
			off:       refusedByWalk,
		},
		{
			name:      "the same topology for an entity that is not configured",
			hints:     map[string][]string{"wallet": {}, "other": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet", "other"}},
			exempt:    map[string][]string{"other": {"ta"}},
			on:        refusedByWalk,
			off:       refusedByWalk,
		},
		{
			name:       "a configured wallet whose only registering superior is not in its configured list",
			hints:      map[string][]string{"wallet": {}, "im": {"ta"}, "ta": {}},
			registers:  map[string][]string{"ta": {"wallet"}},
			exempt:     map[string][]string{"wallet": {"im"}},
			on:         unlistedOutcome{err: model.ErrInvalidTrustChain},
			off:        refusedByWalk,
			neverAsked: []string{"ta>wallet"},
		},
		{
			name:      "a rogue superior outside the configured list registers the wallet with metadata of its own",
			hints:     map[string][]string{"wallet": {}, "rogue": {"ta"}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}, "rogue": {"wallet"}},
			exempt:    map[string][]string{"wallet": {"ta"}},
			setup: func(f *routeFederation) {
				f.claims["rogue>wallet"] = map[string]any{"metadata": map[string]any{"federation_entity": map[string]any{"organization_name": "rogue"}}}
			},
			on:         unlistedOutcome{issuers: []string{"ta"}},
			off:        refusedByWalk,
			neverAsked: []string{"rogue", "rogue>wallet"},
		},
		{
			name:       "a rogue superior outside the configured list is the only one registering the wallet",
			hints:      map[string][]string{"wallet": {}, "rogue": {"ta"}, "ta": {}},
			registers:  map[string][]string{"rogue": {"wallet"}},
			exempt:     map[string][]string{"wallet": {"ta"}},
			on:         unlistedOutcome{err: model.ErrInvalidTrustChain},
			off:        refusedByWalk,
			neverAsked: []string{"rogue", "rogue>wallet"},
		},
		{
			name:      "the configured superior registers a key the wallet does not sign with",
			hints:     map[string][]string{"wallet": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			exempt:    map[string][]string{"wallet": {"ta"}},
			setup:     func(f *routeFederation) { f.claims["ta>wallet"] = map[string]any{"jwks": f.rogueKeyOnly()} },
			on:        unlistedOutcome{err: model.ErrInvalidTrustChain},
			off:       refusedByWalk,
		},
		{
			name:        "a configured superior the wallet also lists, configured twice, is asked once",
			hints:       map[string][]string{"wallet": {"ta"}, "ta": {}},
			exempt:      map[string][]string{"wallet": {"ta", "ta"}},
			on:          unlistedOutcome{issuers: []string{"ta"}},
			off:         unlistedOutcome{issuers: []string{"ta"}},
			askedOnceOn: "ta>wallet",
		},
		{
			name:      "configured superiors do not count against MaxAuthorityHints",
			hints:     map[string][]string{"wallet": {"eco"}, "eco": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			exempt:    map[string][]string{"wallet": {"ta"}},
			cfg:       model.Configuration{MaxAuthorityHints: 1},
			on:        unlistedOutcome{issuers: []string{"ta"}},
			off:       refusedByWalk,
		},
		{
			name:      "an exempt wallet listing more authority_hints than MaxAuthorityHints is still refused",
			hints:     map[string][]string{"wallet": {"eco", "eco2"}, "eco": {}, "eco2": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			exempt:    map[string][]string{"wallet": {"ta"}},
			cfg:       model.Configuration{MaxAuthorityHints: 1},
			on:        unlistedOutcome{err: model.ErrInvalidTrustChain},
			off:       unlistedOutcome{err: model.ErrInvalidTrustChain},
		},
		{
			name:      "a configured superior's entity configuration is charged to MaxEntitiesTraversed",
			hints:     map[string][]string{"wallet": {"im"}, "im": {}, "ta": {}},
			registers: map[string][]string{"ta": {"im"}},
			exempt:    map[string][]string{"im": {"ta"}},
			cfg:       model.Configuration{MaxEntitiesTraversed: 2},
			on:        unlistedOutcome{err: model.ErrLimitReached},
			off:       refusedByWalk,
		},
		{
			name:      "a configured superior is held to MaxTrustChainDepth",
			hints:     map[string][]string{"wallet": {}, "im": {"ta"}, "ta": {}},
			registers: map[string][]string{"im": {"wallet"}},
			exempt:    map[string][]string{"wallet": {"im"}},
			cfg:       model.Configuration{MaxTrustChainDepth: 2},
			on:        unlistedOutcome{err: model.ErrLimitReached},
			off:       refusedByWalk,
		},
	}

	for _, tc := range tests {
		for _, mode := range []string{"on", "off"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				f := newUnlistedFederation(t, tc.hints, tc.registers)
				if tc.setup != nil {
					tc.setup(f)
				}
				cfg := tc.cfg
				cfg.HttpClient = f.client
				want := tc.off
				if mode == "on" {
					cfg.Experimental.UnlistedSuperiors = unlistedSuperiors(f, tc.exempt)
					want = tc.on
				}

				_, chain, _, err := BuildTrustChain(t.Context(), cfg, f.entity("wallet"), f.entity("ta"), nil)

				if want.err != nil {
					if !errors.Is(err, want.err) {
						t.Fatalf("expected %v, got %v", want.err, err)
					}
				} else {
					if err != nil {
						t.Fatalf("expected a chain, got %v", err)
					}
					if got := chainIssuers(f, chain); !reflect.DeepEqual(got, want.issuers) {
						t.Errorf("expected the subordinate statements to be issued by %v, got %v", want.issuers, got)
					}
					if federation := chain[0].Metadata.FederationMetadata; federation != nil && (*federation)["organization_name"] != nil {
						t.Errorf("expected no metadata from a superior outside the chain, got %v", (*federation)["organization_name"])
					}
				}
				if mode == "on" {
					for _, name := range tc.neverAsked {
						if asked := f.timesAsked(name); asked != 0 {
							t.Errorf("expected %s never to be asked, it was asked %d times", name, asked)
						}
					}
					if tc.askedOnceOn != "" {
						if asked := f.timesAsked(tc.askedOnceOn); asked != 1 {
							t.Errorf("expected %s to be asked once, it was asked %d times", tc.askedOnceOn, asked)
						}
					}
				}
			})
		}
	}
}

func TestResolveMetadata_ASuppliedChainMayUseOnlyAConfiguredUnlistedSuperior(t *testing.T) {
	tests := []struct {
		name      string
		hints     map[string][]string
		registers map[string][]string
		built     map[string][]string
		resolved  map[string][]string
		err       error
	}{
		{
			name:      "the subject is configured with the issuer of its statement",
			hints:     map[string][]string{"wallet": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			built:     map[string][]string{"wallet": {"ta"}},
			resolved:  map[string][]string{"wallet": {"ta"}},
		},
		{
			name:      "the subject lists another ecosystem and is configured with the issuer of its statement",
			hints:     map[string][]string{"wallet": {"eco"}, "eco": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			built:     map[string][]string{"wallet": {"ta"}},
			resolved:  map[string][]string{"wallet": {"ta"}},
		},
		{
			name:      "nothing is configured",
			hints:     map[string][]string{"wallet": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			built:     map[string][]string{"wallet": {"ta"}},
			err:       model.ErrInvalidTrustChain,
		},
		{
			name:      "the subject is configured, but not with the issuer of its statement",
			hints:     map[string][]string{"wallet": {}, "im": {"ta"}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			built:     map[string][]string{"wallet": {"ta"}},
			resolved:  map[string][]string{"wallet": {"im"}},
			err:       model.ErrInvalidTrustChain,
		},
		{
			name:      "another entity is configured with the issuer of the subject's statement",
			hints:     map[string][]string{"wallet": {}, "other": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			built:     map[string][]string{"wallet": {"ta"}},
			resolved:  map[string][]string{"other": {"ta"}},
			err:       model.ErrInvalidTrustChain,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newUnlistedFederation(t, tc.hints, tc.registers)
			building := model.Configuration{HttpClient: f.client}
			building.Experimental.UnlistedSuperiors = unlistedSuperiors(f, tc.built)
			chain, _, _, err := BuildTrustChain(t.Context(), building, f.entity("wallet"), f.entity("ta"), nil)
			if err != nil {
				t.Fatalf("failed to build the chain to supply: %v", err)
			}

			resolving := model.Configuration{HttpClient: f.client}
			resolving.Experimental.UnlistedSuperiors = unlistedSuperiors(f, tc.resolved)
			resolved, err := ResolveMetadata(t.Context(), resolving, "https://resolver.example", f.entity("ta"), chain, nil)

			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("[3.2] expected %v, got %v", tc.err, err)
				}
				if !strings.Contains(err.Error(), "is not listed in the authority_hints") {
					t.Errorf("expected the refusal to name authority_hints, got %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the chain to resolve, got %v", err)
			}
			if resolved.Sub != f.entity("wallet") {
				t.Errorf("expected metadata for the wallet, got %s", resolved.Sub)
			}
		})
	}
}

func TestUnlistedSuperiors_TheUseOfAnUnlistedSuperiorIsLoggedOncePerRequest(t *testing.T) {
	tests := []struct {
		name      string
		hints     map[string][]string
		registers map[string][]string
		exempt    map[string][]string
		logged    [][2]string
	}{
		{
			name:      "the subject's superior",
			hints:     map[string][]string{"wallet": {}, "ta": {}},
			registers: map[string][]string{"ta": {"wallet"}},
			exempt:    map[string][]string{"wallet": {"ta"}},
			logged:    [][2]string{{"wallet", "ta"}},
		},
		{
			name:      "an intermediate's superior",
			hints:     map[string][]string{"wallet": {"im"}, "im": {}, "ta": {}},
			registers: map[string][]string{"ta": {"im"}},
			exempt:    map[string][]string{"im": {"ta"}},
			logged:    [][2]string{{"im", "ta"}},
		},
		{
			name:      "both the subject's and the intermediate's superiors",
			hints:     map[string][]string{"wallet": {}, "im": {}, "ta": {}},
			registers: map[string][]string{"im": {"wallet"}, "ta": {"im"}},
			exempt:    map[string][]string{"wallet": {"im"}, "im": {"ta"}},
			logged:    [][2]string{{"wallet", "im"}, {"im", "ta"}},
		},
		{
			name:   "a configured superior the subject also lists",
			hints:  map[string][]string{"wallet": {"ta"}, "ta": {}},
			exempt: map[string][]string{"wallet": {"ta"}},
		},
	}

	requests := []struct {
		name         string
		subjectsOnly bool
		run          func(t *testing.T, f *routeFederation, cfg model.Configuration, chain []string)
	}{
		{name: "building the chain twice in one request", run: func(t *testing.T, f *routeFederation, cfg model.Configuration, _ []string) {
			cache := resolvecache.New()
			for range 2 {
				if _, _, _, err := BuildTrustChain(t.Context(), cfg, f.entity("wallet"), f.entity("ta"), cache); err != nil {
					t.Fatalf("expected a chain, got %v", err)
				}
			}
		}},
		{name: "resolving a supplied chain", subjectsOnly: true, run: func(t *testing.T, f *routeFederation, cfg model.Configuration, chain []string) {
			if _, err := ResolveMetadata(t.Context(), cfg, "https://resolver.example", f.entity("ta"), chain, nil); err != nil {
				t.Fatalf("expected the chain to resolve, got %v", err)
			}
		}},
		{name: "building and resolving in one request", run: func(t *testing.T, f *routeFederation, cfg model.Configuration, _ []string) {
			cache := resolvecache.New()
			chain, _, _, err := BuildTrustChain(t.Context(), cfg, f.entity("wallet"), f.entity("ta"), cache)
			if err != nil {
				t.Fatalf("expected a chain, got %v", err)
			}
			if _, err = ResolveMetadata(t.Context(), cfg, "https://resolver.example", f.entity("ta"), chain, cache); err != nil {
				t.Fatalf("expected the chain to resolve, got %v", err)
			}
		}},
	}

	for _, tc := range tests {
		for _, request := range requests {
			t.Run(tc.name+"/"+request.name, func(t *testing.T) {
				f := newUnlistedFederation(t, tc.hints, tc.registers)
				cfg := model.Configuration{HttpClient: f.client}
				cfg.Experimental.UnlistedSuperiors = unlistedSuperiors(f, tc.exempt)
				chain, _, _, err := BuildTrustChain(t.Context(), cfg, f.entity("wallet"), f.entity("ta"), nil)
				if err != nil {
					t.Fatalf("expected a chain, got %v", err)
				}
				var logs bytes.Buffer
				cfg.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

				request.run(t, f, cfg, chain)

				var got [][2]string
				for _, record := range logRecords(t, &logs) {
					if !strings.Contains(record["msg"].(string), "Experimental.UnlistedSuperiors") {
						continue
					}
					if record["level"] != "INFO" {
						t.Errorf("expected the line at Info, got %v", record["level"])
					}
					entity, _ := record["entity"].(string)
					superior, _ := record["superior"].(string)
					got = append(got, [2]string{entity, superior})
				}
				var want [][2]string
				for _, pair := range tc.logged {
					if !request.subjectsOnly || pair[0] == "wallet" {
						want = append(want, [2]string{string(f.entity(pair[0])), string(f.entity(pair[1]))})
					}
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("expected one line per unlisted link %v, got %v", want, got)
				}
			})
		}
	}
}

func logRecords(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("failed to read a log line: %v", err)
		}
		records = append(records, record)
	}
	return records
}

func TestBuildTrustChain_ASuperiorConfiguredTwiceIsTriedOnce(t *testing.T) {
	tests := []struct {
		name   string
		hints  []string
		exempt []string
	}{
		{name: "configured twice", hints: []string{}, exempt: []string{"im", "im"}},
		{name: "listed and configured", hints: []string{"im"}, exempt: []string{"im"}},
		{name: "listed and configured twice", hints: []string{"im"}, exempt: []string{"im", "im"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newUnlistedFederation(t, map[string][]string{"wallet": tc.hints, "im": {"ta"}, "ta": {}}, map[string][]string{"im": {"wallet"}})
			var logs bytes.Buffer
			cfg := model.Configuration{HttpClient: f.client, Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))}
			cfg.Experimental.UnlistedSuperiors = unlistedSuperiors(f, map[string][]string{"wallet": tc.exempt})

			if _, _, _, err := BuildTrustChain(t.Context(), cfg, f.entity("wallet"), f.entity("ta"), nil); err != nil {
				t.Fatalf("expected a chain, got %v", err)
			}

			for _, record := range logRecords(t, &logs) {
				if record["msg"] == "checking authority hints" && record["subject"] == string(f.entity("wallet")) {
					if checked, _ := record["authority_hints_to_check"].([]any); !reflect.DeepEqual(checked, []any{string(f.entity("im"))}) {
						t.Errorf("expected the superior to be tried once, got %v", checked)
					}
					return
				}
			}
			t.Fatal("expected the wallet's superiors to be logged")
		})
	}
}

func TestUnlistedSuperiors_AMalformedConfigurationIsRefusedBeforeAnyRequest(t *testing.T) {
	tests := []struct {
		name       string
		configured map[string][]string
		field      string
	}{
		{name: "an entity with no superiors", configured: map[string][]string{"wallet": {}}, field: "lists no superior"},
		{name: "an entity configured as its own superior", configured: map[string][]string{"wallet": {"wallet"}}, field: "names the entity itself"},
	}

	entries := []struct {
		name string
		call func(t *testing.T, f *routeFederation, cfg model.Configuration) error
	}{
		{name: "BuildTrustChain", call: func(t *testing.T, f *routeFederation, cfg model.Configuration) error {
			_, _, _, err := BuildTrustChain(t.Context(), cfg, f.entity("wallet"), f.entity("ta"), nil)
			return err
		}},
		{name: "ResolveMetadata", call: func(t *testing.T, f *routeFederation, cfg model.Configuration) error {
			_, err := ResolveMetadata(t.Context(), cfg, "https://resolver.example", f.entity("ta"), []string{"a.b.c", "a.b.c", "a.b.c"}, nil)
			return err
		}},
	}

	for _, tc := range tests {
		for _, entry := range entries {
			t.Run(tc.name+"/"+entry.name, func(t *testing.T) {
				f := newUnlistedFederation(t, map[string][]string{"wallet": {"ta"}, "ta": {}}, nil)
				var logs bytes.Buffer
				cfg := model.Configuration{HttpClient: f.client, Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))}
				cfg.Experimental.UnlistedSuperiors = unlistedSuperiors(f, tc.configured)

				err := entry.call(t, f, cfg)

				logged := false
				for _, record := range logRecords(t, &logs) {
					if text, _ := record["error"].(string); strings.Contains(text, "Experimental.UnlistedSuperiors") {
						logged = record["level"] == "ERROR"
					}
				}
				if !logged {
					t.Errorf("expected the refusal logged at Error, got %s", logs.String())
				}

				if !errors.Is(err, model.ErrServerError) || !strings.Contains(err.Error(), "Experimental.UnlistedSuperiors") || !strings.Contains(err.Error(), tc.field) {
					t.Errorf("expected server_error naming Experimental.UnlistedSuperiors and %q, got %v", tc.field, err)
				}
				for _, name := range []string{"wallet", "ta", "ta>wallet"} {
					if asked := f.timesAsked(name); asked != 0 {
						t.Errorf("expected no request before the configuration is refused, %s was asked %d times", name, asked)
					}
				}
			})
		}
	}
}
