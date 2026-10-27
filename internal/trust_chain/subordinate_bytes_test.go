package trust_chain

import (
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/server_test"
)

func TestBuildTrustChain_ASubordinateStatementIsChargedLikeAConfiguration(t *testing.T) {
	testServer := server_test.TestServer(t)
	cfg := model.Configuration{HttpClient: testServer.Client()}
	leaf := model.EntityIdentifier(testServer.URL + "/leaf")
	anchor := model.EntityIdentifier(testServer.URL + "/ta")

	walkCache := resolvecache.New()
	if _, _, _, err := chainUpOne(t.Context(), cfg, leaf, anchor, []model.EntityIdentifier{}, []model.EntityStatement{}, []string{}, walkCache, newWalkMemo()); err != nil {
		t.Fatalf("expected the walk to reach the anchor: %v", err)
	}
	configurationsOnly := walkCache.PeerBytes()
	if configurationsOnly == 0 {
		t.Fatal("the walk charged nothing, so this test cannot tell the two phases apart")
	}

	fullCache := resolvecache.New()
	signedChain, parsedChain, _, err := BuildTrustChain(t.Context(), cfg, leaf, anchor, fullCache)
	if err != nil {
		t.Fatalf("expected the chain to build: %v", err)
	}
	if len(parsedChain) < 2 {
		t.Fatalf("expected a chain of at least two entries, got %d", len(parsedChain))
	}

	var expected int64
	for i := 1; i < len(parsedChain)-1; i++ {
		expected += 2*int64(len(signedChain[i])) + int64(parsedChain[i].DecodedValues())*model.DecodedValueCost
	}
	if expected == 0 {
		t.Fatal("the chain's subordinate statements cost nothing, so this test asserts nothing")
	}

	if got := fullCache.PeerBytes() - configurationsOnly; got != expected {
		t.Errorf("[8.2] a request retains every subordinate statement in the chain it answers with, so each must be charged like a configuration: expected %d beyond the %d the walk charged, got %d", expected, configurationsOnly, got)
	}
}

func TestBuildTrustChain_ABudgetSpentByTheWalkRefusesTheSubordinateFetch(t *testing.T) {
	testServer := server_test.TestServer(t)
	leaf := model.EntityIdentifier(testServer.URL + "/leaf")
	anchor := model.EntityIdentifier(testServer.URL + "/ta")

	walkCache := resolvecache.New()
	if _, _, _, err := chainUpOne(t.Context(), model.Configuration{HttpClient: testServer.Client()}, leaf, anchor, []model.EntityIdentifier{}, []model.EntityStatement{}, []string{}, walkCache, newWalkMemo()); err != nil {
		t.Fatalf("expected the walk to reach the anchor: %v", err)
	}
	spentByTheWalk := walkCache.PeerBytes()
	if spentByTheWalk == 0 {
		t.Fatal("the walk charged nothing, so no budget can be spent by it")
	}

	tests := map[string]struct {
		budget  int64
		refused bool
	}{
		"a budget the walk alone exceeds": {budget: spentByTheWalk - 1, refused: true},
		"a budget large enough for both":  {budget: spentByTheWalk * 100, refused: false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{HttpClient: testServer.Client(), MaxRequestPeerBytes: test.budget}
			_, _, _, err := BuildTrustChain(t.Context(), cfg, leaf, anchor, resolvecache.New())

			if !test.refused {
				if err != nil {
					t.Fatalf("expected the chain to build within the budget: %v", err)
				}
				return
			}
			if !errors.Is(err, model.ErrLimitReached) {
				t.Errorf("[8.9] the walk alone spends the budget, so no subordinate statement may be fetched: expected a limit, got %v", err)
			}
			if errors.Is(err, model.ErrServerError) || errors.Is(err, model.ErrTemporarilyUnavailable) {
				t.Errorf("[8.9] a configured bound refusing a caller's own graph is not a server fault, got %v", err)
			}
		})
	}
}
