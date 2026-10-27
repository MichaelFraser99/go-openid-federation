package trust_chain

import (
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

	// The walk and the chain assembly are charged separately, so measuring the walk
	// alone isolates what the subordinate statements add. Comparing a single total
	// against a figure derived from the chain cannot: the configurations alone
	// exceed it, so an uncharged subordinate statement looks the same.
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

	// The chain is the leaf's configuration, then one subordinate statement per
	// step, then the anchor's own configuration. Only the middle span is charged
	// here; both configurations were charged during the walk.
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
