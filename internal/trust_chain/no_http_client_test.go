package trust_chain

import (
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestBuildTrustChain_NoHttpClientIsThisServersFault(t *testing.T) {
	_, _, _, err := BuildTrustChain(t.Context(), model.Configuration{}, chainSubject, chainAnchor, resolvecache.New())
	if !errors.Is(err, model.ErrServerError) {
		t.Fatalf("[8.9] expected a missing client to be a server_error, got %v", err)
	}
	if errors.Is(err, model.ErrInvalidTrustAnchor) || errors.Is(err, model.ErrNotFound) || errors.Is(err, model.ErrInvalidTrustChain) {
		t.Errorf("a missing client is this server's fault and must not be reported as the peer's, got %v", err)
	}
}

func TestResolveMetadata_NoHttpClientForAnOmittedAnchorIsThisServersFault(t *testing.T) {
	chain := chainWithClaims(t, nil, nil)
	_, err := resolveTrustingSuppliedAnchor(t, t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chain[:2], resolvecache.New())
	if !errors.Is(err, model.ErrServerError) {
		t.Fatalf("[8.9] expected a missing client to be a server_error, got %v", err)
	}
	if errors.Is(err, model.ErrInvalidTrustAnchor) {
		t.Errorf("a missing client must not be reported as an anchor that could not be retrieved, got %v", err)
	}
}
