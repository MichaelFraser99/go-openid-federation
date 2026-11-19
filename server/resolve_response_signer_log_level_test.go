package server

import (
	"crypto"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type failOnCallSigner struct {
	josemodel.Signer
	calls  *atomic.Int64
	failOn int64
	err    error
}

func (s failOnCallSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.calls.Add(1) == s.failOn {
		return nil, s.err
	}
	return s.Signer.Sign(rand, digest, opts)
}

func TestServer_Resolve_LogsAResponseSigningFailureAtItsClassLevel(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		errors int
	}{
		{name: "a signer that fails", err: errors.New("hsm.internal refused the signature"), status: http.StatusInternalServerError, errors: 1},
		{name: "a signer that is temporarily unavailable", err: model.NewTemporarilyUnavailableError("hsm.internal is busy"), status: http.StatusServiceUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := startSuperiorMetadataFederation(t, map[string]any{"federation_entity": map[string]any{"organization_name": "Leaf"}})
			f.register(t, nil, model.MetadataPolicy{})
			signer := f.anchor.cfg.SignerConfiguration.Signer.(josemodel.Signer)
			resolve := func() *http.Response {
				response, err := f.anchorServer.Client().Get(f.anchorServer.URL + "/resolve?sub=" + url.QueryEscape(f.leafURL) + "&trust_anchor=" + url.QueryEscape(f.anchorServer.URL))
				if err != nil {
					t.Fatalf("resolve failed: %v", err)
				}
				_ = response.Body.Close()
				return response
			}

			calls := &atomic.Int64{}
			f.anchor.cfg.SignerConfiguration.Signer = failOnCallSigner{Signer: signer, calls: calls}
			if response := resolve(); response.StatusCode != http.StatusOK {
				t.Fatalf("expected the calibrating resolve to succeed, got %d", response.StatusCode)
			}
			signatures := calls.Load()

			logs := newLevelCountingHandler()
			f.anchor.cfg.Logger = slog.New(logs)
			f.anchor.cfg.SignerConfiguration.Signer = failOnCallSigner{Signer: signer, calls: &atomic.Int64{}, failOn: signatures, err: tc.err}
			if response := resolve(); response.StatusCode != tc.status {
				t.Fatalf("[8.9] expected %d when the response signature fails, got %d", tc.status, response.StatusCode)
			}
			if got := logs.count(slog.LevelError); got != tc.errors {
				t.Errorf("expected %d Error lines for a %d, got %d", tc.errors, tc.status, got)
			}
		})
	}
}
