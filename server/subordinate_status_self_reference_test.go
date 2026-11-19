package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type answeringStatusRetriever struct {
	asked *atomic.Int64
}

func (r answeringStatusRetriever) GetSubordinateStatus(context.Context, model.EntityIdentifier) (*model.SubordinateStatusResponse, error) {
	r.asked.Add(1)
	return &model.SubordinateStatusResponse{Events: []model.SubordinateStatusEvent{{Iat: time.Now().Unix(), Event: "registration"}}}, nil
}

func TestServer_SubordinateStatus_RefusesTheServersOwnIdentifierAsInvalidRequest(t *testing.T) {
	const own = "https://ta.example.com/fed"
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	tests := []struct {
		name      string
		reference string
		sub       string
		refused   bool
	}{
		{name: "a subordinate", reference: "8.1.2", sub: "https://leaf.example.com"},
		{name: "a subordinate under this server's own path", reference: "8.1.2", sub: "https://ta.example.com/fed/leaf"},
		{name: "the server's own identifier", reference: "8.1.2", sub: own, refused: true},
		{name: "the server's own identifier with a trailing slash", reference: "8.1.2", sub: own + "/", refused: true},
		{name: "the server's own identifier with an upper-case host and the default port", reference: "8.1.2", sub: "https://TA.example.com:443/fed", refused: true},
		{name: "the server's own identifier with an upper-case path", reference: "8.1.2", sub: "https://ta.example.com/FED", refused: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			asked := &atomic.Int64{}
			s := mustNewServer(t, model.ServerConfiguration{
				EntityIdentifier:          own,
				SignerConfiguration:       model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
				IntermediateConfiguration: &model.IntermediateConfiguration{},
				Extensions: model.Extensions{SubordinateStatus: model.SubordinateStatusConfiguration{
					Enabled:           true,
					MetadataRetriever: answeringStatusRetriever{asked: asked},
				}},
			})
			mux := http.NewServeMux()
			s.Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)

			response, err := ts.Client().Get(ts.URL + "/subordinate-status?sub=" + url.QueryEscape(tc.sub))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer func() { _ = response.Body.Close() }()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}

			if !tc.refused {
				if response.StatusCode != http.StatusOK || asked.Load() != 1 {
					t.Fatalf("[%s] expected a statement about a subordinate, got %d after %d lookups: %s", tc.reference, response.StatusCode, asked.Load(), raw)
				}
				return
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil {
				t.Fatalf("expected a JSON error object, got %d %s", response.StatusCode, raw)
			}
			if response.StatusCode != http.StatusBadRequest || answer["error"] != model.InvalidRequest {
				t.Errorf("[%s] a statement whose iss and sub name the same entity is not about a subordinate, so expected the 400 invalid_request /fetch answers, got %d %s", tc.reference, response.StatusCode, raw)
			}
			if asked.Load() != 0 {
				t.Errorf("[%s] expected the retriever not asked about the server itself, got %d lookups", tc.reference, asked.Load())
			}
		})
	}
}
