package server

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_TrustMarkList_ListsEntities(t *testing.T) {
	tests := map[string]struct {
		query       string
		expectedSub *string
	}{
		"without sub": {query: "trust_mark_type=https://tm.example.com/verified", expectedSub: nil},
		"with sub":    {query: "sub=https://sub.example.com&trust_mark_type=https://tm.example.com/verified", expectedSub: model.Pointer("https://sub.example.com")},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			retriever := &capturingTrustMarkRetriever{
				listed: []model.EntityIdentifier{"https://a.example.com", "https://b.example.com"},
			}
			s := startTrustMarkStatusServer(t, retriever)

			resp, err := s.Client().Get(s.URL + "/trust-mark-list?" + tt.query)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			defer resp.Body.Close() //nolint:errcheck

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected status 200, got %d", resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("expected application/json content type, got %q", ct)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read body: %v", err)
			}
			var got []string
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("failed to unmarshal body %q: %v", body, err)
			}
			if !slices.Equal(got, []string{"https://a.example.com", "https://b.example.com"}) {
				t.Errorf("unexpected entities: %v", got)
			}

			if retriever.receivedType != "https://tm.example.com/verified" {
				t.Errorf("expected trust_mark_type passed through, got %q", retriever.receivedType)
			}
			if tt.expectedSub == nil {
				if retriever.receivedSub != nil {
					t.Errorf("expected nil sub, got %v", retriever.receivedSub)
				}
			} else if retriever.receivedSub == nil || string(*retriever.receivedSub) != *tt.expectedSub {
				t.Errorf("expected sub %q passed through, got %v", *tt.expectedSub, retriever.receivedSub)
			}
		})
	}
}

func TestServer_TrustMarkList_InvalidRequests(t *testing.T) {
	tests := map[string]struct {
		query       string
		description string
	}{
		"missing trust_mark_type": {query: "sub=https://sub.example.com", description: "request missing required parameter 'trust_mark_type'"},
		"malformed sub":           {query: "sub=not-a-valid-identifier&trust_mark_type=https://tm.example.com/verified", description: "malformed 'sub' parameter"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			retriever := &capturingTrustMarkRetriever{}
			s := startTrustMarkStatusServer(t, retriever)

			resp, err := s.Client().Get(s.URL + "/trust-mark-list?" + tt.query)
			validateErrorResponse(t, resp, err, http.StatusBadRequest, "invalid_request", tt.description)

			if retriever.receivedType != "" {
				t.Error("expected invalid request to be rejected before reaching the retriever")
			}
		})
	}
}

func TestServer_TrustMarkList_RetrieverErrorPropagates(t *testing.T) {
	retriever := &capturingTrustMarkRetriever{listErr: model.NewUnsupportedParameterError("trust mark listing not supported")}
	s := startTrustMarkStatusServer(t, retriever)

	resp, err := s.Client().Get(s.URL + "/trust-mark-list?trust_mark_type=https://tm.example.com/verified")
	validateErrorResponse(t, resp, err, http.StatusBadRequest, "unsupported_parameter", "trust mark listing not supported")
}
