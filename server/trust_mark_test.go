package server

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type capturingTrustMarkRetriever struct {
	issued       *string
	issueErr     error
	listed       []model.EntityIdentifier
	listErr      error
	receivedType string
	receivedSub  *model.EntityIdentifier
}

func (r *capturingTrustMarkRetriever) GetTrustMarkStatus(_ context.Context, _ string) (*string, error) {
	return nil, nil
}

func (r *capturingTrustMarkRetriever) IssueTrustMark(_ context.Context, trustMarkType string, sub model.EntityIdentifier) (*string, error) {
	r.receivedType = trustMarkType
	r.receivedSub = &sub
	return r.issued, r.issueErr
}

func (r *capturingTrustMarkRetriever) ListTrustMarks(_ context.Context, trustMarkType string, sub *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	r.receivedType = trustMarkType
	r.receivedSub = sub
	return r.listed, r.listErr
}

func TestServer_TrustMark_IssuesTrustMark(t *testing.T) {
	retriever := &capturingTrustMarkRetriever{issued: model.Pointer("issued.trust.mark")}
	s := startTrustMarkStatusServer(t, retriever)

	resp, err := s.Client().Get(s.URL + "/trust-mark?sub=https://sub.example.com&trust_mark_type=https://tm.example.com/verified")
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/trust-mark+jwt" {
		t.Errorf("expected trust-mark+jwt content type, got %q", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if string(body) != "issued.trust.mark" {
		t.Errorf("expected issued trust mark echoed back, got %q", body)
	}

	if retriever.receivedType != "https://tm.example.com/verified" {
		t.Errorf("expected trust_mark_type passed through, got %q", retriever.receivedType)
	}
	if retriever.receivedSub == nil || string(*retriever.receivedSub) != "https://sub.example.com" {
		t.Errorf("expected sub passed through, got %v", retriever.receivedSub)
	}
}

func TestServer_TrustMark_InvalidRequests(t *testing.T) {
	tests := map[string]struct {
		query       string
		description string
	}{
		"missing sub":             {query: "trust_mark_type=https://tm.example.com/verified", description: "request missing required parameter 'sub'"},
		"malformed sub":           {query: "sub=not-a-valid-identifier&trust_mark_type=https://tm.example.com/verified", description: "malformed 'sub' parameter"},
		"missing trust_mark_type": {query: "sub=https://sub.example.com", description: "request missing required parameter 'trust_mark_type'"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			retriever := &capturingTrustMarkRetriever{issued: model.Pointer("issued.trust.mark")}
			s := startTrustMarkStatusServer(t, retriever)

			resp, err := s.Client().Get(s.URL + "/trust-mark?" + tt.query)
			validateErrorResponse(t, resp, err, http.StatusBadRequest, "invalid_request", tt.description)

			if retriever.receivedSub != nil {
				t.Error("expected invalid request to be rejected before reaching the retriever")
			}
		})
	}
}

func TestServer_TrustMark_RetrieverErrorPropagates(t *testing.T) {
	retriever := &capturingTrustMarkRetriever{issueErr: model.NewUnsupportedParameterError("trust mark issuance not supported")}
	s := startTrustMarkStatusServer(t, retriever)

	resp, err := s.Client().Get(s.URL + "/trust-mark?sub=https://sub.example.com&trust_mark_type=https://tm.example.com/verified")
	validateErrorResponse(t, resp, err, http.StatusBadRequest, "unsupported_parameter", "trust mark issuance not supported")
}
