package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestParseError_BoundsTheDescription(t *testing.T) {
	server := NewServer(model.ServerConfiguration{})

	tests := []struct {
		name  string
		err   error
		bound bool
	}{
		{name: "a short reason passes through", err: model.NewInvalidTrustChainError("a short reason")},
		{name: "a megabyte of peer bytes is bounded", err: model.NewInvalidTrustChainError(strings.Repeat("A", 1<<20)), bound: true},
		{name: "a megabyte of metadata detail is bounded", err: model.NewInvalidMetadataError(strings.Repeat("B", 1<<20)), bound: true},
		{name: "a megabyte on a not found is bounded", err: model.NewNotFoundError(strings.Repeat("C", 1<<20)), bound: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, body := server.parseError(tc.err)

			var decoded struct {
				Description string `json:"error_description"`
			}
			if err := json.Unmarshal([]byte(body), &decoded); err != nil {
				t.Fatalf("failed to decode the error body: %v", err)
			}

			if len(decoded.Description) > model.MaxErrorDescriptionBytes+3 {
				t.Fatalf("expected the description to be bounded by %d bytes, got %d", model.MaxErrorDescriptionBytes, len(decoded.Description))
			}
			if tc.bound && !strings.HasSuffix(decoded.Description, "...") {
				t.Errorf("expected a bounded description to be marked as truncated")
			}
			if !tc.bound && strings.HasSuffix(decoded.Description, "...") {
				t.Errorf("expected a short description to pass through unchanged, got %q", decoded.Description)
			}
		})
	}
}
