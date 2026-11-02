package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type levelCountingHandler struct {
	mu     *sync.Mutex
	counts map[slog.Level]int
	causes map[string]int
}

func newLevelCountingHandler() levelCountingHandler {
	return levelCountingHandler{mu: &sync.Mutex{}, counts: map[slog.Level]int{}, causes: map[string]int{}}
}

func (h levelCountingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h levelCountingHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.counts[record.Level]++
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "error" {
			h.causes[attr.Value.String()]++
		}
		return true
	})
	return nil
}

func (h levelCountingHandler) causeLines(substring string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	lines := 0
	for cause, n := range h.causes {
		if strings.Contains(cause, substring) {
			lines += n
		}
	}
	return lines
}

func (h levelCountingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h levelCountingHandler) WithGroup(string) slog.Handler { return h }

func (h levelCountingHandler) count(level slog.Level) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counts[level]
}

type failingSubordinateSignerRetriever struct{ classifiedSubordinateRetriever }

func (failingSubordinateSignerRetriever) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, errors.New("connection refused by db.internal")
}

type issuingTrustMarkRetriever struct{ err error }

func (r issuingTrustMarkRetriever) GetTrustMarkStatus(context.Context, string) (*string, error) {
	return nil, r.err
}

func (r issuingTrustMarkRetriever) IssueTrustMark(context.Context, string, model.EntityIdentifier) (*string, error) {
	return nil, r.err
}

func (r issuingTrustMarkRetriever) ListTrustMarks(context.Context, string, *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	return nil, r.err
}

func TestServer_AFaultOfThisServersOwnIsLoggedAtErrorOnceAndACallersFaultIsNot(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	withKeylessSubordinate := func(cfg *model.ServerConfiguration) {
		cfg.IntermediateConfiguration.AddSubordinate("https://leaf.example.com", &model.SubordinateConfiguration{})
	}
	withSubordinateStore := func(err error) func(*model.ServerConfiguration) {
		return func(cfg *model.ServerConfiguration) {
			cfg.MetadataRetriever = classifiedSubordinateRetriever{err: err}
		}
	}
	withTrustMarkStore := func(err error) func(*model.ServerConfiguration) {
		return func(cfg *model.ServerConfiguration) {
			cfg.TrustMarkRetriever = issuingTrustMarkRetriever{err: err}
		}
	}

	tests := []struct {
		name      string
		reference string
		configure func(*model.ServerConfiguration)
		path      string
		status    int
		errors    int
		cause     string
	}{
		{
			name:      "the entity configuration when this server cannot read its subordinate signers",
			reference: "8.9 server_error",
			configure: func(cfg *model.ServerConfiguration) { cfg.MetadataRetriever = failingSubordinateSignerRetriever{} },
			path:      "/.well-known/openid-federation",
			status:    http.StatusInternalServerError,
			errors:    1,
		},
		{
			name:      "a subordinate statement when the subordinate store fails",
			reference: "8.9 server_error",
			configure: withSubordinateStore(errors.New("connection refused by db.internal")),
			path:      "/fetch?sub=https://leaf.example.com",
			status:    http.StatusInternalServerError,
			errors:    1,
			cause:     "db.internal",
		},
		{
			name:      "a subordinate statement for a subordinate registered with no keys",
			reference: "8.9 server_error",
			configure: withKeylessSubordinate,
			path:      "/fetch?sub=https://leaf.example.com",
			status:    http.StatusInternalServerError,
			errors:    1,
		},
		{
			name:      "a subordinate statement for a subject this server does not know",
			reference: "8.9 not_found",
			configure: func(*model.ServerConfiguration) {},
			path:      "/fetch?sub=https://unknown.example.com",
			status:    http.StatusNotFound,
		},
		{
			name:      "a subordinate statement while the subordinate store is temporarily unavailable",
			reference: "8.9 temporarily_unavailable",
			configure: withSubordinateStore(model.NewTemporarilyUnavailableError("database down")),
			path:      "/fetch?sub=https://leaf.example.com",
			status:    http.StatusServiceUnavailable,
		},
		{
			name:      "a subordinate statement requested without a subject",
			reference: "8.9 invalid_request",
			configure: func(*model.ServerConfiguration) {},
			path:      "/fetch",
			status:    http.StatusBadRequest,
		},
		{
			name:      "a trust mark when the trust mark store fails",
			reference: "8.9 server_error",
			configure: withTrustMarkStore(errors.New("connection refused by db.internal")),
			path:      "/trust-mark?sub=https://leaf.example.com&trust_mark_type=https://tm.example.com/certified",
			status:    http.StatusInternalServerError,
			errors:    1,
		},
		{
			name:      "a trust mark the subject does not hold",
			reference: "8.9 not_found",
			configure: withTrustMarkStore(model.NewNotFoundError("entity does not hold this trust mark")),
			path:      "/trust-mark?sub=https://leaf.example.com&trust_mark_type=https://tm.example.com/certified",
			status:    http.StatusNotFound,
		},
		{
			name:      "an extended listing with subordinate statements when the subordinate store fails",
			reference: "8.9 server_error",
			configure: func(cfg *model.ServerConfiguration) {
				cfg.MetadataRetriever = classifiedSubordinateRetriever{err: errors.New("connection refused by db.internal")}
				cfg.Extensions.ExtendedListing = model.ExtendedListingConfiguration{
					Enabled:   true,
					SizeLimit: 50,
					MetadataRetriever: &testExtendedListingRetriever{result: &model.ExtendedListingResponse{
						ImmediateSubordinateEntities: []map[string]any{{"id": "https://leaf.example.com"}},
					}},
				}
			},
			path:   "/extended-list?claims=subordinate_statement",
			status: http.StatusInternalServerError,
			errors: 1,
			cause:  "db.internal",
		},
		{
			name:      "an extended listing with subordinate statements while the subordinate store is temporarily unavailable",
			reference: "8.9 temporarily_unavailable",
			configure: func(cfg *model.ServerConfiguration) {
				cfg.MetadataRetriever = classifiedSubordinateRetriever{err: model.NewTemporarilyUnavailableError("database down")}
				cfg.Extensions.ExtendedListing = model.ExtendedListingConfiguration{
					Enabled:   true,
					SizeLimit: 50,
					MetadataRetriever: &testExtendedListingRetriever{result: &model.ExtendedListingResponse{
						ImmediateSubordinateEntities: []map[string]any{{"id": "https://leaf.example.com"}},
					}},
				}
			},
			path:   "/extended-list?claims=subordinate_statement",
			status: http.StatusServiceUnavailable,
			cause:  "database down",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := newLevelCountingHandler()
			cfg := model.ServerConfiguration{
				SignerConfiguration:       model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
				IntermediateConfiguration: &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour, SubordinateCacheTime: time.Minute},
				Configuration:             model.Configuration{Logger: slog.New(logs)},
			}
			tc.configure(&cfg)
			ts := startFetchServer(t, cfg)

			response, err := ts.Client().Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			_ = response.Body.Close()
			if response.StatusCode != tc.status {
				t.Fatalf("[%s] expected status %d, got %d", tc.reference, tc.status, response.StatusCode)
			}

			if got := logs.count(slog.LevelError); got != tc.errors {
				t.Errorf("[%s] a server_error must leave exactly one Error line, because the response carries fixed text and the log is the only record of why, and a fault of the peer or caller must leave none: expected %d, got %d", tc.reference, tc.errors, got)
			}
			if tc.cause != "" {
				if got := logs.causeLines(tc.cause); got != 1 {
					t.Errorf("[%s] a store fault must be logged once, where its cause is known: expected 1 line carrying %q, got %d", tc.reference, tc.cause, got)
				}
			}
		})
	}
}
