package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type unreachedExtendedListingRetriever struct{ model.ExtendedListingRetriever }

func TestServer_AnExtensionHandlerMountedWithoutItsConfigurationAnswersTheFixedDescription(t *testing.T) {
	tests := []struct {
		name        string
		extensions  model.Extensions
		handler     func(s *Server) func(http.ResponseWriter, *http.Request) ResponseFunc
		description string
		cause       string
	}{
		{
			name:        "the extended listing while disabled",
			extensions:  model.Extensions{ExtendedListing: model.ExtendedListingConfiguration{MetadataRetriever: unreachedExtendedListingRetriever{}, SizeLimit: 10}},
			handler:     func(s *Server) func(http.ResponseWriter, *http.Request) ResponseFunc { return s.ExtendedList },
			description: extendedListingUnavailableError,
			cause:       "extended subordinate listing not enabled",
		},
		{
			name:        "the extended listing with no retriever",
			extensions:  model.Extensions{ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10}},
			handler:     func(s *Server) func(http.ResponseWriter, *http.Request) ResponseFunc { return s.ExtendedList },
			description: extendedListingUnavailableError,
			cause:       "extended subordinate listing metadata retriever not configured",
		},
		{
			name:        "the extended listing with no size limit",
			extensions:  model.Extensions{ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, MetadataRetriever: unreachedExtendedListingRetriever{}}},
			handler:     func(s *Server) func(http.ResponseWriter, *http.Request) ResponseFunc { return s.ExtendedList },
			description: extendedListingUnavailableError,
			cause:       "extended subordinate listing size limit not configured",
		},
		{
			name:        "the subordinate status while disabled",
			extensions:  model.Extensions{SubordinateStatus: model.SubordinateStatusConfiguration{MetadataRetriever: unreachedSubordinateStatusRetriever{}}},
			handler:     func(s *Server) func(http.ResponseWriter, *http.Request) ResponseFunc { return s.SubordinateStatus },
			description: subordinateStatusUnavailableError,
			cause:       "subordinate status not enabled",
		},
		{
			name:        "the subordinate status with no retriever",
			extensions:  model.Extensions{SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true}},
			handler:     func(s *Server) func(http.ResponseWriter, *http.Request) ResponseFunc { return s.SubordinateStatus },
			description: subordinateStatusUnavailableError,
			cause:       "subordinate status metadata retriever not configured",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			s := NewServer(model.ServerConfiguration{
				Configuration:             model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
				EntityIdentifier:          "https://ta.example.com",
				IntermediateConfiguration: &model.IntermediateConfiguration{},
				Extensions:                tc.extensions,
			})
			recorder := httptest.NewRecorder()
			s.handle(tc.handler(s))(recorder, httptest.NewRequest(http.MethodGet, "https://ta.example.com/endpoint", nil))

			var answer map[string]string
			if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
				t.Fatalf("failed to read the error %s: %v", recorder.Body.String(), err)
			}
			if recorder.Code != http.StatusInternalServerError || answer["error"] != model.ServerError || answer["error_description"] != tc.description {
				t.Errorf("[8.9 server_error] expected 500 server_error %q, got %d %s", tc.description, recorder.Code, recorder.Body.String())
			}

			logged := false
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, tc.cause) {
					logged = true
				}
			}
			if !logged {
				t.Errorf("expected the cause %q logged at error level, got %s", tc.cause, logs.String())
			}
		})
	}
}
