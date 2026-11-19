package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func inMemoryListServer(t *testing.T, identifiers []model.EntityIdentifier, logs *bytes.Buffer) *Server {
	t.Helper()
	intermediate := &model.IntermediateConfiguration{}
	for _, identifier := range identifiers {
		intermediate.AddSubordinate(identifier, &model.SubordinateConfiguration{})
	}
	cfg := model.ServerConfiguration{IntermediateConfiguration: intermediate}
	if logs != nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(logs, nil))
	}
	return mustNewServer(t, cfg)
}

func listOnce(t *testing.T, server *Server) []string {
	t.Helper()
	mux := http.NewServeMux()
	server.Configure(mux)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/list", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("[8.2.2] expected 200, got %d %s", recorder.Code, recorder.Body.String())
	}
	var listed []string
	if err := json.Unmarshal(recorder.Body.Bytes(), &listed); err != nil {
		t.Fatalf("[8.2.2] expected a JSON array, got %s", recorder.Body.String())
	}
	return listed
}

func TestServer_List_TheInMemoryStoreServesItsEntityIdentifiersInSortedOrder(t *testing.T) {
	tests := []struct {
		name    string
		added   []model.EntityIdentifier
		want    []string
		invalid int
	}{
		{name: "entity identifiers added out of order", added: []model.EntityIdentifier{"https://c.example.com", "https://a.example.com", "https://b.example.com"}, want: []string{"https://a.example.com", "https://b.example.com", "https://c.example.com"}},
		{name: "values that are not entity identifiers among them", added: []model.EntityIdentifier{"https://b.example.com", "http://plain.example.org", "not a url", "https://a.example.com"}, want: []string{"https://a.example.com", "https://b.example.com"}, invalid: 2},
		{name: "the same identifier added twice", added: []model.EntityIdentifier{"https://a.example.com", "https://a.example.com"}, want: []string{"https://a.example.com"}},
		{name: "an empty store", want: []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			listed := listOnce(t, inMemoryListServer(t, tc.added, &logs))

			if !slices.Equal(listed, tc.want) {
				t.Errorf("[8.2.2] expected %q, got %q", tc.want, listed)
			}
			lines := omissionLines(t, logs.String())
			if tc.invalid == 0 {
				if len(lines) != 0 {
					t.Errorf("expected nothing logged as omitted, got %+v", lines)
				}
				return
			}
			if len(lines) != 1 || lines[0].Level != "ERROR" || lines[0].NotEntityIdentifiers != tc.invalid {
				t.Errorf("expected one Error line naming %d values that are not entity identifiers, got %+v", tc.invalid, lines)
			}
		})
	}
}

func TestServer_List_TheInMemoryListingFollowsTheStore(t *testing.T) {
	var logs bytes.Buffer
	intermediate := &model.IntermediateConfiguration{}
	intermediate.AddSubordinate("https://b.example.com", &model.SubordinateConfiguration{})
	intermediate.AddSubordinate("http://flushed.example.org", &model.SubordinateConfiguration{})
	server := mustNewServer(t, model.ServerConfiguration{IntermediateConfiguration: intermediate, Configuration: model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, nil))}})

	if got := listOnce(t, server); !slices.Equal(got, []string{"https://b.example.com"}) {
		t.Fatalf("expected the first subordinate listed, got %q", got)
	}
	intermediate.AddSubordinate("https://a.example.com", &model.SubordinateConfiguration{})
	if got := listOnce(t, server); !slices.Equal(got, []string{"https://a.example.com", "https://b.example.com"}) {
		t.Errorf("expected a subordinate added after a listing to be listed, got %q", got)
	}
	intermediate.FlushCache()
	logs.Reset()
	if got := listOnce(t, server); len(got) != 0 {
		t.Errorf("expected a flushed store to list nothing, got %q", got)
	}
	if lines := omissionLines(t, logs.String()); len(lines) != 0 {
		t.Errorf("expected nothing logged as omitted once the store is flushed, got %+v", lines)
	}
	intermediate.AddSubordinate("http://plain.example.org", &model.SubordinateConfiguration{})
	intermediate.AddSubordinate("https://c.example.com", &model.SubordinateConfiguration{})
	if got := listOnce(t, server); !slices.Equal(got, []string{"https://c.example.com"}) {
		t.Errorf("expected only the entity identifier listed after a flush, got %q", got)
	}
}

func TestServer_List_TheInMemoryListingCostsNoAllocationPerSubordinate(t *testing.T) {
	allocations := func(count int) float64 {
		identifiers := make([]model.EntityIdentifier, count)
		for i := range identifiers {
			identifiers[i] = model.EntityIdentifier(fmt.Sprintf("https://sub%d.example.com", i))
		}
		mux := http.NewServeMux()
		inMemoryListServer(t, identifiers, nil).Configure(mux)
		request := httptest.NewRequest(http.MethodGet, "/list", nil)
		return testing.AllocsPerRun(20, func() {
			mux.ServeHTTP(httptest.NewRecorder(), request)
		})
	}

	small, large := allocations(10), allocations(2_000)
	if large-small > 100 {
		t.Errorf("expected the allocations of /list over the in-memory store not to grow with each subordinate, got %.0f for 10 and %.0f for 2000", small, large)
	}
}
