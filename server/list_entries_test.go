package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type mapListRetriever struct {
	TestRetriever
	subordinates map[model.EntityIdentifier]*model.SubordinateConfiguration
}

func (r mapListRetriever) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return r.subordinates, nil
}

type omissionLine struct {
	Level                string `json:"level"`
	Msg                  string `json:"msg"`
	NotEntityIdentifiers int    `json:"not_entity_identifiers"`
	Duplicates           int    `json:"duplicates"`
}

func omissionLines(t *testing.T, logs string) []omissionLine {
	t.Helper()
	var lines []omissionLine
	for _, raw := range strings.Split(strings.TrimSpace(logs), "\n") {
		if raw == "" {
			continue
		}
		var line omissionLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("failed to read a log line %q: %v", raw, err)
		}
		if strings.HasPrefix(line.Msg, "omitting") {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestServer_List_ServesOnlyEntityIdentifiersEachOnce(t *testing.T) {
	const (
		rp = "https://rp.example.com"
		op = "https://op.example.com"
	)
	valid := &model.SubordinateConfiguration{}

	tests := []struct {
		name         string
		listed       []model.EntityIdentifier
		stored       map[model.EntityIdentifier]*model.SubordinateConfiguration
		want         []string
		ordered      bool
		invalid      int
		duplicates   int
		wantOmission bool
	}{
		{
			name:    "a listing of entity identifiers only",
			listed:  []model.EntityIdentifier{rp, op},
			want:    []string{rp, op},
			ordered: true,
		},
		{
			name:         "a listing with values that are not entity identifiers among them",
			listed:       []model.EntityIdentifier{"http://plain.example.org", rp, "", "not a url", "https://q.example.com?x=1", "https://f.example.com#f", "https://user@u.example.com", "https://", op},
			want:         []string{rp, op},
			ordered:      true,
			invalid:      7,
			wantOmission: true,
		},
		{
			name:         "a listing that repeats an entity identifier",
			listed:       []model.EntityIdentifier{rp, op, rp, rp},
			want:         []string{rp, op},
			ordered:      true,
			duplicates:   2,
			wantOmission: true,
		},
		{
			name:         "a listing that repeats a value that is not an entity identifier",
			listed:       []model.EntityIdentifier{"http://plain.example.org", "http://plain.example.org", rp},
			want:         []string{rp},
			ordered:      true,
			invalid:      2,
			wantOmission: true,
		},
		{
			name:    "a listing with two different spellings, which are different strings",
			listed:  []model.EntityIdentifier{rp, "https://RP.example.com"},
			want:    []string{rp, "https://RP.example.com"},
			ordered: true,
		},
		{
			name:   "an empty listing",
			listed: []model.EntityIdentifier{},
			want:   []string{},
		},
		{
			name:   "the store's subordinates, all with a record",
			stored: map[model.EntityIdentifier]*model.SubordinateConfiguration{rp: valid, op: valid},
			want:   []string{rp, op},
		},
		{
			name:   "the store's subordinates, one with a nil record as a listing placeholder, since /fetch asks GetSubordinate",
			stored: map[model.EntityIdentifier]*model.SubordinateConfiguration{rp: valid, op: nil},
			want:   []string{rp, op},
		},
		{
			name:         "the store's subordinates, one that is not an entity identifier",
			stored:       map[model.EntityIdentifier]*model.SubordinateConfiguration{rp: valid, "http://plain.example.org": valid},
			want:         []string{rp},
			invalid:      1,
			wantOmission: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var retriever model.Retriever = &testListingRetriever{result: tc.listed}
			if tc.stored != nil {
				retriever = mapListRetriever{subordinates: tc.stored}
			}
			var logs bytes.Buffer
			ts := startListServer(t, model.ServerConfiguration{
				IntermediateConfiguration: &model.IntermediateConfiguration{},
				MetadataRetriever:         retriever,
				Configuration:             model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, nil))},
			})

			response, err := ts.Client().Get(ts.URL + "/list")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("[8.2.2] expected 200, got %d %s", response.StatusCode, raw)
			}
			var got []string
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("[8.2.2] expected a JSON array, got %s", raw)
			}
			if !tc.ordered {
				slices.Sort(got)
				slices.Sort(tc.want)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("[8.2.2] expected the known entity identifiers %q, each once and in the store's order, got %q", tc.want, got)
			}

			lines := omissionLines(t, logs.String())
			if !tc.wantOmission {
				if len(lines) != 0 {
					t.Errorf("expected nothing logged as omitted, got %+v", lines)
				}
				return
			}
			invalid, duplicates := 0, 0
			for _, line := range lines {
				if line.Level != "ERROR" {
					t.Errorf("expected an omission logged at Error, because the store is this deployment's own, got %+v", line)
				}
				invalid += line.NotEntityIdentifiers
				duplicates += line.Duplicates
			}
			if len(lines) != 1 {
				t.Errorf("expected one line for the response, not one per entry, got %+v", lines)
			}
			if invalid != tc.invalid || duplicates != tc.duplicates {
				t.Errorf("expected %d values that are not entity identifiers and %d duplicates logged, got %d and %d", tc.invalid, tc.duplicates, invalid, duplicates)
			}
		})
	}
}
