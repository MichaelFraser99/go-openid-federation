package model

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

func singleLogRecord(t *testing.T, raw string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one record, got %d: %s", len(lines), raw)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("failed to parse the record: %v", err)
	}
	return record
}

func rawSetOf(keys ...map[string]any) map[string]any {
	entries := make([]any, len(keys))
	for i, key := range keys {
		entries[i] = key
	}
	return map[string]any{"keys": entries}
}

func TestLogPrivateKeyMembers_NamesTheMembersAndBoundsTheKeyIDs(t *testing.T) {
	symmetric := func(kid string) map[string]any {
		return map[string]any{"kid": kid, "kty": "oct", "k": "AQAB"}
	}

	tests := []struct {
		name        string
		reference   string
		keys        []map[string]any
		expectCount float64
		expectNamed int
		expectMembs []any
	}{
		{
			name:        "one key carrying one member",
			reference:   "RFC 7518 6.4.1",
			keys:        []map[string]any{symmetric("one")},
			expectCount: 1,
			expectNamed: 1,
			expectMembs: []any{"k"},
		},
		{
			name:      "two keys carrying three members between them",
			reference: "RFC 7518 6.3.2",
			keys: []map[string]any{
				{"kid": "one", "kty": "RSA", "n": "AQAB", "e": "AQAB", "p": "AQAB", "d": "AQAB"},
				symmetric("two"),
			},
			expectCount: 2,
			expectNamed: 2,
			expectMembs: []any{"d", "k", "p"},
		},
		{
			name:        "eight keys, the cap",
			reference:   "8.9",
			keys:        []map[string]any{symmetric("a"), symmetric("b"), symmetric("c"), symmetric("d"), symmetric("e"), symmetric("f"), symmetric("g"), symmetric("h")},
			expectCount: 8,
			expectNamed: 8,
			expectMembs: []any{"k"},
		},
		{
			name:        "twelve keys, above the cap",
			reference:   "8.9",
			keys:        []map[string]any{symmetric("a"), symmetric("b"), symmetric("c"), symmetric("d"), symmetric("e"), symmetric("f"), symmetric("g"), symmetric("h"), symmetric("i"), symmetric("j"), symmetric("k"), symmetric("l")},
			expectCount: 12,
			expectNamed: 8,
			expectMembs: []any{"k"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			cfg := &Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, nil))}

			LogPrivateKeyMembersInRawSet(context.Background(), cfg, "https://ta.example.com", "https://peer.example.com", rawSetOf(tc.keys...))

			record := singleLogRecord(t, logs.String())
			if record["affected_keys"] != tc.expectCount {
				t.Errorf("[%s] expected affected_keys %v, got %v", tc.reference, tc.expectCount, record["affected_keys"])
			}
			named, _ := record["first_key_ids"].([]any)
			if len(named) != tc.expectNamed {
				t.Errorf("[%s] the key count is peer-controlled, so at most %d may be named, got %d: %v", tc.reference, maxLoggedPrivateKeys, len(named), named)
			}
			members, _ := record["members"].([]any)
			if !slices.Equal(members, tc.expectMembs) {
				t.Errorf("[%s] expected members %v, got %v", tc.reference, tc.expectMembs, members)
			}
			if record["issuer"] != "https://ta.example.com" {
				t.Errorf("[%s] expected the record to name the issuer that published the set, got %v", tc.reference, record["issuer"])
			}
			if record["subject"] != "https://peer.example.com" {
				t.Errorf("[%s] expected the record to name the subject, got %v", tc.reference, record["subject"])
			}
		})
	}
}

func TestLogPrivateKeyMembers_IsSilentWhenThereIsNothingToReport(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		raw       any
	}{
		{name: "a set of public keys", reference: "RFC 7518 6.3.1", raw: rawSetOf(map[string]any{"kid": "one", "kty": "RSA", "n": "AQAB", "e": "AQAB"})},
		{name: "a set with no keys member", reference: "RFC 7517 5", raw: map[string]any{}},
		{name: "a keys member that is not an array", reference: "RFC 7517 5", raw: map[string]any{"keys": "nope"}},
		{name: "an entry that is not an object", reference: "RFC 7517 5", raw: map[string]any{"keys": []any{"nope"}}},
		{name: "a value that is not an object at all", reference: "RFC 7517 5", raw: "nope"},
		{name: "a nil value", reference: "RFC 7517 5", raw: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			cfg := &Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, nil))}

			LogPrivateKeyMembersInRawSet(context.Background(), cfg, "https://ta.example.com", "https://peer.example.com", tc.raw)

			if logs.Len() != 0 {
				t.Errorf("[%s] expected no record, got %s", tc.reference, logs.String())
			}
		})
	}
}

func TestLogPrivateKeyMembers_WithNoConfigurationDoesNotPanic(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("logging with no configuration panicked: %v", recovered)
		}
	}()
	LogPrivateKeyMembers(context.Background(), nil, "https://ta.example.com", "https://peer.example.com", josemodel.Jwks{
		Keys: []map[string]any{{"kid": "one", "kty": "oct", "k": "AQAB"}},
	})
}
