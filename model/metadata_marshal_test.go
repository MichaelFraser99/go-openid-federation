package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMetadata_MarshalJSON_TypedNestedMaps(t *testing.T) {
	tests := []struct {
		name     string
		metadata OpenIDRelyingPartyMetadata
		expect   string
	}{
		{
			name:     "a nested map of strings",
			metadata: OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://leaf.example.com/cb"}, "claims": map[string]string{"a": "b"}},
			expect:   `"claims":{"a":"b"}`,
		},
		{
			name:     "a nested map of integers",
			metadata: OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://leaf.example.com/cb"}, "limits": map[string]int{"max": 7}},
			expect:   `"limits":{"max":7}`,
		},
		{
			name:     "a nested map with non-string keys",
			metadata: OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://leaf.example.com/cb"}, "codes": map[int]string{1: "one"}},
			expect:   `"codes":{"1":"one"}`,
		},
		{
			name:     "a nested map of any, the shape peer JSON produces",
			metadata: OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://leaf.example.com/cb"}, "claims": map[string]any{"a": "b"}},
			expect:   `"claims":{"a":"b"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			metadata := Metadata{OpenIDRelyingPartyMetadata: &tc.metadata}

			var raw []byte
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("marshalling a typed nested map panicked: %v", r)
					}
				}()
				raw, err = json.Marshal(metadata)
			}()

			if err != nil {
				t.Fatalf("expected the metadata to marshal, got %v", err)
			}
			if !strings.Contains(string(raw), tc.expect) {
				t.Errorf("expected the output to contain %s, got %s", tc.expect, raw)
			}
		})
	}
}
