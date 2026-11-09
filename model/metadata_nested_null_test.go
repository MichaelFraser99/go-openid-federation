package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestMetadata_MarshalJSON_WritesANestedNullAsParsed(t *testing.T) {
	tests := []struct {
		name       string
		entityType string
		parameters string
	}{
		{name: "a null member of a nested object", entityType: "federation_entity", parameters: `{"nested":{"b":null,"c":"d"}}`},
		{name: "a nested object whose only member is null", entityType: "federation_entity", parameters: `{"nested":{"b":null}}`},
		{name: "a null three objects deep", entityType: "federation_entity", parameters: `{"nested":{"b":{"c":{"d":null}}}}`},
		{name: "a null inside an array", entityType: "federation_entity", parameters: `{"nested":[null,"a"]}`},
		{name: "a null member of an object inside an array", entityType: "federation_entity", parameters: `{"nested":[{"b":null}]}`},
		{name: "a null member of an object inside an array inside an object", entityType: "federation_entity", parameters: `{"nested":{"b":[{"c":null}]}}`},
		{name: "an empty nested object", entityType: "federation_entity", parameters: `{"nested":{}}`},
		{name: "an empty nested array", entityType: "federation_entity", parameters: `{"nested":{"b":[]}}`},
		{name: "a null member of a nested object under an entity type this library does not model", entityType: "x_custom_type", parameters: `{"nested":{"b":null}}`},
		{name: "a null member of a nested object under an entity type this library models with a schema", entityType: "openid_relying_party", parameters: `{"redirect_uris":["https://rp.example.com/cb"],"nested":{"b":null}}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			published := `{"` + tc.entityType + `":` + tc.parameters + `}`
			var metadata Metadata
			if err := json.Unmarshal([]byte(published), &metadata); err != nil {
				t.Fatalf("expected the metadata to parse, got %v", err)
			}
			written, err := json.Marshal(metadata)
			if err != nil {
				t.Fatalf("expected the metadata to marshal, got %v", err)
			}

			var want, got any
			if err := json.Unmarshal([]byte(published), &want); err != nil {
				t.Fatalf("failed to read the published metadata: %v", err)
			}
			if err := json.Unmarshal(written, &got); err != nil {
				t.Fatalf("failed to read the written metadata: %v", err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Errorf("[8.3.2] the written metadata must be the value parsed, want %s, got %s", published, written)
			}
		})
	}
}

func TestMetadata_MarshalJSON_OmitsANullParameterAndKeepsANullBelowIt(t *testing.T) {
	metadata := Metadata{FederationMetadata: &FederationMetadata{
		"absent":   nil,
		"nested":   map[string]any{"b": nil},
		"list":     []string(nil),
		"children": map[string]any{"list": []string(nil)},
	}}

	written, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("expected the metadata to marshal, got %v", err)
	}

	want := `{"federation_entity":{"children":{"list":[]},"list":[],"nested":{"b":null}}}`
	if string(written) != want {
		t.Errorf("[3.2 16] a null parameter is omitted and a null below a parameter is kept, want %s, got %s", want, written)
	}
}
