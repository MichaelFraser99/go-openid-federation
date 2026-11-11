package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestMarshalJSON_ABuiltInEntityTypeInExtensionsIsRefused(t *testing.T) {
	for _, entityType := range builtInEntityTypes {
		field, known := builtInEntityTypeFields[entityType]
		if !known {
			t.Fatalf("%s is a built-in entity type with no typed field named for it", entityType)
		}
		for _, kind := range []string{"Metadata", "MetadataPolicy"} {
			t.Run(kind+" "+entityType, func(t *testing.T) {
				var value any = Metadata{Extensions: map[string]map[string]any{entityType: {"organization_name": "Example"}}}
				owner := reflect.TypeOf(Metadata{})
				if kind == "MetadataPolicy" {
					value = MetadataPolicy{Extensions: map[string]map[string]PolicyOperators{entityType: {}}}
					owner = reflect.TypeOf(MetadataPolicy{})
				}
				if _, exists := owner.FieldByName(field); !exists {
					t.Fatalf("%s has no field %s for %s", kind, field, entityType)
				}

				_, err := json.Marshal(value)
				if err == nil {
					t.Fatalf("expected %s.Extensions holding %q to be refused, because it would replace %s.%s when written", kind, entityType, kind, field)
				}
				for _, named := range []string{kind + ".Extensions", entityType, kind + "." + field} {
					if !strings.Contains(err.Error(), named) {
						t.Errorf("expected the refusal to name %s, got %v", named, err)
					}
				}
			})
		}
	}
}

func TestMarshalJSON_AnEntityTypeThisLibraryDoesNotModelIsWrittenFromExtensions(t *testing.T) {
	metadata, err := json.Marshal(Metadata{
		FederationMetadata: &FederationMetadata{"organization_name": "Typed"},
		Extensions:         map[string]map[string]any{"x_custom_type": {"p": "a"}},
	})
	if err != nil {
		t.Fatalf("expected metadata with a custom type to be written, got %v", err)
	}
	if !strings.Contains(string(metadata), `"x_custom_type":{"p":"a"}`) || !strings.Contains(string(metadata), `"federation_entity":{"organization_name":"Typed"}`) {
		t.Errorf("expected both the typed and the custom type written, got %s", metadata)
	}

	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(`{"x_custom_type":{"p":{"value":"a"}}}`), &policy); err != nil {
		t.Fatalf("failed to read the policy: %v", err)
	}
	written, err := json.Marshal(policy)
	if err != nil || !strings.Contains(string(written), `"x_custom_type":{"p":{"value":"a"}}`) {
		t.Errorf("expected a policy for a custom type written from Extensions, got %s %v", written, err)
	}
}
