package model

import (
	"encoding/json"
	"testing"
)

type upperList []string

func (u upperList) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]int{"count": len(u)})
}

func TestMetadata_MarshalJSON_WritesATypedValueAsEncodingJSONWould(t *testing.T) {
	tests := map[string]struct {
		value any
		want  string
	}{
		"a json.RawMessage":                     {value: json.RawMessage(`{"a":1}`), want: `{"a":1}`},
		"a byte slice":                          {value: []byte("hi"), want: `"aGk="`},
		"a slice type with its own MarshalJSON": {value: upperList{"a", "b"}, want: `{"count":2}`},
		"a json.RawMessage inside an object":    {value: map[string]any{"inner": json.RawMessage(`[1,2]`)}, want: `{"inner":[1,2]}`},
		"a slice of strings":                    {value: []string{"a", "b"}, want: `["a","b"]`},
		"a typed nil slice":                     {value: []string(nil), want: `[]`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			written, err := json.Marshal(Metadata{FederationMetadata: &FederationMetadata{"parameter": tc.value}})
			if err != nil {
				t.Fatalf("expected the metadata to be written, got %v", err)
			}
			want := `{"federation_entity":{"parameter":` + tc.want + `}}`
			if string(written) != want {
				t.Errorf("expected %s, got %s", want, written)
			}
		})
	}
}
