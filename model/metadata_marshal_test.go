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

func TestProcessAndExtractPolicy_BoundsOperandCount(t *testing.T) {
	buildPolicy := func(n int) string {
		values := make([]string, n)
		for i := range values {
			values[i] = `"v` + string(rune('a'+i%26)) + `-` + string(rune('a'+(i/26)%26)) + `-` + itoa(i) + `"`
		}
		return `{"openid_relying_party":{"contacts":{"subset_of":[` + strings.Join(values, ",") + `]}}}`
	}

	tests := []struct {
		name      string
		count     int
		expectErr string
	}{
		{name: "at the limit", count: MaxPolicyOperandValues},
		{name: "one over the limit", count: MaxPolicyOperandValues + 1, expectErr: "must not carry more than"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var policy MetadataPolicy
			if err := json.Unmarshal([]byte(buildPolicy(tc.count)), &policy); err != nil {
				t.Fatalf("the policy fixture did not parse: %v", err)
			}
			subordinate := EntityStatement{Iss: "https://ta.example.com", Sub: "https://leaf.example.com", MetadataPolicy: &policy}

			_, err := ProcessAndExtractPolicy([]EntityStatement{{}, subordinate, {}})
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("expected a policy at the limit to be accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected a policy over the limit to be refused")
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("expected an error naming the limit, got %v", err)
			}
		})
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	out := ""
	for i > 0 {
		out = string(rune('0'+i%10)) + out
		i /= 10
	}
	return out
}
