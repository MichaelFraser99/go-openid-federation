package model

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

type TestData struct {
	N                int            `json:"n"`
	Combination      []string       `json:"combination"`
	TA               map[string]any `json:"TA"`
	INT              map[string]any `json:"INT"`
	Merged           map[string]any `json:"merged"`
	Metadata         map[string]any `json:"metadata"`
	Resolved         map[string]any `json:"resolved"`
	Error            string         `json:"error"`
	ErrorDescription string         `json:"error_description"`
}

func TestMetadataProcessingE2E(t *testing.T) {
	data, err := os.ReadFile("metadata-policy-test-vectors-2025-02-13.json")
	if err != nil {
		t.Fatalf("Failed to read test vectors file: %v", err)
	}

	var testCases []TestData
	if err = json.Unmarshal(data, &testCases); err != nil {
		t.Fatalf("Failed to parse test vectors: %v", err)
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d - %s", tc.N, tc.Combination), func(t *testing.T) {
			bTa, err := json.Marshal(tc.TA)
			if err != nil {
				t.Fatalf("Failed to marshal TA: %v", err)
			}
			bInt, err := json.Marshal(tc.INT)
			if err != nil {
				t.Fatalf("Failed to marshal INT: %v", err)
			}

			var parsedTa, parsedInt map[string]PolicyOperators

			if err = json.Unmarshal(bTa, &parsedTa); err != nil {
				t.Fatalf("Failed to unmarshal TA: %v", err)
			}

			if err = json.Unmarshal(bInt, &parsedInt); err != nil {
				t.Fatalf("Failed to unmarshal TA: %v", err)
			}

			trustChain := []EntityStatement{
				{
					MetadataPolicy: &MetadataPolicy{
						FederationMetadata: parsedInt,
					},
				},
				{
					MetadataPolicy: &MetadataPolicy{
						FederationMetadata: parsedTa,
					},
				},
			}

			mergedPolicy, err := ProcessAndExtractPolicy(trustChain)
			if tc.Error == "invalid_policy" {
				if err == nil {
					t.Errorf("Should have errored with \ncode: %q \nreason: %q", tc.Error, tc.ErrorDescription)
				} else {
					t.Logf("Test case expected \nerror: %q \nreason: %q \ngot: %q", tc.Error, tc.ErrorDescription, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Failed to process policy: %v", err)
				}

				mergedPolicyBytes, err := json.Marshal(mergedPolicy)
				if err != nil {
					t.Fatalf("Failed to marshal finalPolicy: %v", err)
				}

				var mergedPolicyMap map[string]any
				if err := json.Unmarshal(mergedPolicyBytes, &mergedPolicyMap); err != nil {
					t.Fatalf("Failed to unmarshal finalPolicy: %v", err)
				}

				if diff := cmp.Diff(map[string]any{"federation_entity": tc.Merged}, mergedPolicyMap, cmpopts.SortSlices(func(x, y any) bool {
					if sx, ok := x.(string); ok {
						if sy, ok := y.(string); ok {
							return sx < sy
						}
					}
					return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
				})); diff != "" {
					t.Errorf("mismatch on merged policy (-expected +got):\n%s", diff)
				}

				finalMetadata, err := ApplyPolicy(EntityStatement{
					Metadata: &Metadata{
						FederationMetadata: (*FederationMetadata)(Pointer(tc.Metadata)),
					},
				}, *mergedPolicy)

				if tc.Error != "" {
					if err == nil {
						t.Errorf("Should have errored with \ncode: %q \nreason: %q", tc.Error, tc.ErrorDescription)
					} else {
						t.Logf("Test case expected \nerror: %q \nreason: %q \ngot: %q", tc.Error, tc.ErrorDescription, err.Error())
					}
				} else {
					if err != nil {
						t.Fatalf("Failed to apply policy: %v", err)
					}

					finalMetadataBytes, err := json.Marshal(finalMetadata)
					if err != nil {
						t.Fatalf("Failed to marshal finalMetadata: %v", err)
					}

					var finalMetadataMap map[string]any
					if err := json.Unmarshal(finalMetadataBytes, &finalMetadataMap); err != nil {
						t.Fatalf("Failed to unmarshal finalMetadata: %v", err)
					}

					finalMetadataMap = finalMetadataMap["metadata"].(map[string]any)

					if diff := cmp.Diff(map[string]any{"federation_entity": tc.Resolved}, finalMetadataMap, cmpopts.SortSlices(func(x, y any) bool {
						if sx, ok := x.(string); ok {
							if sy, ok := y.(string); ok {
								return sx < sy
							}
						}
						return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
					})); diff != "" {
						t.Errorf("mismatch on final metadata (-expected +got):\n%s", diff)
					}
				}
			}
		})
	}
}
