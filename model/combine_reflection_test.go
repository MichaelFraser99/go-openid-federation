package model

import (
	"strings"
	"testing"
)

func TestCombineArray_TheOperatorsOwnUnusableOperandIsNotReflected(t *testing.T) {
	const marker = "OPERATOR-SIDE-MARKER"

	unusable := []any{"first", []any{marker}}
	usable := []any{"fine"}

	tests := []struct {
		name      string
		reference string
		merge     func() error
	}{
		{
			name:      "add",
			reference: "8.9",
			merge: func() error {
				_, err := Add{operatorValue: unusable}.Merge(usable)
				return err
			},
		},
		{
			name:      "superset_of",
			reference: "8.9",
			merge: func() error {
				_, err := SupersetOf{operatorValue: unusable}.Merge(usable)
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.merge()
			if err == nil {
				t.Fatalf("[%s] an operand that cannot be keyed must be refused rather than skipped", tc.reference)
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("[%s] the refusal carries an operand a superior chose, which reaches the response description: %v", tc.reference, err)
			}
			if !strings.Contains(err.Error(), "second operator") {
				t.Errorf("[%s] expected the refusal to name which side carried the operand, got %v", tc.reference, err)
			}
		})
	}
}
