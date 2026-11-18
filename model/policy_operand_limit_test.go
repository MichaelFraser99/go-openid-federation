package model

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func chainWithOperandLevels(t *testing.T, operator string, levels ...[]any) []EntityStatement {
	t.Helper()
	chain := []EntityStatement{{Iss: "https://leaf.example.com", Sub: "https://leaf.example.com"}}
	for i, operands := range levels {
		built, err := parsePolicyOperator(operator, operands)
		if err != nil {
			t.Fatalf("failed to build the %s operator: %v", operator, err)
		}
		sub := EntityIdentifier("https://leaf.example.com")
		if i > 0 {
			sub = EntityIdentifier(fmt.Sprintf("https://superior%d.example.com", i))
		}
		chain = append(chain, EntityStatement{
			Iss: EntityIdentifier(fmt.Sprintf("https://superior%d.example.com", i+1)),
			Sub: sub,
			MetadataPolicy: &MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{
				"contacts": {Metadata: []MetadataPolicyOperator{built}},
			}},
		})
	}
	return chain
}

func operandsNamed(prefix string, count int) []any {
	operands := make([]any, count)
	for i := range operands {
		operands[i] = fmt.Sprintf("%s%d@example.com", prefix, i)
	}
	return operands
}

func mergedOperandCount(t *testing.T, policy *MetadataPolicy) int {
	t.Helper()
	operators := policy.OpenIDRelyingPartyMetadata["contacts"].Metadata
	if len(operators) != 1 {
		t.Fatalf("expected one merged operator, got %d", len(operators))
	}
	return len(operators[0].OperatorValue().([]any))
}

func TestConfiguration_ProcessAndExtractPolicy_BoundsTheOperandsAMergedOperatorHolds(t *testing.T) {
	cfg := Configuration{MaxStatementValues: 5}

	for _, operator := range []string{"add", "superset_of"} {
		tests := map[string]struct {
			levels  [][]any
			refused bool
			holds   int
		}{
			"a union of exactly the limit": {
				levels: [][]any{operandsNamed("a", 3), operandsNamed("b", 2)},
				holds:  5,
			},
			"a union one over the limit": {
				levels:  [][]any{operandsNamed("a", 3), operandsNamed("b", 3)},
				refused: true,
			},
			"repeated operands that keep the union at the limit": {
				levels: [][]any{operandsNamed("a", 5), operandsNamed("a", 5), operandsNamed("a", 5)},
				holds:  5,
			},
			"a union that passes the limit at the third level": {
				levels:  [][]any{operandsNamed("a", 2), operandsNamed("b", 2), operandsNamed("c", 2)},
				refused: true,
			},
		}

		for name, tc := range tests {
			t.Run(operator+", "+name, func(t *testing.T) {
				policy, err := cfg.ProcessAndExtractPolicy(chainWithOperandLevels(t, operator, tc.levels...))
				if !tc.refused {
					if err != nil {
						t.Fatalf("expected the policy to merge, got %v", err)
					}
					if got := mergedOperandCount(t, policy); got != tc.holds {
						t.Errorf("expected the merged operator to hold %d operands, got %d", tc.holds, got)
					}
					return
				}
				if !errors.Is(err, ErrLimitReached) {
					t.Fatalf("expected a limit error, got %v", err)
				}
				if !strings.Contains(err.Error(), "holds more than 5 operands") {
					t.Errorf("expected the error to name the bound, got %v", err)
				}
				if strings.Contains(err.Error(), "contacts") {
					t.Errorf("expected the error to name no parameter a peer chose, got %v", err)
				}
			})
		}
	}
}

func TestConfiguration_ProcessAndExtractPolicy_HoldsANarrowingOperatorToTheStatementBound(t *testing.T) {
	cfg := Configuration{MaxStatementValues: 5}
	policy, err := cfg.ProcessAndExtractPolicy(chainWithOperandLevels(t, "subset_of", operandsNamed("a", 5), operandsNamed("a", 5)))
	if err != nil {
		t.Fatalf("expected subset_of at the bound to merge, got %v", err)
	}
	if got := mergedOperandCount(t, policy); got != 5 {
		t.Errorf("expected the intersection of five operands, got %d", got)
	}

	_, err = cfg.ProcessAndExtractPolicy(chainWithOperandLevels(t, "subset_of", operandsNamed("a", 6), operandsNamed("a", 6)))
	if !errors.Is(err, ErrLimitReached) {
		t.Fatalf("expected subset_of over the bound to be refused, since no statement holds more values than the bound, got %v", err)
	}
}

func TestProcessAndExtractPolicy_BoundsTheMergedOperandsByDefault(t *testing.T) {
	tests := map[string]struct {
		second  int
		refused bool
	}{
		"a union of the default bound": {second: 1_000},
		"a union one over the default": {second: 1_001, refused: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ProcessAndExtractPolicy(chainWithOperandLevels(t, "add", operandsNamed("a", 9_000), operandsNamed("b", tc.second)))
			if tc.refused != errors.Is(err, ErrLimitReached) {
				t.Fatalf("expected refused=%v at the default of %d, got %v", tc.refused, DefaultMaxStatementValues, err)
			}
			if !tc.refused && err != nil {
				t.Fatalf("expected the policy to merge, got %v", err)
			}
		})
	}
}

func TestMergePolicyOperators_BoundsTheMergedOperandsByDefault(t *testing.T) {
	first, err := NewAdd(operandsNamed("a", DefaultMaxStatementValues))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewAdd(operandsNamed("b", 1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = MergePolicyOperators("contacts", PolicyOperators{Metadata: []MetadataPolicyOperator{*first}}, PolicyOperators{Metadata: []MetadataPolicyOperator{*second}})
	if !errors.Is(err, ErrLimitReached) {
		t.Fatalf("expected a limit error, got %v", err)
	}
}

type spreadLevel struct {
	entityTypes []string
	parameters  int
	operands    int
	prefix      string
	operator    string
}

func chainWithSpreadLevels(t *testing.T, levels ...spreadLevel) []EntityStatement {
	t.Helper()
	chain := []EntityStatement{{Iss: "https://leaf.example.com", Sub: "https://leaf.example.com"}}
	for i, level := range levels {
		operator := level.operator
		if operator == "" {
			operator = "add"
		}
		policy := &MetadataPolicy{}
		for _, entityType := range level.entityTypes {
			parameters := map[string]PolicyOperators{}
			for p := range level.parameters {
				built, err := parsePolicyOperator(operator, operandsNamed(fmt.Sprintf("%s-%s-%d-", level.prefix, entityType, p), level.operands))
				if err != nil {
					t.Fatalf("failed to build the %s operator: %v", operator, err)
				}
				parameters[fmt.Sprintf("parameter%d", p)] = PolicyOperators{Metadata: []MetadataPolicyOperator{built}}
			}
			policy.setEntityType(entityType, parameters)
		}
		sub := EntityIdentifier("https://leaf.example.com")
		if i > 0 {
			sub = EntityIdentifier(fmt.Sprintf("https://superior%d.example.com", i))
		}
		chain = append(chain, EntityStatement{Iss: EntityIdentifier(fmt.Sprintf("https://superior%d.example.com", i+1)), Sub: sub, MetadataPolicy: policy})
	}
	return chain
}

func TestConfiguration_ProcessAndExtractPolicy_BoundsTheOperandsTheWholeMergedPolicyHolds(t *testing.T) {
	cfg := Configuration{MaxStatementValues: 10}
	relyingParty := []string{"openid_relying_party"}

	tests := map[string]struct {
		levels  []spreadLevel
		refused bool
	}{
		"many parameters, each under the bound, over it in total": {
			levels: []spreadLevel{
				{entityTypes: relyingParty, parameters: 4, operands: 2, prefix: "first"},
				{entityTypes: relyingParty, parameters: 4, operands: 2, prefix: "second"},
			},
			refused: true,
		},
		"parameters spread across entity types, an extension type included": {
			levels: []spreadLevel{
				{entityTypes: []string{"openid_relying_party", "federation_entity", "x_custom"}, parameters: 1, operands: 2, prefix: "first"},
				{entityTypes: []string{"openid_relying_party", "federation_entity", "x_custom"}, parameters: 1, operands: 2, prefix: "second"},
			},
			refused: true,
		},
		"an extension type that alone passes the bound in total": {
			levels: []spreadLevel{
				{entityTypes: []string{"x_custom"}, parameters: 3, operands: 2, prefix: "first"},
				{entityTypes: []string{"x_custom"}, parameters: 3, operands: 2, prefix: "second"},
			},
			refused: true,
		},
		"superset_of spread over many parameters": {
			levels: []spreadLevel{
				{entityTypes: relyingParty, parameters: 4, operands: 2, prefix: "first", operator: "superset_of"},
				{entityTypes: relyingParty, parameters: 4, operands: 2, prefix: "second", operator: "superset_of"},
			},
			refused: true,
		},
		"repeated operands that keep the total at the bound": {
			levels: []spreadLevel{
				{entityTypes: relyingParty, parameters: 2, operands: 5, prefix: "same"},
				{entityTypes: relyingParty, parameters: 2, operands: 5, prefix: "same"},
				{entityTypes: relyingParty, parameters: 2, operands: 5, prefix: "same"},
			},
		},
		"a total one over the bound": {
			levels: []spreadLevel{
				{entityTypes: relyingParty, parameters: 1, operands: 5, prefix: "first"},
				{entityTypes: relyingParty, parameters: 1, operands: 6, prefix: "second"},
			},
			refused: true,
		},
		"a single level over the bound on its own": {
			levels: []spreadLevel{
				{entityTypes: relyingParty, parameters: 1, operands: 11, prefix: "first"},
			},
			refused: true,
		},
		"narrowing operators count towards the total": {
			levels: []spreadLevel{
				{entityTypes: relyingParty, parameters: 3, operands: 4, prefix: "same", operator: "subset_of"},
				{entityTypes: relyingParty, parameters: 3, operands: 4, prefix: "same", operator: "subset_of"},
			},
			refused: true,
		},
		"narrowing operators within the total": {
			levels: []spreadLevel{
				{entityTypes: relyingParty, parameters: 2, operands: 5, prefix: "same", operator: "subset_of"},
				{entityTypes: relyingParty, parameters: 2, operands: 5, prefix: "same", operator: "subset_of"},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := cfg.ProcessAndExtractPolicy(chainWithSpreadLevels(t, tc.levels...))
			if !tc.refused {
				if err != nil {
					t.Fatalf("expected the policy to merge, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrLimitReached) {
				t.Fatalf("[#153] expected the total to be refused as a limit, got %v", err)
			}
			if !strings.Contains(err.Error(), "more than 10 operands") {
				t.Errorf("expected the error to name the bound, got %v", err)
			}
			for _, chosen := range []string{"parameter0", "openid_relying_party", "x_custom"} {
				if strings.Contains(err.Error(), chosen) {
					t.Errorf("expected the error to name nothing a peer chose, got %v", err)
				}
			}
		})
	}
}
