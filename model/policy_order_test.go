package model

import (
	"encoding/json"
	"fmt"
	"testing"
)

const policyOrderRepetitions = 50

type namedOperator struct {
	name  string
	value any
}

func (o namedOperator) build(t *testing.T) MetadataPolicyOperator {
	t.Helper()
	switch o.name {
	case "value":
		operator, err := NewValue(o.value)
		requireNoOperatorError(t, o.name, err)
		return *operator
	case "add":
		operator, err := NewAdd(o.value)
		requireNoOperatorError(t, o.name, err)
		return *operator
	case "default":
		operator, err := NewDefault(o.value)
		requireNoOperatorError(t, o.name, err)
		return *operator
	case "one_of":
		operator, err := NewOneOf(o.value)
		requireNoOperatorError(t, o.name, err)
		return *operator
	case "subset_of":
		operator, err := NewSubsetOf(o.value)
		requireNoOperatorError(t, o.name, err)
		return *operator
	case "superset_of":
		operator, err := NewSupersetOf(o.value)
		requireNoOperatorError(t, o.name, err)
		return *operator
	case "essential":
		operator, err := NewEssential(o.value)
		requireNoOperatorError(t, o.name, err)
		return *operator
	default:
		t.Fatalf("unknown operator %q", o.name)
		return nil
	}
}

func requireNoOperatorError(t *testing.T, name string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected no error creating %s operator, got %q", name, err.Error())
	}
}

func operatorSubsets(operators []namedOperator) [][]namedOperator {
	var subsets [][]namedOperator
	for mask := 1; mask < 1<<len(operators); mask++ {
		var subset []namedOperator
		for i, operator := range operators {
			if mask&(1<<i) != 0 {
				subset = append(subset, operator)
			}
		}
		subsets = append(subsets, subset)
	}
	return subsets
}

func operatorsJSON(t *testing.T, operators []namedOperator) string {
	t.Helper()
	object := map[string]any{}
	for _, operator := range operators {
		object[operator.name] = operator.value
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("expected no error marshalling operators, got %q", err.Error())
	}
	return string(encoded)
}

func leafMetadata(key string, existing any) map[string]any {
	metadata := map[string]any{
		"client_id":     "https://leaf.example.com",
		"redirect_uris": []any{"https://leaf.example.com/callback"},
	}
	if existing != nil {
		metadata[key] = existing
	}
	return metadata
}

func outcome(statement *EntityStatement, key string, err error) string {
	if err != nil {
		return "error"
	}
	value, ok := (*statement.Metadata.OpenIDRelyingPartyMetadata)[key]
	if !ok {
		return "absent"
	}
	return fmt.Sprintf("%v", value)
}

func expectedOutcome(t *testing.T, key string, existing any, operators []namedOperator) string {
	t.Helper()
	ordered := make([]MetadataPolicyOperator, 0, len(operators))
	for _, operator := range operators {
		ordered = append(ordered, operator.build(t))
	}
	metadata := OpenIDRelyingPartyMetadata(leafMetadata(key, existing))
	subject := EntityStatement{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &metadata}}
	policy := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{key: {Metadata: ordered}}}
	result, err := ApplyPolicy(subject, policy)
	return outcome(result, key, err)
}

func resolvedOutcome(t *testing.T, key string, existing any, operators []namedOperator, intermediate bool) string {
	t.Helper()
	leaf, err := json.Marshal(map[string]any{
		"iss":             "https://leaf.example.com",
		"sub":             "https://leaf.example.com",
		"iat":             1,
		"exp":             9999999999,
		"jwks":            map[string]any{"keys": []any{}},
		"authority_hints": []any{"https://ta.example.com"},
		"metadata":        map[string]any{"openid_relying_party": leafMetadata(key, existing)},
	})
	if err != nil {
		t.Fatalf("expected no error marshalling leaf, got %q", err.Error())
	}
	statements := []string{string(leaf)}
	if intermediate {
		statements = append(statements, `{"iss":"https://intermediate.example.com","sub":"https://leaf.example.com","iat":1,"exp":9999999999,"jwks":{"keys":[]},"metadata_policy":{"openid_relying_party":{"response_types":{"value":["code"]}}}}`)
	}
	statements = append(statements,
		fmt.Sprintf(`{"iss":"https://ta.example.com","sub":"https://leaf.example.com","iat":1,"exp":9999999999,"jwks":{"keys":[]},"metadata_policy":{"openid_relying_party":{%q:%s}}}`, key, operatorsJSON(t, operators)),
		`{"iss":"https://ta.example.com","sub":"https://ta.example.com","iat":1,"exp":9999999999,"jwks":{"keys":[]}}`,
	)

	chain := make([]EntityStatement, 0, len(statements))
	for _, raw := range statements {
		var statement EntityStatement
		if err := json.Unmarshal([]byte(raw), &statement); err != nil {
			return "policy error"
		}
		chain = append(chain, statement)
	}
	policy, err := ProcessAndExtractPolicy(chain)
	if err != nil {
		return "policy error"
	}
	result, err := ApplyPolicy(chain[0], *policy)
	return outcome(result, key, err)
}

func TestPolicyOperatorsApplyInSpecOrderWhateverTheParseOrder(t *testing.T) {
	arrayOperators := []namedOperator{
		{"value", []any{"a", "b"}},
		{"add", []any{"a"}},
		{"default", []any{"a", "x"}},
		{"subset_of", []any{"a", "b", "c"}},
		{"superset_of", []any{"a"}},
		{"essential", true},
	}
	stringOperators := []namedOperator{
		{"value", "private_key_jwt"},
		{"default", "private_key_jwt"},
		{"one_of", []any{"private_key_jwt", "tls_client_auth"}},
		{"essential", true},
	}
	parameters := []struct {
		key       string
		operators []namedOperator
		present   any
	}{
		{"grant_types", arrayOperators, []any{"b", "c"}},
		{"scope", arrayOperators, "b c"},
		{"token_endpoint_auth_method", stringOperators, "tls_client_auth"},
	}

	for _, parameter := range parameters {
		for _, existing := range []any{nil, parameter.present} {
			for _, operators := range operatorSubsets(parameter.operators) {
				for _, intermediate := range []bool{false, true} {
					names := make([]string, 0, len(operators))
					for _, operator := range operators {
						names = append(names, operator.name)
					}
					name := fmt.Sprintf("%s/existing=%v/%v/intermediate=%v", parameter.key, existing, names, intermediate)
					t.Run(name, func(t *testing.T) {
						expected := expectedOutcome(t, parameter.key, existing, operators)
						for i := 0; i < policyOrderRepetitions; i++ {
							if got := resolvedOutcome(t, parameter.key, existing, operators, intermediate); got != expected {
								t.Fatalf("run %d: expected %s, got %s", i, expected, got)
							}
						}
					})
				}
			}
		}
	}
}

func forbiddenCombinations() map[string]struct {
	key       string
	operators []namedOperator
} {
	return map[string]struct {
		key       string
		operators []namedOperator
	}{
		"value null with default":                     {"grant_types", []namedOperator{{"value", nil}, {"default", []any{"a"}}}},
		"value null with essential true":              {"grant_types", []namedOperator{{"value", nil}, {"essential", true}}},
		"add not a subset of value":                   {"grant_types", []namedOperator{{"value", []any{"a"}}, {"add", []any{"b"}}}},
		"value not a subset of subset_of":             {"grant_types", []namedOperator{{"value", []any{"a"}}, {"subset_of", []any{"b"}}}},
		"value not a superset of superset_of":         {"grant_types", []namedOperator{{"value", []any{"a"}}, {"superset_of", []any{"b"}}}},
		"add not a subset of subset_of":               {"grant_types", []namedOperator{{"add", []any{"x"}}, {"subset_of", []any{"a"}}}},
		"subset_of not a superset of superset_of":     {"grant_types", []namedOperator{{"subset_of", []any{"a"}}, {"superset_of", []any{"b"}}}},
		"subset_of covering only part of superset_of": {"grant_types", []namedOperator{{"subset_of", []any{"a"}}, {"superset_of", []any{"a", "b"}}}},
		"value not among one_of":                      {"token_endpoint_auth_method", []namedOperator{{"value", "x"}, {"one_of", []any{"y"}}}},
	}
}

func TestForbiddenOperatorCombinationsAlwaysProduceAPolicyError(t *testing.T) {
	for name, tt := range forbiddenCombinations() {
		for _, intermediate := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/intermediate=%v", name, intermediate), func(t *testing.T) {
				for i := 0; i < policyOrderRepetitions; i++ {
					if got := resolvedOutcome(t, tt.key, nil, tt.operators, intermediate); got != "policy error" {
						t.Fatalf("run %d: expected a policy error, got %s", i, got)
					}
				}
			})
		}
	}
}
