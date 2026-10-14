package model

import (
	"encoding/json"
	"fmt"
	"testing"
)

func resolvedOutcomeForShape(t *testing.T, key string, operators []namedOperator, shape string) string {
	t.Helper()
	policyJSON := fmt.Sprintf(`"metadata_policy":{"openid_relying_party":{%q:%s}}`, key, operatorsJSON(t, operators))
	metadataJSON := `"metadata":{"openid_relying_party":{"client_id":"https://leaf.example.com","redirect_uris":["https://leaf.example.com/callback"]}}`

	var statements []string
	switch shape {
	case "subject policy":
		statements = []string{
			fmt.Sprintf(`{"iss":"https://leaf.example.com","sub":"https://leaf.example.com","iat":1,"exp":9999999999,"jwks":{"keys":[]},%s,%s}`, metadataJSON, policyJSON),
			`{"iss":"https://ta.example.com","sub":"https://leaf.example.com","iat":1,"exp":9999999999,"jwks":{"keys":[]}}`,
			`{"iss":"https://ta.example.com","sub":"https://ta.example.com","iat":1,"exp":9999999999,"jwks":{"keys":[]}}`,
		}
	case "single statement chain":
		statements = []string{
			fmt.Sprintf(`{"iss":"https://leaf.example.com","sub":"https://leaf.example.com","iat":1,"exp":9999999999,"jwks":{"keys":[]},%s,%s}`, metadataJSON, policyJSON),
		}
	default:
		t.Fatalf("unknown shape %q", shape)
	}

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
	if policy == nil {
		return "no policy"
	}
	result, err := ApplyPolicy(chain[0], *policy)
	return outcome(result, key, err)
}

func TestForbiddenCombinationsOnSkippedStatementsProduceAPolicyError(t *testing.T) {
	for name, tt := range forbiddenCombinations() {
		for _, shape := range []string{"subject policy", "single statement chain"} {
			t.Run(fmt.Sprintf("%s/%s", name, shape), func(t *testing.T) {
				for i := 0; i < policyOrderRepetitions; i++ {
					if got := resolvedOutcomeForShape(t, tt.key, tt.operators, shape); got != "policy error" {
						t.Fatalf("run %d: expected a policy error, got %s", i, got)
					}
				}
			})
		}
	}
}
