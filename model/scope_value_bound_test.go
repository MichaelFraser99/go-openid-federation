package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func scopeOfTokens(count int, prefix string) string {
	tokens := make([]string, count)
	for i := range tokens {
		tokens[i] = prefix + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
	}
	return strings.Join(tokens, " ")
}

func scopeTokenPolicyStatement(t *testing.T, issuer, subject string, policy map[string]any) EntityStatement {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"iss": issuer, "sub": subject, "iat": 1, "exp": 99999999999, "jwks": map[string]any{"keys": []any{}}, "metadata_policy": policy})
	if err != nil {
		t.Fatalf("failed to marshal the fixture policy: %v", err)
	}
	var statement EntityStatement
	if err := json.Unmarshal(raw, &statement); err != nil {
		t.Fatalf("failed to parse the fixture policy: %v", err)
	}
	return statement
}

func TestConfiguration_ProcessAndExtractPolicy_ChargesScopeValuesAgainstTheStatementBound(t *testing.T) {
	const bound = 20
	cfg := Configuration{MaxStatementValues: bound}
	leaf := EntityStatement{Iss: "https://leaf.example.com", Sub: "https://leaf.example.com"}

	tests := []struct {
		name    string
		policy  map[string]any
		refused bool
	}{
		{name: "one subset_of string of exactly the bound's scope values", policy: map[string]any{"oauth_client": map[string]any{"scope": map[string]any{"subset_of": []any{scopeOfTokens(bound, "zq")}}}}},
		{name: "one subset_of string one scope value over the bound", policy: map[string]any{"oauth_client": map[string]any{"scope": map[string]any{"subset_of": []any{scopeOfTokens(bound+1, "zq")}}}}, refused: true},
		{name: "one one_of string over the bound", policy: map[string]any{"oauth_client": map[string]any{"scope": map[string]any{"one_of": []any{scopeOfTokens(bound+1, "zq")}}}}, refused: true},
		{name: "one value string over the bound", policy: map[string]any{"oauth_client": map[string]any{"scope": map[string]any{"value": scopeOfTokens(bound+1, "zq")}}}, refused: true},
		{name: "one default array element over the bound", policy: map[string]any{"oauth_client": map[string]any{"scope": map[string]any{"default": []any{scopeOfTokens(bound+1, "zq")}}}}, refused: true},
		{name: "array elements that pass the bound together", policy: map[string]any{"oauth_client": map[string]any{"scope": map[string]any{"superset_of": []any{scopeOfTokens(bound/2, "a"), scopeOfTokens(bound/2+1, "b")}}}}, refused: true},
		{name: "scope operands of two entity types that pass the bound together", policy: map[string]any{
			"oauth_client":         map[string]any{"scope": map[string]any{"add": []any{scopeOfTokens(bound/2, "a")}}},
			"openid_relying_party": map[string]any{"scope": map[string]any{"subset_of": []any{scopeOfTokens(bound/2+1, "b")}}},
		}, refused: true},
		{name: "value and default scope operands of two entity types that pass the bound together", policy: map[string]any{
			"oauth_client":         map[string]any{"scope": map[string]any{"value": scopeOfTokens(bound/2, "a")}},
			"openid_relying_party": map[string]any{"scope": map[string]any{"default": scopeOfTokens(bound/2+1, "b")}},
		}, refused: true},
		{name: "one add string over the bound", policy: map[string]any{"oauth_client": map[string]any{"scope": map[string]any{"add": []any{scopeOfTokens(bound+1, "zq")}}}}, refused: true},
		{name: "exactly the bound's scope values beside essential, whose operand is not a scope value", policy: map[string]any{"oauth_client": map[string]any{"scope": map[string]any{"value": scopeOfTokens(bound, "zq"), "essential": true}}}},
		{name: "spaces around and between the scope values, which are not values", policy: map[string]any{"oauth_client": map[string]any{"scope": map[string]any{"subset_of": []any{"  " + strings.ReplaceAll(scopeOfTokens(bound, "zq"), " ", "   ") + "  "}}}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cfg.ProcessAndExtractPolicy([]EntityStatement{leaf, scopeTokenPolicyStatement(t, "https://ta.example.com", "https://leaf.example.com", tc.policy)})
			if !tc.refused {
				if errors.Is(err, ErrLimitReached) {
					t.Fatalf("expected a statement within the bound to merge, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrLimitReached) {
				t.Fatalf("[6.1.3.1.8] scope is processed as an array of scope values, so its values count against the statement bound, got %v", err)
			}
			if !strings.Contains(err.Error(), "more than 20 values once each scope string is read as its scope values") {
				t.Errorf("expected the error to name the bound, got %v", err)
			}
			for _, chosen := range []string{"oauth_client", "openid_relying_party", "subset_of", "zqa"} {
				if strings.Contains(err.Error(), chosen) {
					t.Errorf("expected the error to name nothing a peer chose, got %v", err)
				}
			}
		})
	}
}

func TestMergePolicyOperators_ChargesScopeValuesAgainstTheDefaultBound(t *testing.T) {
	over, err := NewSubsetOf([]any{scopeOfTokens(DefaultMaxStatementValues+1, "s")})
	if err != nil {
		t.Fatalf("expected the operator to build, got %v", err)
	}
	within, err := NewSubsetOf([]any{"openid"})
	if err != nil {
		t.Fatalf("expected the operator to build, got %v", err)
	}
	_, err = MergePolicyOperators("scope", PolicyOperators{Metadata: []MetadataPolicyOperator{*over}}, PolicyOperators{Metadata: []MetadataPolicyOperator{*within}})
	if !errors.Is(err, ErrLimitReached) {
		t.Fatalf("expected a scope operand over the default bound to be refused, got %v", err)
	}
}

func TestConfiguration_ProcessAndExtractPolicy_CountsOnlyAddAndSupersetOfInTheMergedTotal(t *testing.T) {
	cfg := Configuration{MaxStatementValues: 10}
	leaf := EntityStatement{Iss: "https://leaf.example.com", Sub: "https://leaf.example.com"}

	tests := []struct {
		name    string
		policy  map[string]any
		refused bool
	}{
		{name: "one_of and subset_of that pass the bound together", policy: map[string]any{"oauth_client": map[string]any{
			"token_endpoint_auth_method": map[string]any{"one_of": operandsNamed("m", 6)},
			"grant_types":                map[string]any{"subset_of": operandsNamed("g", 6)},
		}}},
		{name: "subset_of and superset_of that pass the bound together", policy: map[string]any{"oauth_client": map[string]any{
			"grant_types":    map[string]any{"subset_of": operandsNamed("g", 6)},
			"response_types": map[string]any{"superset_of": operandsNamed("r", 5)},
		}}},
		{name: "a scope subset_of whose scope values pass the bound with an add", policy: map[string]any{"oauth_client": map[string]any{
			"scope":    map[string]any{"subset_of": []any{scopeOfTokens(6, "s")}},
			"contacts": map[string]any{"add": operandsNamed("c", 5)},
		}}},
		{name: "add and superset_of that pass the bound together", policy: map[string]any{"oauth_client": map[string]any{
			"contacts":       map[string]any{"add": operandsNamed("c", 6)},
			"response_types": map[string]any{"superset_of": operandsNamed("r", 5)},
		}}, refused: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cfg.ProcessAndExtractPolicy([]EntityStatement{leaf, scopeTokenPolicyStatement(t, "https://ta.example.com", "https://leaf.example.com", tc.policy)})
			if !tc.refused {
				if err != nil {
					t.Fatalf("expected an intersection, which only shrinks when merged, to be left out of the total, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrLimitReached) {
				t.Fatalf("expected the merged add and superset_of operators to be held to the statement bound in total, got %v", err)
			}
			if !strings.Contains(err.Error(), "more than 10 operands") {
				t.Errorf("expected the error to name the bound, got %v", err)
			}
		})
	}
}

func TestMergePolicyOperators_LeavesAMergedNarrowingOperatorToTheStatementBound(t *testing.T) {
	for _, operator := range []string{"subset_of", "one_of"} {
		t.Run(operator, func(t *testing.T) {
			over := operandsNamed("a", DefaultMaxStatementValues+1)
			left, err := parsePolicyOperator(operator, over)
			if err != nil {
				t.Fatalf("expected the operator to build, got %v", err)
			}
			right, err := parsePolicyOperator(operator, over)
			if err != nil {
				t.Fatalf("expected the operator to build, got %v", err)
			}
			merged, err := MergePolicyOperators("grant_types", PolicyOperators{Metadata: []MetadataPolicyOperator{left}}, PolicyOperators{Metadata: []MetadataPolicyOperator{right}})
			if err != nil {
				t.Fatalf("expected the intersection of two %s operands to merge, got %v", operator, err)
			}
			if got := len(merged[0].OperatorValue().([]any)); got != DefaultMaxStatementValues+1 {
				t.Errorf("expected the intersection to hold every operand, got %d", got)
			}
		})
	}
}

func TestProcessAndExtractPolicy_RefusesTheScopeStringAttackOnTheStatementChargeAlone(t *testing.T) {
	tokens := make([]string, 200_000)
	for i := range tokens {
		tokens[i] = strconv.FormatInt(int64(i), 36)
	}
	scope := strings.Join(tokens, " ")
	leaf := EntityStatement{Iss: "https://leaf.example.com", Sub: "https://leaf.example.com"}
	for _, operator := range []string{"subset_of", "one_of"} {
		t.Run(operator, func(t *testing.T) {
			chain := []EntityStatement{leaf}
			for i := range 9 {
				subject := "https://leaf.example.com"
				if i > 0 {
					subject = fmt.Sprintf("https://i%d.example.com", i)
				}
				chain = append(chain, scopeTokenPolicyStatement(t, fmt.Sprintf("https://i%d.example.com", i+1), subject, map[string]any{
					"openid_relying_party": map[string]any{"scope": map[string]any{operator: []any{scope}}},
				}))
			}
			_, err := ProcessAndExtractPolicy(chain)
			if !errors.Is(err, ErrLimitReached) {
				t.Fatalf("expected 200,000 scope values in one string to be refused, got %v", err)
			}
			if !strings.Contains(err.Error(), "once each scope string is read as its scope values") {
				t.Errorf("expected the statement's scope charge to refuse it, got %v", err)
			}
		})
	}
}

type scopeCarryingOperator struct{ operand string }

func (o scopeCarryingOperator) String() string                            { return "x_scope" }
func (o scopeCarryingOperator) Resolve(value any) (any, error)            { return value, nil }
func (o scopeCarryingOperator) ResolutionHierarchy() int                  { return 99 }
func (o scopeCarryingOperator) Merge(any) (MetadataPolicyOperator, error) { return o, nil }
func (o scopeCarryingOperator) OperatorValue() any                        { return o.operand }
func (o scopeCarryingOperator) ToSlice(string) MetadataPolicyOperator     { return o }
func (o scopeCarryingOperator) CheckForConflict(func(reflect.Type) (MetadataPolicyOperator, bool)) error {
	return nil
}

func TestConfiguration_ProcessAndExtractPolicy_ChargesTheScopeValuesOfAnOperatorTheLibraryDoesNotDefine(t *testing.T) {
	cfg := Configuration{MaxStatementValues: 20}
	chain := []EntityStatement{
		{Iss: "https://leaf.example.com", Sub: "https://leaf.example.com"},
		{Iss: "https://ta.example.com", Sub: "https://leaf.example.com", MetadataPolicy: &MetadataPolicy{OAuthClientMetadata: map[string]PolicyOperators{
			"scope": {Metadata: []MetadataPolicyOperator{scopeCarryingOperator{operand: scopeOfTokens(21, "zq")}}},
		}}},
	}
	if _, err := cfg.ProcessAndExtractPolicy(chain); !errors.Is(err, ErrLimitReached) {
		t.Fatalf("expected the scope values of a Go caller's own operator to count against the bound, got %v", err)
	}
}

func TestProcessAndExtractPolicy_TokenisingScopeLeavesTheChainUnchanged(t *testing.T) {
	leaf := scopeSubject(t, "openid profile")
	authority := scopePolicyStatement(t, `{"subset_of":["openid profile email"],"default":"openid"}`)
	superior := scopePolicyStatement(t, `{"superset_of":["openid profile"]}`)
	before, err := json.Marshal([]any{authority.MetadataPolicy, superior.MetadataPolicy})
	if err != nil {
		t.Fatalf("failed to marshal the chain: %v", err)
	}

	if _, err := ProcessAndExtractPolicy([]EntityStatement{leaf, authority, superior}); err != nil {
		t.Fatalf("expected the policy to merge, got %v", err)
	}

	after, err := json.Marshal([]any{authority.MetadataPolicy, superior.MetadataPolicy})
	if err != nil {
		t.Fatalf("failed to marshal the chain: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("[#156] expected the chain's scope operands to be left as written:\nwant %s\ngot  %s", before, after)
	}
}

func TestProcessAndExtractPolicy_AScopeOperandWithNoScopeValuesIsStillReadAsTokens(t *testing.T) {
	leaf := scopeSubject(t, "openid")
	authority := scopePolicyStatement(t, `{"value":""}`)
	superior := scopePolicyStatement(t, `{"value":[]}`)

	if _, err := ProcessAndExtractPolicy([]EntityStatement{leaf, authority, superior}); err != nil {
		t.Errorf("[6.1.3.1.8] an empty scope string holds no scope values, as an empty array does, so the two values are equal: %v", err)
	}
}
