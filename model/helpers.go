package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"
)

func ReMarshalJsonAsEntityMetadata[T any](data any) (*T, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	t := new(T)
	err = json.Unmarshal(bytes, t)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func VerifyFederationEndpoint(endpoint any) error {
	if endpoint == nil {
		return nil
	}
	if _, ok := endpoint.(string); !ok {
		return fmt.Errorf("endpoint must be a string")
	}
	sEndpoint := endpoint.(string)
	parsedUrl, err := url.Parse(sEndpoint)
	if err != nil {
		return fmt.Errorf("invalid url: %s", err.Error())
	}

	if parsedUrl.Scheme != "https" {
		return fmt.Errorf("url does not use the required scheme 'https': %s", parsedUrl.Scheme)
	}

	if parsedUrl.Hostname() == "" {
		return fmt.Errorf("url must have a host component")
	}

	if strings.Contains(sEndpoint, "#") {
		return fmt.Errorf("url must not contain Fragment components")
	}

	if parsedUrl.User != nil {
		return fmt.Errorf("url must not contain Userinfo components")
	}

	return nil
}

func structureAsMap(policies []MetadataPolicyOperator) map[int]MetadataPolicyOperator {
	m := make(map[int]MetadataPolicyOperator)
	for _, policy := range policies {
		m[policy.ResolutionHierarchy()] = policy
	}
	return m
}

func sortByPriority(policies []MetadataPolicyOperator) []MetadataPolicyOperator {
	slices.SortFunc(policies, func(a, b MetadataPolicyOperator) int {
		return a.ResolutionHierarchy() - b.ResolutionHierarchy()
	})
	return policies
}

func verifyScopeOperand(value any) error {
	if value == nil {
		return nil
	}
	if _, ok := value.(string); ok {
		return nil
	}
	if reflect.TypeOf(value).Kind() != reflect.Slice {
		return fmt.Errorf("all scope values must be strings")
	}
	slice := reflect.ValueOf(value)
	for i := range slice.Len() {
		if _, ok := slice.Index(i).Interface().(string); !ok {
			return fmt.Errorf("all scope values must be strings")
		}
	}
	return nil
}

func sortAndValidatePolicy(policy *MetadataPolicy) error {
	if policy == nil {
		return nil
	}
	for _, parameters := range policy.byEntityType() {
		for parameter, operators := range parameters {
			if parameter == "scope" {
				for _, operator := range operators.Metadata {
					if operator.String() == "essential" {
						continue
					}
					if err := verifyScopeOperand(operator.OperatorValue()); err != nil {
						return err
					}
				}
			}
			if err := validatePoliciesCanCombine(sortByPriority(operators.Metadata)); err != nil {
				return err
			}
		}
	}
	return nil
}

func ProcessAndExtractPolicy(trustChain []EntityStatement) (*MetadataPolicy, error) {
	for i := range trustChain {
		if err := sortAndValidatePolicy(trustChain[i].MetadataPolicy); err != nil {
			return nil, err
		}
	}

	if len(trustChain) == 1 {
		return trustChain[0].MetadataPolicy, nil // self-asserting chain of 1
	}
	if len(trustChain) < 2 {
		return nil, fmt.Errorf("trust chain must have at least 2 statements")
	}

	finalisedPolicy := trustChain[0]

	for i := 1; i < len(trustChain); i++ {
		metadataPolicy := trustChain[i].MetadataPolicy
		if metadataPolicy == nil {
			continue
		}

		if finalisedPolicy.MetadataPolicy == nil {
			finalisedPolicy.MetadataPolicy = metadataPolicy
			continue
		}

		destination := finalisedPolicy.MetadataPolicy.byEntityType()
		for entityType, incoming := range metadataPolicy.byEntityType() {
			if incoming == nil {
				continue
			}
			merged, err := applyPolicy(destination[entityType], incoming)
			if err != nil {
				return nil, err
			}
			finalisedPolicy.MetadataPolicy.setEntityType(entityType, merged)
		}
	}
	return finalisedPolicy.MetadataPolicy, nil
}

func applyPolicy(existing, policy map[string]PolicyOperators) (map[string]PolicyOperators, error) {
	if policy != nil {
		if existing == nil {
			existing = policy
		} else {
			for k, policies := range existing {
				if policyOp, found := policy[k]; found {
					mergedPolicies, err := MergePolicyOperators(k, policyOp, policies)
					if err != nil {
						return nil, err
					}
					existing[k] = PolicyOperators{Metadata: mergedPolicies}
				}
			}

			for k, policyOp := range policy {
				if _, found := existing[k]; !found {
					existing[k] = policyOp
				}
			}
		}
	}
	return existing, nil
}

// MergePolicyOperators takes in two PolicyOperator values and returns the result of merging the two
func MergePolicyOperators(claimName string, policySetA, policySetB PolicyOperators) ([]MetadataPolicyOperator, error) {
	if len(policySetA.Metadata) == 0 && len(policySetB.Metadata) == 0 {
		return nil, nil
	} else if len(policySetA.Metadata) == 0 {
		return policySetB.Metadata, nil
	} else if len(policySetB.Metadata) == 0 {
		return policySetA.Metadata, nil
	} else {
		structuredA := structureAsMap(policySetA.Metadata)
		structuredB := structureAsMap(policySetB.Metadata)

		var mergedPolicies []MetadataPolicyOperator

		for _, next := range []MetadataPolicyOperator{Value{}, Add{}, Default{}, OneOf{}, SubsetOf{}, SupersetOf{}, Essential{}} {
			if structuredA[next.ResolutionHierarchy()] == nil && structuredB[next.ResolutionHierarchy()] == nil {
				continue
			} else if structuredA[next.ResolutionHierarchy()] == nil {
				mergedPolicies = append(mergedPolicies, structuredB[next.ResolutionHierarchy()])
				continue
			} else if structuredB[next.ResolutionHierarchy()] == nil {
				mergedPolicies = append(mergedPolicies, structuredA[next.ResolutionHierarchy()])
				continue
			} else {
				if claimName == "scope" {
					structuredA[next.ResolutionHierarchy()] = structuredA[next.ResolutionHierarchy()].ToSlice(claimName)
					structuredB[next.ResolutionHierarchy()] = structuredB[next.ResolutionHierarchy()].ToSlice(claimName)
				}

				m, err := structuredA[next.ResolutionHierarchy()].Merge(structuredB[next.ResolutionHierarchy()].OperatorValue())
				if err != nil {
					return nil, err
				}
				mergedPolicies = append(mergedPolicies, m)
			}
		}

		sortedPolicies := sortByPriority(mergedPolicies)

		if err := validatePoliciesCanCombine(sortedPolicies); err != nil {
			return nil, err
		}

		return sortedPolicies, nil
	}
}

func validatePoliciesCanCombine(policies []MetadataPolicyOperator) error {
	for _, mergedPolicy := range policies {
		if err := mergedPolicy.CheckForConflict(func(policyType reflect.Type) (MetadataPolicyOperator, bool) {
			return metadataPolicySetContains(policies, policyType)
		}); err != nil {
			return err
		}
	}

	return nil
}

func metadataPolicySetContains(policySet []MetadataPolicyOperator, policyType reflect.Type) (MetadataPolicyOperator, bool) {
	for _, policy := range policySet {
		if reflect.TypeOf(policy) == policyType {
			return policy, true
		}
	}
	return nil, false
}

func ApplyPolicy(subject EntityStatement, policy MetadataPolicy) (*EntityStatement, error) {
	if subject.Metadata == nil { //if no metadata
		return &subject, nil
	}

	policies := policy.byEntityType()
	for entityType, metadata := range subject.Metadata.byEntityType() {
		operators, ok := policies[entityType]
		if !ok || operators == nil {
			continue
		}
		if err := applyPolicyToMetadata(metadata, operators); err != nil {
			return nil, err
		}
	}
	return &subject, nil
}

func applyPolicyToMetadata(metadata map[string]any, policy map[string]PolicyOperators) error {
	for k, operators := range policy {
		for _, operator := range sortByPriority(slices.Clone(operators.Metadata)) {
			existing, ok := metadata[k]
			if k == "scope" {
				if ok {
					existingString, isString := existing.(string)
					if !isString {
						return fmt.Errorf("scope must be a string")
					}
					existing = ConvertStringsToAnySlice(strings.Split(existingString, " "))
				}
				operator = operator.ToSlice(k)
			}
			resolved, err := operator.Resolve(existing)
			if err != nil {
				return err
			}
			if k == "scope" && resolved != nil {
				switch resolvedTyped := resolved.(type) {
				case []string:
					resolved = joinScopeTokens(resolvedTyped)
				case []any:
					stringSlice := make([]string, len(resolvedTyped))
					for i, v := range resolvedTyped {
						stringValue, isString := v.(string)
						if !isString {
							return fmt.Errorf("all scope values must be strings")
						}
						stringSlice[i] = stringValue
					}
					resolved = joinScopeTokens(stringSlice)
				default:
					return fmt.Errorf("scope must be a string or array of strings")
				}
			}
			if resolved == nil {
				delete(metadata, k)
			} else {
				metadata[k] = resolved
			}
		}
	}
	return nil
}

func joinScopeTokens(values []string) string {
	seen := make(map[string]struct{})
	var tokens []string
	for _, value := range values {
		for _, token := range strings.Fields(value) {
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			tokens = append(tokens, token)
		}
	}
	return strings.Join(tokens, " ")
}

func ResolveStatementLifetime(name string, configured, fallback time.Duration) (time.Duration, error) {
	if configured < 0 {
		return 0, fmt.Errorf("%s must not be negative, got %s", name, configured)
	}
	if configured == 0 {
		return fallback, nil
	}
	if configured < time.Second {
		return 0, fmt.Errorf("%s must be at least one second, got %s", name, configured)
	}
	return configured, nil
}

func VerifyIssuedStatement(claims []byte, registry EntityTypeRegistry) error {
	var issued EntityStatement
	if err := json.Unmarshal(claims, &issued); err != nil {
		return err
	}
	if issued.Metadata != nil {
		if err := issued.Metadata.Verify(registry, false); err != nil {
			return err
		}
	}
	if issued.MetadataPolicy != nil {
		if err := issued.MetadataPolicy.Verify(registry, false); err != nil {
			return err
		}
	}
	return nil
}

const MaxErrorDescriptionBytes = 256

func TruncateForResponse(value string) string {
	if len(value) <= MaxErrorDescriptionBytes {
		return value
	}
	return value[:MaxErrorDescriptionBytes] + "..."
}

func VerifyChainExpiry(exp int64) error {
	if ChainHasExpired(exp) {
		return NewInvalidTrustChainError("trust chain expired")
	}
	if exp <= time.Now().UTC().Unix() {
		return NewInvalidTrustChainError("trust chain expiry is not in the future, so no resolve response can be issued for it")
	}
	return nil
}

func ChainHasExpired(exp int64) bool {
	return time.Now().Add(-ClockSkewLeeway).UTC().Unix() > exp
}

func CalculateChainExpiration(chain []EntityStatement) int64 {
	exp := chain[0].Exp
	for _, statement := range chain[1:] {
		if statement.Exp < exp {
			exp = statement.Exp
		}
	}
	return exp
}

func ConvertStringsToAnySlice(input []string) []any {
	result := make([]any, len(input))
	for i, v := range input {
		result[i] = v
	}
	return result
}

// DeduplicateSlice removes duplicate values from a slice, preserving order.
// Works with all data types including strings, numbers, booleans, and maps.
func DeduplicateSlice(input []any) []any {
	if len(input) == 0 {
		return input
	}

	seen := newOperandAccumulator(len(input))
	result := make([]any, 0, len(input))

	for _, elem := range input {
		if seen.add(elem) {
			result = append(result, elem)
		}
	}

	return result
}
