package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
)

func ReMarshalJsonAsEntityMetadata[T any](data any) (*T, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	t := new(T)
	if slices.Equal(bytes, []byte("{}")) {
		return t, nil
	}
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

	if parsedUrl.RawFragment != "" || parsedUrl.Fragment != "" {
		return fmt.Errorf("url must not contain Fragment components")
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

func ProcessAndExtractPolicy(trustChain []EntityStatement) (*MetadataPolicy, error) {
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

		var err error
		if finalisedPolicy.MetadataPolicy.FederationMetadata, err = applyPolicy(finalisedPolicy.MetadataPolicy.FederationMetadata, metadataPolicy.FederationMetadata); err != nil {
			return nil, err
		}
		if finalisedPolicy.MetadataPolicy.OpenIDConnectOpenIDProviderMetadata, err = applyPolicy(finalisedPolicy.MetadataPolicy.OpenIDConnectOpenIDProviderMetadata, metadataPolicy.OpenIDConnectOpenIDProviderMetadata); err != nil {
			return nil, err
		}
		if finalisedPolicy.MetadataPolicy.OpenIDRelyingPartyMetadata, err = applyPolicy(finalisedPolicy.MetadataPolicy.OpenIDRelyingPartyMetadata, metadataPolicy.OpenIDRelyingPartyMetadata); err != nil {
			return nil, err
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
				mergedPolicies, err := MergePolicyOperators(k, policy[k], policies)
				if err != nil {
					return nil, err
				}
				existing[k] = PolicyOperators{Metadata: mergedPolicies}
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

	if subject.Metadata.FederationMetadata != nil {
		for k, operators := range policy.FederationMetadata {
			for _, operator := range operators.Metadata {
				resolved, err := operator.Resolve((*subject.Metadata.FederationMetadata)[k])
				if err != nil {
					return nil, err
				}
				(*subject.Metadata.FederationMetadata)[k] = resolved
			}
		}
	}

	if subject.Metadata.OpenIDRelyingPartyMetadata != nil {
		for k, operators := range policy.OpenIDRelyingPartyMetadata {
			for _, operator := range operators.Metadata {
				existing, ok := (*subject.Metadata.OpenIDRelyingPartyMetadata)[k]
				if k == "scope" {
					// scope has special behaviour
					if ok {
						existing = ConvertStringsToAnySlice(strings.Split(existing.(string), " "))
					} else {
						existing = []any{}
					}
				}
				if k == "scope" {
					operator = operator.ToSlice(k)
				}
				resolved, err := operator.Resolve(existing)
				if err != nil {
					return nil, err
				}
				if k == "scope" {
					if resolvedSlice, ok := resolved.([]string); ok {
						resolved = strings.Join(resolvedSlice, " ")
					} else if resolvedAny, ok := resolved.([]any); ok {
						stringSlice := make([]string, len(resolvedAny))
						for i, v := range resolvedAny {
							stringSlice[i], ok = v.(string)
							if !ok {
								return nil, fmt.Errorf("all scope values must be strings")
							}
						}
						resolved = strings.Join(stringSlice, " ")
					} else {
						return nil, fmt.Errorf("scope must be a string or array of strings")
					}
				}
				(*subject.Metadata.OpenIDRelyingPartyMetadata)[k] = resolved
			}
		}
	}

	if subject.Metadata.OpenIDConnectOpenIDProviderMetadata != nil {
		for k, operators := range policy.OpenIDConnectOpenIDProviderMetadata {
			for _, operator := range operators.Metadata {
				resolved, err := operator.Resolve((*subject.Metadata.OpenIDConnectOpenIDProviderMetadata)[k])
				if err != nil {
					return nil, err
				}
				(*subject.Metadata.OpenIDConnectOpenIDProviderMetadata)[k] = resolved
			}
		}
	}
	return &subject, nil
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

	seen := make(map[string]bool)
	result := make([]any, 0, len(input))

	hashElement := func(element any) string {
		switch e := element.(type) {
		case map[string]any:
			// For maps, create a stable hash by sorting keys
			keys := make([]string, 0, len(e))
			for k := range e {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			sortedMap := make([]string, 0, len(e)*2)
			for _, k := range keys {
				sortedMap = append(sortedMap, k, fmt.Sprintf("%v", e[k]))
			}
			return fmt.Sprintf("%v", sortedMap)
		default:
			// For primitive types (string, int, float, bool, etc.)
			return fmt.Sprintf("%#v", element)
		}
	}

	for _, elem := range input {
		hash := hashElement(elem)
		if !seen[hash] {
			seen[hash] = true
			result = append(result, elem)
		}
	}

	return result
}
