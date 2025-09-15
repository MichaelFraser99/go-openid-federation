package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"
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

		if metadataPolicy.FederationMetadata != nil {
			if finalisedPolicy.MetadataPolicy.FederationMetadata == nil {
				finalisedPolicy.MetadataPolicy.FederationMetadata = metadataPolicy.FederationMetadata
			} else {
				for k, policies := range finalisedPolicy.MetadataPolicy.FederationMetadata {
					mergedPolicies, err := MergePolicyOperators(metadataPolicy.FederationMetadata[k], policies)
					if err != nil {
						return nil, err
					}
					finalisedPolicy.MetadataPolicy.FederationMetadata[k] = PolicyOperators{Metadata: mergedPolicies}
				}
			}
		}

		if metadataPolicy.OpenIDConnectOpenIDProviderMetadata != nil {
			if finalisedPolicy.MetadataPolicy.OpenIDConnectOpenIDProviderMetadata == nil {
				finalisedPolicy.MetadataPolicy.OpenIDConnectOpenIDProviderMetadata = metadataPolicy.OpenIDConnectOpenIDProviderMetadata
			} else {
				for k, policies := range finalisedPolicy.MetadataPolicy.OpenIDConnectOpenIDProviderMetadata {
					mergedPolicies, err := MergePolicyOperators(metadataPolicy.OpenIDConnectOpenIDProviderMetadata[k], policies)
					if err != nil {
						return nil, err
					}
					finalisedPolicy.MetadataPolicy.OpenIDConnectOpenIDProviderMetadata[k] = PolicyOperators{Metadata: mergedPolicies}
				}
			}
		}

		if metadataPolicy.OpenIDRelyingPartyMetadata != nil {
			if finalisedPolicy.MetadataPolicy.OpenIDRelyingPartyMetadata == nil {
				finalisedPolicy.MetadataPolicy.OpenIDRelyingPartyMetadata = metadataPolicy.OpenIDRelyingPartyMetadata
			} else {
				for k, policies := range finalisedPolicy.MetadataPolicy.OpenIDRelyingPartyMetadata {
					mergedPolicies, err := MergePolicyOperators(metadataPolicy.OpenIDRelyingPartyMetadata[k], policies)
					if err != nil {
						return nil, err
					}
					finalisedPolicy.MetadataPolicy.OpenIDRelyingPartyMetadata[k] = PolicyOperators{Metadata: mergedPolicies}
				}
			}
		}
	}
	return finalisedPolicy.MetadataPolicy, nil
}

// MergePolicyOperators takes in two PolicyOperator values and returns the result of merging the two
func MergePolicyOperators(policySetA, policySetB PolicyOperators) ([]MetadataPolicyOperator, error) {
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
				resolved, err := operator.Resolve((*subject.Metadata.OpenIDRelyingPartyMetadata)[k])
				if err != nil {
					return nil, err
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
