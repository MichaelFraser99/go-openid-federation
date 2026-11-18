package model

import (
	"encoding/json"
	"fmt"
	"mime"
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
		return fmt.Errorf("invalid url")
	}

	if parsedUrl.Scheme != "https" {
		return fmt.Errorf("url does not use the required scheme 'https'")
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
			candidates := operators.Metadata
			if parameter == "scope" {
				candidates = make([]MetadataPolicyOperator, 0, len(operators.Metadata))
				for _, operator := range operators.Metadata {
					candidates = append(candidates, operator.ToSlice(parameter))
				}
			}
			if err := validatePoliciesCanCombine(sortByPriority(slices.Clone(candidates))); err != nil {
				return err
			}
		}
	}
	return nil
}

func ProcessAndExtractPolicy(trustChain []EntityStatement) (*MetadataPolicy, error) {
	return processAndExtractPolicy(trustChain, DefaultMaxStatementValues)
}

func (cfg *Configuration) ProcessAndExtractPolicy(trustChain []EntityStatement) (*MetadataPolicy, error) {
	return processAndExtractPolicy(trustChain, cfg.StatementValuesLimit())
}

func processAndExtractPolicy(trustChain []EntityStatement, operandLimit int) (*MetadataPolicy, error) {
	for i := range trustChain {
		if err := sortAndValidatePolicy(trustChain[i].MetadataPolicy); err != nil {
			return nil, err
		}
	}

	if len(trustChain) == 0 {
		return nil, fmt.Errorf("trust chain must hold at least one statement")
	}

	var finalisedPolicy *MetadataPolicy

	for i := range trustChain {
		if trustChain[i].Iss == trustChain[i].Sub {
			continue
		}
		metadataPolicy := trustChain[i].MetadataPolicy
		if metadataPolicy == nil {
			continue
		}

		if finalisedPolicy == nil {
			finalisedPolicy = metadataPolicy.clone()
			if err := verifyMergedPolicyOperandCount(finalisedPolicy, operandLimit); err != nil {
				return nil, err
			}
			continue
		}

		destination := finalisedPolicy.byEntityType()
		for entityType, incoming := range metadataPolicy.byEntityType() {
			if incoming == nil {
				continue
			}
			merged, err := applyPolicy(destination[entityType], incoming, operandLimit)
			if err != nil {
				return nil, err
			}
			finalisedPolicy.setEntityType(entityType, merged)
		}
		if err := verifyMergedPolicyOperandCount(finalisedPolicy, operandLimit); err != nil {
			return nil, err
		}
	}
	return finalisedPolicy, nil
}

func verifyMergedPolicyOperandCount(policy *MetadataPolicy, operandLimit int) error {
	var operands int
	for _, parameters := range policy.byEntityType() {
		for _, operators := range parameters {
			for _, operator := range operators.Metadata {
				operands += unionOperandCount(operator)
			}
		}
	}
	if operands > operandLimit {
		return fmt.Errorf("%wthe merged 'add' and 'superset_of' operators hold more than %d operands in total, the most one statement may hold", ErrLimitReached, operandLimit)
	}
	return nil
}

func unionOperandCount(operator MetadataPolicyOperator) int {
	switch typed := operator.(type) {
	case Add:
		return len(typed.operatorValue)
	case SupersetOf:
		return len(typed.operatorValue)
	}
	return 0
}

func applyPolicy(existing, policy map[string]PolicyOperators, operandLimit int) (map[string]PolicyOperators, error) {
	if policy != nil {
		if existing == nil {
			existing = clonePolicyParameters(policy)
		} else {
			for k, policies := range existing {
				if policyOp, found := policy[k]; found {
					mergedPolicies, err := mergePolicyOperators(k, policyOp, policies, operandLimit)
					if err != nil {
						return nil, err
					}
					existing[k] = PolicyOperators{Metadata: mergedPolicies}
				}
			}

			for k, policyOp := range policy {
				if _, found := existing[k]; !found {
					existing[k] = policyOp.clone()
				}
			}
		}
	}
	return existing, nil
}

// MergePolicyOperators takes in two PolicyOperator values and returns the result of merging the two
func MergePolicyOperators(claimName string, policySetA, policySetB PolicyOperators) ([]MetadataPolicyOperator, error) {
	return mergePolicyOperators(claimName, policySetA, policySetB, DefaultMaxStatementValues)
}

func mergePolicyOperators(claimName string, policySetA, policySetB PolicyOperators, operandLimit int) ([]MetadataPolicyOperator, error) {
	if len(policySetA.Metadata) == 0 && len(policySetB.Metadata) == 0 {
		return nil, nil
	} else if len(policySetA.Metadata) == 0 {
		return slices.Clone(policySetB.Metadata), nil
	} else if len(policySetB.Metadata) == 0 {
		return slices.Clone(policySetA.Metadata), nil
	} else {
		structuredA := structureAsMap(policySetA.Metadata)
		structuredB := structureAsMap(policySetB.Metadata)

		if claimName == "scope" {
			for _, structured := range []map[int]MetadataPolicyOperator{structuredA, structuredB} {
				for hierarchy, operator := range structured {
					if operator == nil {
						continue
					}
					structured[hierarchy] = operator.ToSlice(claimName)
				}
			}
		}

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
				if err := verifyMergedOperandCount(m, operandLimit); err != nil {
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

func verifyMergedOperandCount(merged MetadataPolicyOperator, operandLimit int) error {
	if unionOperandCount(merged) > operandLimit {
		return fmt.Errorf("%wa merged '%s' operator holds more than %d operands, the most one statement may hold", ErrLimitReached, merged.String(), operandLimit)
	}
	return nil
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
		if policy == nil {
			continue
		}
		held := reflect.ValueOf(policy)
		if held.Kind() == reflect.Pointer {
			if held.IsNil() {
				continue
			}
			held = held.Elem()
		}
		if held.Type() != policyType {
			continue
		}
		if operator, ok := held.Interface().(MetadataPolicyOperator); ok {
			return operator, true
		}
	}
	return nil, false
}

func ApplyPolicy(subject EntityStatement, policy MetadataPolicy) (*EntityStatement, error) {
	if subject.Metadata == nil { //if no metadata
		return &subject, nil
	}
	subject.Metadata = subject.Metadata.clone()

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
					existing = ConvertStringsToAnySlice(scopeTokens(existingString))
				}
				operator = operator.ToSlice(k)
			}
			if _, isOneOf := operator.(OneOf); isOneOf && k == "scope" && ok {
				return fmt.Errorf("one_of cannot be applied to scope, because policy operators process scope as an array of scope values")
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
				metadata[k] = cloneValue(resolved)
			}
		}
	}
	return nil
}

func joinScopeTokens(values []string) string {
	seen := make(map[string]struct{})
	var tokens []string
	for _, value := range values {
		for _, token := range scopeTokens(value) {
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

const EntityStatementMediaType = "application/entity-statement+jwt"

func IsEntityStatementMediaType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == EntityStatementMediaType
}

const MaxErrorDescriptionBytes = 256

func TruncateForResponse(value string) string {
	return TruncateAtCharacter(value, MaxErrorDescriptionBytes)
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
	return time.Now().Add(-ClockSkewLeeway).UTC().Unix() >= exp
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

func ApplySuperiorMetadata(subject, superior *Metadata) *Metadata {
	if subject == nil {
		return nil
	}

	var supplied map[string]map[string]any
	if superior != nil {
		supplied = superior.byEntityType()
	}

	result := &Metadata{}
	for entityType, parameters := range subject.byEntityType() {
		merged := make(map[string]any, len(parameters))
		for parameter, value := range parameters {
			merged[parameter] = value
		}
		for parameter, value := range supplied[entityType] {
			merged[parameter] = value
		}
		result.setEntityType(entityType, merged)
	}
	return result
}
