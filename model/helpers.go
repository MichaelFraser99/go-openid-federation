package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
)

func reMarshalJsonAsEntityMetadata[T any](data any) (*T, error) {
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

func verifyFederationEndpoint(endpoint any) error {
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

func tokeniseAndValidatePolicy(policy *MetadataPolicy, operandLimit int) (*MetadataPolicy, error) {
	if policy == nil {
		return nil, nil
	}
	scopeValues := 0
	scoped := false
	for _, parameters := range policy.byEntityType() {
		operators, ok := parameters["scope"]
		if !ok {
			continue
		}
		scoped = true
		for _, operator := range operators.Metadata {
			if operator.String() == "essential" {
				continue
			}
			if err := verifyScopeOperand(operator.OperatorValue()); err != nil {
				return nil, err
			}
		}
		scopeValues += scopeValueCount(operators.Metadata)
	}
	if scopeValues > operandLimit {
		return nil, scopeValueLimitError(operandLimit)
	}
	tokenised := policy
	if scoped {
		tokenised = policy.clone()
		for _, parameters := range tokenised.byEntityType() {
			if operators, ok := parameters["scope"]; ok {
				parameters["scope"] = PolicyOperators{Metadata: tokeniseScope(operators.Metadata), Unrecognised: operators.Unrecognised}
			}
		}
	}
	for _, parameters := range tokenised.byEntityType() {
		for _, operators := range parameters {
			if err := validatePoliciesCanCombine(sortByPriority(slices.Clone(operators.Metadata))); err != nil {
				return nil, err
			}
		}
	}
	return tokenised, nil
}

func scopeValueLimitError(operandLimit int) error {
	return fmt.Errorf("%wa statement's policy operands hold more than %d values once each scope string is read as its scope values, the most one statement may hold", ErrLimitReached, operandLimit)
}

func tokeniseScope(operators []MetadataPolicyOperator) []MetadataPolicyOperator {
	tokenised := make([]MetadataPolicyOperator, 0, len(operators))
	for _, operator := range operators {
		tokenised = append(tokenised, operator.ToSlice("scope"))
	}
	return tokenised
}

func scopeValueCount(operators []MetadataPolicyOperator) int {
	count := 0
	for _, operator := range operators {
		switch typed := operator.(type) {
		case Essential:
		case Value:
			count += scopeOperandValueCount(typed.operatorValue)
		case Default:
			count += scopeOperandValueCount(typed.operatorValue)
		case Add:
			count += scopeOperandValueCount(typed.operatorValue)
		case OneOf:
			count += scopeOperandValueCount(typed.operatorValue)
		case SubsetOf:
			count += scopeOperandValueCount(typed.operatorValue)
		case SupersetOf:
			count += scopeOperandValueCount(typed.operatorValue)
		default:
			count += scopeOperandValueCount(operator.OperatorValue())
		}
	}
	return count
}

func scopeOperandValueCount(operand any) int {
	switch typed := operand.(type) {
	case nil:
		return 0
	case string:
		return scopeTokenCount(typed)
	case []any:
		count := 0
		for _, element := range typed {
			if s, ok := element.(string); ok {
				count += scopeTokenCount(s)
				continue
			}
			count++
		}
		return count
	}
	return 1
}

func scopeTokenCount(scope string) int {
	count := 0
	inToken := false
	for i := range len(scope) {
		if scope[i] == ' ' {
			inToken = false
			continue
		}
		if !inToken {
			count++
			inToken = true
		}
	}
	return count
}

func ProcessAndExtractPolicy(trustChain []EntityStatement) (*MetadataPolicy, error) {
	return processAndExtractPolicy(trustChain, DefaultMaxStatementValues)
}

func (cfg *Configuration) ProcessAndExtractPolicy(trustChain []EntityStatement) (*MetadataPolicy, error) {
	return processAndExtractPolicy(trustChain, cfg.StatementValuesLimit())
}

func processAndExtractPolicy(trustChain []EntityStatement, operandLimit int) (*MetadataPolicy, error) {
	tokenised := make([]*MetadataPolicy, len(trustChain))
	for i := range trustChain {
		policy, err := tokeniseAndValidatePolicy(trustChain[i].MetadataPolicy, operandLimit)
		if err != nil {
			return nil, err
		}
		tokenised[i] = policy
	}

	if len(trustChain) == 0 {
		return nil, fmt.Errorf("trust chain must hold at least one statement")
	}

	var finalisedPolicy *MetadataPolicy

	for i := len(trustChain) - 1; i >= 0; i-- {
		if trustChain[i].Iss == trustChain[i].Sub {
			continue
		}
		metadataPolicy := tokenised[i]
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
		return fmt.Errorf("%wthe merged list operators hold more than %d operands in total, the most one statement may hold", ErrLimitReached, operandLimit)
	}
	return nil
}

func unionOperandCount(operator MetadataPolicyOperator) int {
	switch typed := operator.(type) {
	case Add:
		return len(typed.operatorValue)
	case SupersetOf:
		return len(typed.operatorValue)
	case SubsetOf:
		return len(typed.operatorValue)
	case OneOf:
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
					mergedPolicies, err := mergeTokenisedPolicyOperators(policyOp, policies, operandLimit)
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
	if claimName == "scope" {
		for _, policySet := range []*PolicyOperators{&policySetA, &policySetB} {
			if scopeValueCount(policySet.Metadata) > operandLimit {
				return nil, scopeValueLimitError(operandLimit)
			}
			policySet.Metadata = tokeniseScope(policySet.Metadata)
		}
	}
	return mergeTokenisedPolicyOperators(policySetA, policySetB, operandLimit)
}

func mergeTokenisedPolicyOperators(policySetA, policySetB PolicyOperators, operandLimit int) ([]MetadataPolicyOperator, error) {
	if len(policySetA.Metadata) == 0 && len(policySetB.Metadata) == 0 {
		return nil, nil
	} else if len(policySetA.Metadata) == 0 {
		return policySetB.deepClone().Metadata, nil
	} else if len(policySetB.Metadata) == 0 {
		return policySetA.deepClone().Metadata, nil
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
	subject = subject.clone()
	if subject.Metadata == nil {
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

func (e EntityStatement) clone() EntityStatement {
	copied := e
	copied.JWKs.Keys = cloneValue(e.JWKs.Keys).([]map[string]any)
	copied.AuthorityHints = slices.Clone(e.AuthorityHints)
	copied.TrustAnchorHints = slices.Clone(e.TrustAnchorHints)
	copied.TrustMarks = slices.Clone(e.TrustMarks)
	if e.Metadata != nil {
		copied.Metadata = e.Metadata.clone()
	}
	if e.MetadataPolicy != nil {
		copied.MetadataPolicy = e.MetadataPolicy.deepClone()
	}
	if e.Constraints != nil {
		copied.Constraints = e.Constraints.clone()
	}
	if e.TrustMarkIssuers != nil {
		copied.TrustMarkIssuers = make(map[string][]EntityIdentifier, len(e.TrustMarkIssuers))
		for trustMarkType, issuers := range e.TrustMarkIssuers {
			copied.TrustMarkIssuers[trustMarkType] = slices.Clone(issuers)
		}
	}
	if e.TrustMarkOwners != nil {
		copied.TrustMarkOwners = make(map[string]TrustMarkOwner, len(e.TrustMarkOwners))
		for trustMarkType, owner := range e.TrustMarkOwners {
			owner.JWKs.Keys = cloneValue(owner.JWKs.Keys).([]map[string]any)
			owner.AdditionalClaims = cloneValue(owner.AdditionalClaims).(map[string]any)
			copied.TrustMarkOwners[trustMarkType] = owner
		}
	}
	if e.SourceEndpoint != nil {
		endpoint := *e.SourceEndpoint
		copied.SourceEndpoint = &endpoint
	}
	return copied
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
					existing = convertStringsToAnySlice(scopeTokens(existingString))
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

func convertStringsToAnySlice(input []string) []any {
	result := make([]any, len(input))
	for i, v := range input {
		result[i] = v
	}
	return result
}

func deduplicateSlice(input []any) []any {
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
			merged[parameter] = cloneValue(value)
		}
		for parameter, value := range supplied[entityType] {
			merged[parameter] = cloneValue(value)
		}
		result.setEntityType(entityType, merged)
	}
	return result
}
