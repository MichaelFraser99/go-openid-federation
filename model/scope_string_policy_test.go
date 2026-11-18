package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func scopePolicyStatement(t *testing.T, policy string) EntityStatement {
	t.Helper()
	var statement EntityStatement
	raw := `{"iss":"https://ta.example.com","sub":"https://leaf.example.com","iat":1,"exp":99999999999,"jwks":{"keys":[]},"metadata_policy":{"oauth_client":{"scope":` + policy + `}}}`
	if err := json.Unmarshal([]byte(raw), &statement); err != nil {
		t.Fatalf("failed to parse the fixture policy: %v", err)
	}
	return statement
}

func scopeSubject(t *testing.T, scope string) EntityStatement {
	t.Helper()
	var statement EntityStatement
	raw := `{"iss":"https://leaf.example.com","sub":"https://leaf.example.com","iat":1,"exp":99999999999,"jwks":{"keys":[]},"metadata":{"oauth_client":{"redirect_uris":["https://leaf.example.com/cb"],"scope":"` + scope + `"}}}`
	if err := json.Unmarshal([]byte(raw), &statement); err != nil {
		t.Fatalf("failed to parse the fixture subject: %v", err)
	}
	return statement
}

func TestProcessAndExtractPolicy_AStringScopeIsSplitWhateverOperatorFacesIt(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		superior  string
		authority string
		expect    string
	}{
		{
			name:      "a string value under a superior subset_of",
			reference: "6.1.3.1.8",
			superior:  `{"subset_of":["openid","offline_access","profile"]}`,
			authority: `{"value":"openid offline_access"}`,
			expect:    "openid offline_access",
		},
		{
			name:      "a string value over a subordinate subset_of",
			reference: "6.1.3.1.8",
			superior:  `{"value":"openid offline_access"}`,
			authority: `{"subset_of":["openid","offline_access","profile"]}`,
			expect:    "openid offline_access",
		},
		{
			name:      "a string value under a superior superset_of",
			reference: "6.1.3.1.8",
			superior:  `{"superset_of":["openid"]}`,
			authority: `{"value":"openid offline_access"}`,
			expect:    "openid offline_access",
		},
		{
			name:      "a string value under a superior add",
			reference: "6.1.3.1.8",
			superior:  `{"add":["openid"]}`,
			authority: `{"value":"openid offline_access"}`,
			expect:    "openid offline_access",
		},
		{
			name:      "a string default under a superior subset_of, which resolve-time conversion already handled",
			reference: "6.1.3.1.8",
			superior:  `{"subset_of":["openid","offline_access","profile"]}`,
			authority: `{"default":"openid offline_access"}`,
			expect:    "openid offline_access profile",
		},
		{
			name:      "an array value, which already worked",
			reference: "6.1.3.1.8",
			superior:  `{"subset_of":["openid","offline_access","profile"]}`,
			authority: `{"value":["openid","offline_access"]}`,
			expect:    "openid offline_access",
		},
		{
			name:      "two array operators, which need no conversion",
			reference: "6.1.3.1.5",
			superior:  `{"subset_of":["openid","offline_access","profile"]}`,
			authority: `{"superset_of":["openid"]}`,
			expect:    "openid offline_access profile",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := scopeSubject(t, "openid offline_access profile")

			merged, err := ProcessAndExtractPolicy([]EntityStatement{
				leaf,
				scopePolicyStatement(t, tc.authority),
				scopePolicyStatement(t, tc.superior),
			})
			if err != nil {
				t.Fatalf("[%s] the scope parameter is to be processed as a string array by policy operators, so a space-separated string must merge: %v", tc.reference, err)
			}

			applied, err := ApplyPolicy(leaf, *merged)
			if err != nil {
				t.Fatalf("[%s] expected the merged policy to apply, got %v", tc.reference, err)
			}

			got, _ := (*applied.Metadata.OAuthClientMetadata)["scope"].(string)
			if got != tc.expect {
				t.Errorf("[%s] expected scope %q, got %q", tc.reference, tc.expect, got)
			}
		})
	}
}

func TestProcessAndExtractPolicy_AStringScopeIsSplitWithinOneStatement(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		policy    string
		expect    string
		expectErr bool
	}{
		{
			name:      "a string value beside subset_of",
			reference: "6.1.3.1.8",
			policy:    `{"value":"openid offline_access","subset_of":["openid","offline_access","profile"]}`,
			expect:    "openid offline_access",
		},
		{
			name:      "a string value beside superset_of",
			reference: "6.1.3.1.8",
			policy:    `{"value":"openid offline_access","superset_of":["openid"]}`,
			expect:    "openid offline_access",
		},
		{
			name:      "a string value beside add",
			reference: "6.1.3.1.8",
			policy:    `{"value":"openid offline_access","add":["openid"]}`,
			expect:    "openid offline_access",
		},
		{
			name:      "a string value that is not a subset of subset_of",
			reference: "6.1.3.1.1",
			policy:    `{"value":"openid admin","subset_of":["openid","offline_access"]}`,
			expectErr: true,
		},
		{
			name:      "a string value that is not a superset of superset_of",
			reference: "6.1.3.1.1",
			policy:    `{"value":"openid","superset_of":["openid","profile"]}`,
			expectErr: true,
		},
		{
			name:      "an add that is not a subset of a string value",
			reference: "6.1.3.1.2",
			policy:    `{"value":"openid offline_access","add":["profile"]}`,
			expectErr: true,
		},
		{
			name:      "an add that is not a subset of subset_of",
			reference: "6.1.3.1.2",
			policy:    `{"add":["admin"],"subset_of":["openid"]}`,
			expectErr: true,
		},
		{
			name:      "a null value beside a default",
			reference: "6.1.3.1.3",
			policy:    `{"value":null,"default":"openid"}`,
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := scopeSubject(t, "openid offline_access profile")

			merged, err := ProcessAndExtractPolicy([]EntityStatement{leaf, scopePolicyStatement(t, tc.policy)})
			if tc.expectErr {
				if err == nil {
					t.Fatalf("[%s] section 6.1.3.1 makes this combination a policy error, so splitting the string must not make it merge", tc.reference)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] a string scope must be split before one statement's own operators are checked against each other: %v", tc.reference, err)
			}

			applied, err := ApplyPolicy(leaf, *merged)
			if err != nil {
				t.Fatalf("[%s] expected the policy to apply, got %v", tc.reference, err)
			}
			got, _ := (*applied.Metadata.OAuthClientMetadata)["scope"].(string)
			if got != tc.expect {
				t.Errorf("[%s] expected scope %q, got %q", tc.reference, tc.expect, got)
			}
		})
	}
}

func TestProcessAndExtractPolicy_AScopeStringIsTokenisedTheSameWayEverywhere(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		superior  string
		authority string
		subject   string
		expect    string
	}{
		{
			name:      "a trailing space in an operator value",
			reference: "RFC 7591 2",
			superior:  `{"subset_of":["openid","profile"]}`,
			authority: `{"value":"openid profile "}`,
			subject:   "openid profile",
			expect:    "openid profile",
		},
		{
			name:      "a leading space in an operator value",
			reference: "RFC 7591 2",
			superior:  `{"subset_of":["openid","profile"]}`,
			authority: `{"value":" openid profile"}`,
			subject:   "openid profile",
			expect:    "openid profile",
		},
		{
			name:      "a double space in an operator value",
			reference: "RFC 7591 2",
			superior:  `{"subset_of":["openid","profile"]}`,
			authority: `{"value":"openid  profile"}`,
			subject:   "openid profile",
			expect:    "openid profile",
		},
		{
			name:      "irregular whitespace in the subject's own scope",
			reference: "RFC 7591 2",
			superior:  `{"subset_of":["openid","profile"]}`,
			authority: `{"value":"openid profile"}`,
			subject:   "openid  profile ",
			expect:    "openid profile",
		},
		{
			name:      "irregular whitespace in a subject's scope an operator reads",
			reference: "RFC 7591 2",
			superior:  `{"subset_of":["openid","profile"]}`,
			authority: `{"subset_of":["openid","profile"]}`,
			subject:   "openid  profile ",
			expect:    "openid profile",
		},
		{
			name:      "two values that differ only in whitespace",
			reference: "6.1.3.1.1",
			superior:  `{"value":"openid profile"}`,
			authority: `{"value":"openid profile "}`,
			subject:   "openid profile",
			expect:    "openid profile",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := scopeSubject(t, tc.subject)

			merged, err := ProcessAndExtractPolicy([]EntityStatement{
				leaf,
				scopePolicyStatement(t, tc.authority),
				scopePolicyStatement(t, tc.superior),
			})
			if err != nil {
				t.Fatalf("[%s] a scope string is a list of space-separated values, so irregular whitespace must not make a chain unresolvable: %v", tc.reference, err)
			}

			applied, err := ApplyPolicy(leaf, *merged)
			if err != nil {
				t.Fatalf("[%s] expected the merged policy to apply, got %v", tc.reference, err)
			}
			got, _ := (*applied.Metadata.OAuthClientMetadata)["scope"].(string)
			if got != tc.expect {
				t.Errorf("[%s] expected scope %q, got %q", tc.reference, tc.expect, got)
			}
		})
	}
}

func TestToSlice_ReturnsAValueTypeAndToleratesANilOperand(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		operator  MetadataPolicyOperator
	}{
		{name: "a value with a nil operand", reference: "6.1.3.1.1", operator: Value{}},
		{name: "a default with a nil operand", reference: "6.1.3.1.3", operator: Default{}},
		{name: "an add", reference: "6.1.3.1.2", operator: Add{}},
		{name: "a one_of", reference: "6.1.3.1.4", operator: OneOf{}},
		{name: "a subset_of", reference: "6.1.3.1.5", operator: SubsetOf{}},
		{name: "a superset_of", reference: "6.1.3.1.6", operator: SupersetOf{}},
		{name: "an essential", reference: "6.1.3.1.7", operator: Essential{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("[%s] converting an operator with no operand panicked: %v", tc.reference, recovered)
				}
			}()

			converted := tc.operator.ToSlice("scope")
			if reflect.TypeOf(converted).Kind() == reflect.Pointer {
				t.Errorf("[%s] a converted operator must keep the receiver shape the others use, or a reflect.TypeOf lookup in metadataPolicySetContains misses it and a consumer's type assertion panics, got %T", tc.reference, converted)
			}
			if _, found := metadataPolicySetContains([]MetadataPolicyOperator{converted}, reflect.TypeOf(tc.operator)); !found {
				t.Errorf("[%s] a converted operator must still be found by a lookup for its own type, got %T", tc.reference, converted)
			}
		})
	}
}

func TestToSlice_ConvertsAStringOperandForEveryOperatorThatHoldsOne(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		key       string
		operator  MetadataPolicyOperator
		expect    []any
	}{
		{name: "a value holding a scope string", reference: "6.1.3.1.8", key: "scope", operator: Value{operatorValue: "openid profile"}, expect: []any{"openid", "profile"}},
		{name: "a default holding a scope string", reference: "6.1.3.1.8", key: "scope", operator: Default{operatorValue: "openid profile"}, expect: []any{"openid", "profile"}},
		{name: "a value holding irregular whitespace", reference: "RFC 7591 2", key: "scope", operator: Value{operatorValue: " openid  profile "}, expect: []any{"openid", "profile"}},
		{name: "a value already holding an array", reference: "6.1.3.1.8", key: "scope", operator: Value{operatorValue: []any{"openid", "profile"}}, expect: []any{"openid", "profile"}},
		{name: "a value holding a single value for a parameter that is not scope", reference: "6.1.3.1.1", key: "acr_values", operator: Value{operatorValue: "urn:example:loa2"}, expect: []any{"urn:example:loa2"}},
		{name: "a default holding a single value for a parameter that is not scope", reference: "6.1.3.1.3", key: "acr_values", operator: Default{operatorValue: "urn:example:loa2"}, expect: []any{"urn:example:loa2"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			converted := tc.operator.ToSlice(tc.key)
			got, ok := converted.OperatorValue().([]any)
			if !ok {
				t.Fatalf("[%s] expected a slice operand, got %T", tc.reference, converted.OperatorValue())
			}
			if !reflect.DeepEqual(got, tc.expect) {
				t.Errorf("[%s] expected %v, got %v", tc.reference, tc.expect, got)
			}
			if reflect.TypeOf(converted).Kind() == reflect.Pointer {
				t.Errorf("[%s] converting a string operand must keep the receiver shape the others use, or a reflect.TypeOf lookup in metadataPolicySetContains misses it and a consumer's type assertion panics, got %T", tc.reference, converted)
			}
			if _, found := metadataPolicySetContains([]MetadataPolicyOperator{converted}, reflect.TypeOf(tc.operator)); !found {
				t.Errorf("[%s] a converted operator must still be found by a lookup for its own type, got %T", tc.reference, converted)
			}
		})
	}
}

func TestScopeTokens_TheDelimiterIsOneAsciiSpaceAndNothingElse(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		scope     string
		expect    []string
	}{
		{name: "one space between tokens", reference: "RFC 6749 3.3", scope: "openid profile", expect: []string{"openid", "profile"}},
		{name: "a trailing space", reference: "RFC 6749 3.3", scope: "openid profile ", expect: []string{"openid", "profile"}},
		{name: "a leading space", reference: "RFC 6749 3.3", scope: " openid profile", expect: []string{"openid", "profile"}},
		{name: "a run of spaces", reference: "RFC 6749 3.3", scope: "openid  profile", expect: []string{"openid", "profile"}},
		{name: "only spaces", reference: "RFC 6749 3.3", scope: "   ", expect: []string{}},
		{name: "a single token", reference: "RFC 6749 3.3", scope: "openid", expect: []string{"openid"}},
		{name: "a no-break space is not a delimiter", reference: "RFC 6749 3.3", scope: "openid profile", expect: []string{"openid profile"}},
		{name: "a line separator is not a delimiter", reference: "RFC 6749 3.3", scope: "openid profile", expect: []string{"openid profile"}},
		{name: "an ideographic space is not a delimiter", reference: "RFC 6749 3.3", scope: "openid　profile", expect: []string{"openid　profile"}},
		{name: "a tab is not a delimiter", reference: "RFC 6749 3.3", scope: "openid\tprofile", expect: []string{"openid\tprofile"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scopeTokens(tc.scope)
			if !reflect.DeepEqual(got, tc.expect) {
				t.Errorf("[%s] scope-token admits no whitespace and the delimiter is one SP, so only an ASCII space separates tokens: expected %q, got %q", tc.reference, tc.expect, got)
			}
		})
	}
}

func TestApplyPolicy_AnInvalidScopeTokenDoesNotClearAnAllowList(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		subject   string
		expect    string
	}{
		{name: "a no-break space inside a token", reference: "RFC 6749 3.3", subject: "openid profile", expect: ""},
		{name: "a line separator inside a token", reference: "RFC 6749 3.3", subject: "openid profile", expect: ""},
		{name: "an ideographic space inside a token", reference: "RFC 6749 3.3", subject: "openid　profile", expect: ""},
		{name: "spaces around valid tokens", reference: "RFC 6749 3.3", subject: " openid  profile ", expect: "openid profile"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := scopeSubject(t, tc.subject)

			merged, err := ProcessAndExtractPolicy([]EntityStatement{leaf, scopePolicyStatement(t, `{"subset_of":["openid","profile"]}`)})
			if err != nil {
				t.Fatalf("[%s] expected the policy to merge, got %v", tc.reference, err)
			}

			applied, err := ApplyPolicy(leaf, *merged)
			if err != nil {
				t.Fatalf("[%s] expected the merged policy to apply, got %v", tc.reference, err)
			}

			got, _ := (*applied.Metadata.OAuthClientMetadata)["scope"].(string)
			if got != tc.expect {
				t.Errorf("[%s] a token holding a character scope-token does not admit must not be split into tokens the policy allows: expected %q, got %q", tc.reference, tc.expect, got)
			}
		})
	}
}

func TestApplyPolicy_ReadsEveryScopeOperandElementAsScopeTokens(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		subject string
		expect  string
		fault   string
		leaks   []string
	}{
		{name: "a subset_of element holding two tokens", policy: `{"subset_of":["openid profile"]}`, subject: "openid profile", expect: "openid profile"},
		{name: "a subset_of element holding three tokens against one", policy: `{"subset_of":["openid profile email"]}`, subject: "openid", expect: "openid"},
		{name: "a superset_of element holding two tokens, both held", policy: `{"superset_of":["openid profile"]}`, subject: "openid profile", expect: "openid profile"},
		{name: "a superset_of element holding two tokens, one held", policy: `{"superset_of":["openid profile"]}`, subject: "openid", fault: "not a superset", leaks: []string{"openid profile"}},
		{name: "a superset_of value with a trailing space", policy: `{"superset_of":["openid "]}`, subject: "openid profile", expect: "openid profile"},
		{name: "a superset_of value with a leading space", policy: `{"superset_of":[" openid"]}`, subject: "openid profile", expect: "openid profile"},
		{name: "a superset_of holding only an empty value", policy: `{"superset_of":[""]}`, subject: "openid profile", expect: "openid profile"},
		{name: "a superset_of holding an empty value beside a real one", policy: `{"superset_of":["","openid"]}`, subject: "openid profile", expect: "openid profile"},
		{name: "a superset_of holding only spaces", policy: `{"superset_of":["   "]}`, subject: "openid profile", expect: "openid profile"},
		{name: "a superset_of holding a tab, which is not a delimiter", policy: `{"superset_of":["\t"]}`, subject: "openid profile", fault: "not a superset"},
		{name: "a superset_of value holding a no-break space, which is not a delimiter", policy: `{"superset_of":["openid\u00a0profile"]}`, subject: "openid profile", fault: "not a superset"},
		{name: "an add element holding two tokens", policy: `{"add":["email phone"]}`, subject: "openid", expect: "openid email phone"},
		{name: "an add element holding two tokens beside a subset_of that allows each", policy: `{"add":["openid email"],"subset_of":["openid","email","profile"]}`, subject: "openid", expect: "openid email"},
		{name: "a one_of element holding two tokens on a present scope", policy: `{"one_of":["openid profile"]}`, subject: "openid", fault: "one_of cannot be applied to scope", leaks: []string{"openid profile"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := scopeSubject(t, tc.subject)

			merged, err := ProcessAndExtractPolicy([]EntityStatement{leaf, scopePolicyStatement(t, tc.policy)})
			if err != nil {
				t.Fatalf("[6.1.3.1.8] expected a scope operand to be read as scope tokens rather than refused, got %v", err)
			}
			applied, err := ApplyPolicy(leaf, *merged)
			if tc.fault != "" {
				if err == nil || !strings.Contains(err.Error(), tc.fault) {
					t.Fatalf("[6.1.3] expected a policy error naming %q, got %v", tc.fault, err)
				}
				for _, operand := range tc.leaks {
					if strings.Contains(err.Error(), operand) {
						t.Errorf("a superior writes this operand, so no part of it may appear in the error: %v", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the policy to apply, got %v", err)
			}
			if got, _ := (*applied.Metadata.OAuthClientMetadata)["scope"].(string); got != tc.expect {
				t.Errorf("[RFC 6749 3.3] expected scope %q, got %q", tc.expect, got)
			}
		})
	}
}

func TestProcessAndExtractPolicy_AnOperandTheSubjectNeedNotMatchIsLeftAlone(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		policy    string
		subject   string
		expect    string
	}{
		{name: "a subset_of holding an empty value beside a real one", reference: "6.1.3.1.5", policy: `{"subset_of":["openid",""]}`, subject: "openid", expect: "openid"},
		{name: "an array value holding an empty value", reference: "6.1.3.1.1", policy: `{"value":["openid",""]}`, subject: "openid", expect: "openid"},
		{name: "an add holding an empty value", reference: "6.1.3.1.2", policy: `{"add":[""]}`, subject: "openid", expect: "openid"},
		{name: "a subset_of holding whitespace beside a real one", reference: "6.1.3.1.5", policy: `{"subset_of":["openid","   "]}`, subject: "openid", expect: "openid"},
		{name: "an add holding a value with a trailing space", reference: "6.1.3.1.2", policy: `{"add":["admin "]}`, subject: "openid", expect: "openid admin"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := scopeSubject(t, tc.subject)

			merged, err := ProcessAndExtractPolicy([]EntityStatement{leaf, scopePolicyStatement(t, tc.policy)})
			if err != nil {
				t.Fatalf("[%s] an operator that intersects, unions or supplies its operand is not made unsatisfiable by an element the subject lacks, so the policy must stand: %v", tc.reference, err)
			}

			applied, err := ApplyPolicy(leaf, *merged)
			if err != nil {
				t.Fatalf("[%s] expected the merged policy to apply, got %v", tc.reference, err)
			}

			got, _ := (*applied.Metadata.OAuthClientMetadata)["scope"].(string)
			if got != tc.expect {
				t.Errorf("[%s] expected scope %q, got %q", tc.reference, tc.expect, got)
			}
		})
	}
}

func TestApplyPolicy_TheResolvedScopeHoldsWhatThePolicySaid(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		policy    string
		subject   string
		expect    string
	}{
		{name: "an array value holding a no-break space", reference: "RFC 6749 3.3", policy: `{"value":["openid profile"]}`, subject: "openid", expect: "openid profile"},
		{name: "a string value holding a no-break space", reference: "RFC 6749 3.3", policy: `{"value":"openid profile"}`, subject: "openid", expect: "openid profile"},
		{name: "an add holding a no-break space", reference: "6.1.3.1.2", policy: `{"add":["openid profile"]}`, subject: "openid", expect: "openid openid profile"},
		{name: "an array value holding a scope set", reference: "6.1.3.1.1", policy: `{"value":["openid","openid accounts"]}`, subject: "openid", expect: "openid accounts"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := scopeSubject(t, tc.subject)

			merged, err := ProcessAndExtractPolicy([]EntityStatement{leaf, scopePolicyStatement(t, tc.policy)})
			if err != nil {
				t.Fatalf("[%s] expected the policy to merge, got %v", tc.reference, err)
			}

			applied, err := ApplyPolicy(leaf, *merged)
			if err != nil {
				t.Fatalf("[%s] expected the merged policy to apply, got %v", tc.reference, err)
			}

			got, _ := (*applied.Metadata.OAuthClientMetadata)["scope"].(string)
			if got != tc.expect {
				t.Errorf("[%s] the value an operator supplied must reach the resolved scope as the policy wrote it, not re-split on a character that does not separate scope values: expected %q, got %q", tc.reference, tc.expect, got)
			}
		})
	}
}

func TestProcessAndExtractPolicy_ReadsAOneOfScopeElementAsTokensWhenMerging(t *testing.T) {
	var leaf EntityStatement
	if err := json.Unmarshal([]byte(`{"iss":"https://leaf.example.com","sub":"https://leaf.example.com","iat":1,"exp":99999999999,"jwks":{"keys":[]},"metadata":{"oauth_client":{"redirect_uris":["https://leaf.example.com/cb"]}}}`), &leaf); err != nil {
		t.Fatalf("failed to parse the fixture subject: %v", err)
	}
	merged, err := ProcessAndExtractPolicy([]EntityStatement{leaf, scopePolicyStatement(t, `{"one_of":["openid"]}`), scopePolicyStatement(t, `{"one_of":["openid profile"]}`)})
	if err != nil {
		t.Fatalf("[6.1.3.1.8] expected the one_of element to be read as tokens, so that the merged intersection holds openid, got %v", err)
	}
	applied, err := ApplyPolicy(leaf, *merged)
	if err != nil {
		t.Fatalf("[6.1.3.1.4] expected one_of to have no effect on an absent scope, got %v", err)
	}
	if scope, present := (*applied.Metadata.OAuthClientMetadata)["scope"]; present {
		t.Errorf("expected no scope, got %#v", scope)
	}
}

func TestApplyPolicy_DoesNotTokeniseAnOperandOnAnotherParameter(t *testing.T) {
	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(`{"oauth_client":{"response_types":{"subset_of":["code id_token","code"]}}}`), &policy); err != nil {
		t.Fatalf("failed to parse the policy: %v", err)
	}
	metadata := map[string]any{"response_types": []any{"code id_token", "token"}}
	if err := applyPolicyToMetadata(metadata, policy.OAuthClientMetadata); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, ok := metadata["response_types"].([]any); !ok || len(got) != 1 || got[0] != "code id_token" {
		t.Errorf("[6.1.3.1.8] only scope is a space-separated list, so a response type holding a space is one value, got %#v", metadata["response_types"])
	}
}

func TestToSlice_TokenisesOnlyScope(t *testing.T) {
	operand := []any{"code id_token", "code"}
	tests := map[string]struct {
		build func() (MetadataPolicyOperator, error)
		scope []any
	}{
		"add":         {build: func() (MetadataPolicyOperator, error) { o, err := NewAdd(operand); return *o, err }, scope: []any{"code", "id_token", "code"}},
		"one_of":      {build: func() (MetadataPolicyOperator, error) { o, err := NewOneOf(operand); return *o, err }, scope: []any{"code", "id_token"}},
		"subset_of":   {build: func() (MetadataPolicyOperator, error) { o, err := NewSubsetOf(operand); return *o, err }, scope: []any{"code", "id_token"}},
		"superset_of": {build: func() (MetadataPolicyOperator, error) { o, err := NewSupersetOf(operand); return *o, err }, scope: []any{"code", "id_token"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := tc.build()
			if err != nil {
				t.Fatalf("failed to build the operator: %v", err)
			}
			if got := operator.ToSlice("response_types").OperatorValue(); !reflect.DeepEqual(got, operand) {
				t.Errorf("expected another parameter's operand to stay whole, got %#v", got)
			}
			if got := operator.ToSlice("scope").OperatorValue(); !reflect.DeepEqual(got, tc.scope) {
				t.Errorf("[6.1.3.1.8] expected scope's operand read as tokens %#v, got %#v", tc.scope, got)
			}
		})
	}
}
