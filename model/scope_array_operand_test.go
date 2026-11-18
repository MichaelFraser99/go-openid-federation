package model

import (
	"encoding/json"
	"testing"
)

func TestProcessAndExtractPolicy_AScopeArrayElementIsSplitUnderValueAndDefault(t *testing.T) {
	tests := []struct {
		name      string
		authority string
		superior  string
		expect    string
	}{
		{
			name:      "an array value holding one string of two scope values, with add",
			authority: `{"value":["openid profile"],"add":["openid"]}`,
			expect:    "openid profile",
		},
		{
			name:      "an array value holding one string of two scope values, with subset_of",
			authority: `{"value":["openid profile"],"subset_of":["openid","profile"]}`,
			expect:    "openid profile",
		},
		{
			name:      "an array value holding one string of two scope values, with superset_of",
			authority: `{"value":["openid profile"],"superset_of":["profile"]}`,
			expect:    "openid profile",
		},
		{
			name:      "an array default holding one string of two scope values, with subset_of",
			authority: `{"default":["openid profile"],"subset_of":["openid","profile"]}`,
			expect:    "openid profile",
		},
		{
			name:      "an array value merged with the string value of the same scope values",
			authority: `{"value":["openid profile"]}`,
			superior:  `{"value":"openid profile"}`,
			expect:    "openid profile",
		},
		{
			name:      "an array default merged with the array default of the same scope values",
			authority: `{"default":["openid profile"]}`,
			superior:  `{"default":["openid","profile"]}`,
			expect:    "openid profile",
		},
		{
			name:      "an array value under a superior subset_of",
			authority: `{"value":["openid profile"]}`,
			superior:  `{"subset_of":["openid","profile","email"]}`,
			expect:    "openid profile",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var leaf EntityStatement
			if err := json.Unmarshal([]byte(`{"iss":"https://leaf.example.com","sub":"https://leaf.example.com","iat":1,"exp":99999999999,"jwks":{"keys":[]},"metadata":{"oauth_client":{"redirect_uris":["https://leaf.example.com/cb"]}}}`), &leaf); err != nil {
				t.Fatalf("failed to parse the fixture subject: %v", err)
			}
			chain := []EntityStatement{leaf, scopePolicyStatement(t, tc.authority)}
			if tc.superior != "" {
				chain = append(chain, scopePolicyStatement(t, tc.superior))
			}

			merged, err := ProcessAndExtractPolicy(chain)
			if err != nil {
				t.Fatalf("[6.1.3.1.8] policy operators process scope as an array of scope values, so an array element holding two is two values: %v", err)
			}
			applied, err := ApplyPolicy(leaf, *merged)
			if err != nil {
				t.Fatalf("[6.1.3.1.8] expected the merged policy to apply, got %v", err)
			}
			if got, _ := (*applied.Metadata.OAuthClientMetadata)["scope"].(string); got != tc.expect {
				t.Errorf("[6.1.3.1.8] expected scope %q, got %q", tc.expect, got)
			}
		})
	}
}

func TestToSlice_SplitsAScopeArrayElementForValueAndDefault(t *testing.T) {
	value, err := NewValue([]any{"openid profile", "email"})
	if err != nil {
		t.Fatalf("expected the value operator to build, got %v", err)
	}
	defaulted, err := NewDefault([]any{"openid profile", "email"})
	if err != nil {
		t.Fatalf("expected the default operator to build, got %v", err)
	}
	want := []any{"openid", "profile", "email"}

	for _, operator := range []MetadataPolicyOperator{*value, *defaulted} {
		if got := operator.ToSlice("scope").OperatorValue(); !jsonEqual(t, got, want) {
			t.Errorf("[6.1.3.1.8] expected %s on scope to hold the scope values %v, got %v", operator.String(), want, got)
		}
		if got := operator.ToSlice("response_types").OperatorValue(); !jsonEqual(t, got, []any{"openid profile", "email"}) {
			t.Errorf("expected %s on another parameter to keep its elements whole, got %v", operator.String(), got)
		}
	}
}

func jsonEqual(t *testing.T, got, want any) bool {
	t.Helper()
	left, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("failed to marshal %v: %v", got, err)
	}
	right, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("failed to marshal %v: %v", want, err)
	}
	return string(left) == string(right)
}
