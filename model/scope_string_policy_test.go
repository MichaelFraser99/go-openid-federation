package model

import (
	"encoding/json"
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

func TestMergePolicyOperators_AStringScopeIsSplitWhateverOperatorFacesIt(t *testing.T) {
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
			name:      "a string default under a superior subset_of",
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
			name:      "a string subset_of, which is not an array operator value",
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
