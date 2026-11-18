package model

import (
	"testing"
)

func TestVerifyScopeClaim_HoldsScopeToAtLeastOneScopeValue(t *testing.T) {
	tests := map[string]struct {
		metadata map[string]any
		valid    bool
	}{
		"absent":            {metadata: map[string]any{}, valid: true},
		"one scope value":   {metadata: map[string]any{"scope": "openid"}, valid: true},
		"two scope values":  {metadata: map[string]any{"scope": "openid profile"}, valid: true},
		"irregular spacing": {metadata: map[string]any{"scope": " openid  profile "}, valid: true},
		"empty":             {metadata: map[string]any{"scope": ""}},
		"only spaces":       {metadata: map[string]any{"scope": "   "}},
		"an array":          {metadata: map[string]any{"scope": []any{"openid"}}},
		"null":              {metadata: map[string]any{"scope": nil}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := VerifyScopeClaim(tc.metadata)
			if (err == nil) != tc.valid {
				t.Errorf("[RFC 6749 3.3, RFC 7591 2] expected valid=%v, got %v", tc.valid, err)
			}
		})
	}
}

func TestVerifyResolvedMetadata_RefusesAnEmptyScopeOnBothClientTypes(t *testing.T) {
	for entityType, verify := range map[string]func(map[string]any) error{
		"openid_relying_party": func(m map[string]any) error { return OpenIDRelyingPartyMetadata(m).VerifyResolvedMetadata() },
		"oauth_client":         func(m map[string]any) error { return OAuthClientMetadata(m).VerifyResolvedMetadata() },
	} {
		t.Run(entityType, func(t *testing.T) {
			if err := verify(map[string]any{"redirect_uris": []any{"https://leaf.example.com/cb"}, "scope": ""}); err == nil {
				t.Error("[6.1.4.2] expected an empty scope to be refused")
			}
			if err := verify(map[string]any{"redirect_uris": []any{"https://leaf.example.com/cb"}, "scope": "openid"}); err != nil {
				t.Errorf("expected a scope value to pass, got %v", err)
			}
		})
	}
}
