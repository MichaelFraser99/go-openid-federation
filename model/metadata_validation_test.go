package model

import (
	"testing"
)

func TestVerifyRequiredClaims(t *testing.T) {
	tests := map[string]struct {
		metadata map[string]any
		keys     []string
		wantErr  bool
	}{
		"all present": {
			metadata: map[string]any{"a": 1, "b": 2},
			keys:     []string{"a", "b"},
			wantErr:  false,
		},
		"one missing": {
			metadata: map[string]any{"a": 1},
			keys:     []string{"a", "b"},
			wantErr:  true,
		},
		"no keys required": {
			metadata: map[string]any{"a": 1},
			keys:     nil,
			wantErr:  false,
		},
		"present with nil value counts as present": {
			metadata: map[string]any{"a": nil},
			keys:     []string{"a"},
			wantErr:  false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := verifyRequiredClaims(tt.metadata, tt.keys...)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyRequiredClaims() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMetadataStringSlice(t *testing.T) {
	tests := map[string]struct {
		value  any
		want   []string
		wantOk bool
	}{
		"native string slice": {
			value:  []string{"a", "b"},
			want:   []string{"a", "b"},
			wantOk: true,
		},
		"any slice of strings": {
			value:  []any{"a", "b"},
			want:   []string{"a", "b"},
			wantOk: true,
		},
		"empty any slice": {
			value:  []any{},
			want:   []string{},
			wantOk: true,
		},
		"any slice with non-string element": {
			value:  []any{"a", 1},
			want:   nil,
			wantOk: false,
		},
		"not a slice": {
			value:  "a",
			want:   nil,
			wantOk: false,
		},
		"int slice": {
			value:  []int{1, 2},
			want:   nil,
			wantOk: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := metadataStringSlice(tt.value)
			if ok != tt.wantOk {
				t.Fatalf("metadataStringSlice() ok = %v, want %v", ok, tt.wantOk)
			}
			if !ok {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("metadataStringSlice() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("metadataStringSlice()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestVerifyStringArrayClaim(t *testing.T) {
	tests := map[string]struct {
		metadata map[string]any
		wantErr  bool
	}{
		"absent claim is valid": {
			metadata: map[string]any{},
			wantErr:  false,
		},
		"nil claim is valid": {
			metadata: map[string]any{"k": nil},
			wantErr:  false,
		},
		"any slice of strings": {
			metadata: map[string]any{"k": []any{"a", "b"}},
			wantErr:  false,
		},
		"native string slice": {
			metadata: map[string]any{"k": []string{"a"}},
			wantErr:  false,
		},
		"scalar string is invalid": {
			metadata: map[string]any{"k": "a"},
			wantErr:  true,
		},
		"slice with non-string is invalid": {
			metadata: map[string]any{"k": []any{"a", 1}},
			wantErr:  true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := verifyStringArrayClaim(tt.metadata, "k")
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyStringArrayClaim() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyNonEmptyStringArrayClaim(t *testing.T) {
	tests := map[string]struct {
		metadata map[string]any
		wantErr  bool
	}{
		"absent claim is valid": {
			metadata: map[string]any{},
			wantErr:  false,
		},
		"non-empty slice is valid": {
			metadata: map[string]any{"k": []any{"a"}},
			wantErr:  false,
		},
		"empty slice is invalid": {
			metadata: map[string]any{"k": []any{}},
			wantErr:  true,
		},
		"non-array is invalid": {
			metadata: map[string]any{"k": "a"},
			wantErr:  true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := verifyNonEmptyStringArrayClaim(tt.metadata, "k")
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyNonEmptyStringArrayClaim() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyObjectClaim(t *testing.T) {
	tests := map[string]struct {
		metadata map[string]any
		wantErr  bool
	}{
		"absent claim is valid": {
			metadata: map[string]any{},
			wantErr:  false,
		},
		"nil claim is valid": {
			metadata: map[string]any{"k": nil},
			wantErr:  false,
		},
		"object is valid": {
			metadata: map[string]any{"k": map[string]any{"a": 1}},
			wantErr:  false,
		},
		"array is invalid": {
			metadata: map[string]any{"k": []any{"a"}},
			wantErr:  true,
		},
		"scalar is invalid": {
			metadata: map[string]any{"k": "a"},
			wantErr:  true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := verifyObjectClaim(tt.metadata, "k")
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyObjectClaim() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyHTTPSURLValue(t *testing.T) {
	tests := map[string]struct {
		value      any
		allowQuery bool
		wantErr    bool
	}{
		"valid https": {
			value:      "https://example.com/path",
			allowQuery: false,
			wantErr:    false,
		},
		"http rejected": {
			value:      "http://example.com",
			allowQuery: false,
			wantErr:    true,
		},
		"non-string rejected": {
			value:      123,
			allowQuery: false,
			wantErr:    true,
		},
		"query rejected when disallowed": {
			value:      "https://example.com?a=b",
			allowQuery: false,
			wantErr:    true,
		},
		"query allowed when permitted": {
			value:      "https://example.com?a=b",
			allowQuery: true,
			wantErr:    false,
		},
		"fragment always rejected": {
			value:      "https://example.com#frag",
			allowQuery: true,
			wantErr:    true,
		},
		"port and path allowed": {
			value:      "https://example.com:8443/a/b",
			allowQuery: false,
			wantErr:    false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := verifyHTTPSURLValue("k", tt.value, tt.allowQuery)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyHTTPSURLValue() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyHTTPSURLClaim(t *testing.T) {
	tests := map[string]struct {
		metadata   map[string]any
		allowQuery bool
		wantErr    bool
	}{
		"absent claim is valid": {
			metadata:   map[string]any{},
			allowQuery: false,
			wantErr:    false,
		},
		"nil claim is valid": {
			metadata:   map[string]any{"k": nil},
			allowQuery: false,
			wantErr:    false,
		},
		"present and valid": {
			metadata:   map[string]any{"k": "https://example.com"},
			allowQuery: false,
			wantErr:    false,
		},
		"present and invalid": {
			metadata:   map[string]any{"k": "http://example.com"},
			allowQuery: false,
			wantErr:    true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := verifyHTTPSURLClaim(tt.metadata, "k", tt.allowQuery)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyHTTPSURLClaim() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyAlgValuesClaim(t *testing.T) {
	tests := map[string]struct {
		metadata  map[string]any
		allowNone bool
		wantErr   bool
	}{
		"absent claim is valid": {
			metadata:  map[string]any{},
			allowNone: false,
			wantErr:   false,
		},
		"valid algs": {
			metadata:  map[string]any{"k": []any{"RS256", "ES256"}},
			allowNone: false,
			wantErr:   false,
		},
		"none rejected when disallowed": {
			metadata:  map[string]any{"k": []any{"RS256", "none"}},
			allowNone: false,
			wantErr:   true,
		},
		"none allowed when permitted": {
			metadata:  map[string]any{"k": []any{"none"}},
			allowNone: true,
			wantErr:   false,
		},
		"non-array is invalid": {
			metadata:  map[string]any{"k": "RS256"},
			allowNone: false,
			wantErr:   true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := verifyAlgValuesClaim(tt.metadata, "k", tt.allowNone)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyAlgValuesClaim() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHasKeyMechanism(t *testing.T) {
	tests := map[string]struct {
		metadata map[string]any
		want     bool
	}{
		"none present": {
			metadata: map[string]any{"issuer": "https://example.com"},
			want:     false,
		},
		"jwks present": {
			metadata: map[string]any{"jwks": map[string]any{}},
			want:     true,
		},
		"jwks_uri present": {
			metadata: map[string]any{"jwks_uri": "https://example.com/jwks"},
			want:     true,
		},
		"signed_jwks_uri present": {
			metadata: map[string]any{"signed_jwks_uri": "https://example.com/jwks.jose"},
			want:     true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := hasKeyMechanism(tt.metadata); got != tt.want {
				t.Errorf("hasKeyMechanism() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResponseTypesRequireTokenEndpoint(t *testing.T) {
	tests := map[string]struct {
		metadata map[string]any
		want     bool
	}{
		"absent response types defaults to required": {
			metadata: map[string]any{},
			want:     true,
		},
		"code requires token endpoint": {
			metadata: map[string]any{"response_types_supported": []any{"code"}},
			want:     true,
		},
		"hybrid containing code requires token endpoint": {
			metadata: map[string]any{"response_types_supported": []any{"code id_token"}},
			want:     true,
		},
		"implicit only does not require token endpoint": {
			metadata: map[string]any{"response_types_supported": []any{"id_token", "id_token token"}},
			want:     false,
		},
		"oauth implicit token only does not require token endpoint": {
			metadata: map[string]any{"response_types_supported": []any{"token"}},
			want:     false,
		},
		"malformed response types defaults to required": {
			metadata: map[string]any{"response_types_supported": "code"},
			want:     true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := responseTypesRequireTokenEndpoint(tt.metadata); got != tt.want {
				t.Errorf("responseTypesRequireTokenEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}
