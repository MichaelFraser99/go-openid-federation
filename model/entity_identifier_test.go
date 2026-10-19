package model

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		input    string
		validate func(t *testing.T, identifier *EntityIdentifier, err error)
	}{
		"valid entity identifier": {
			input: "https://foo.bar.com",
			validate: func(t *testing.T, identifier *EntityIdentifier, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if identifier == nil {
					t.Error("identifier should not be nil")
				}
			},
		},
		"valid entity identifier with path": {
			input: "https://foo.bar.com/path",
			validate: func(t *testing.T, identifier *EntityIdentifier, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if identifier == nil {
					t.Error("identifier should not be nil")
				}
			},
		},
		"we fail on http scheme": {
			input: "http://foo.bar.com",
			validate: func(t *testing.T, identifier *EntityIdentifier, err error) {
				if err == nil {
					t.Fatal("expected error")
				}
				if err.Error() != "entity identifiers must use the https scheme" {
					t.Errorf("expected error, got %v", err)
				}
				if identifier != nil {
					t.Error("identifier should be nil")
				}
			},
		},
		"we fail on no scheme": {
			input: "foo.bar.com",
			validate: func(t *testing.T, identifier *EntityIdentifier, err error) {
				if err == nil {
					t.Fatal("expected error")
				}
				if err.Error() != "entity identifiers must use the https scheme" {
					t.Errorf("expected error, got %v", err)
				}
				if identifier != nil {
					t.Error("identifier should be nil")
				}
			},
		},
		"we fail on other scheme": {
			input: "ftp://foo.bar.com",
			validate: func(t *testing.T, identifier *EntityIdentifier, err error) {
				if err == nil {
					t.Fatal("expected error")
				}
				if err.Error() != "entity identifiers must use the https scheme" {
					t.Errorf("expected error, got %v", err)
				}
				if identifier != nil {
					t.Error("identifier should be nil")
				}
			},
		},
		"we fail on missing host": {
			input: "https:///foo",
			validate: func(t *testing.T, identifier *EntityIdentifier, err error) {
				if err == nil {
					t.Fatal("expected error")
				}
				if err.Error() != "entity identifiers must have a host component" {
					t.Errorf("expected error, got %v", err)
				}
				if identifier != nil {
					t.Error("identifier should be nil")
				}
			},
		},
		"we fail when fragment present": {
			input: "https://foo.bar.com/path#fragment",
			validate: func(t *testing.T, identifier *EntityIdentifier, err error) {
				if err == nil {
					t.Fatal("expected error")
				}
				if err.Error() != "entity identifiers must not contain Fragment components" {
					t.Errorf("expected error, got %v", err)
				}
				if identifier != nil {
					t.Error("identifier should be nil")
				}
			},
		},
		"we fail when query present": {
			input: "https://foo.bar.com?foo=bar",
			validate: func(t *testing.T, identifier *EntityIdentifier, err error) {
				if err == nil {
					t.Fatal("expected error")
				}
				if err.Error() != "entity identifiers must not contain Query components" {
					t.Errorf("expected error, got %v", err)
				}
				if identifier != nil {
					t.Error("identifier should be nil")
				}
			},
		},
		"we fail when not a valid url": { //this is surprisingly hard to encounter - I've only included the check for coverage perfection reasons
			input: string([]byte{0x7f}),
			validate: func(t *testing.T, identifier *EntityIdentifier, err error) {
				if err == nil {
					t.Fatal("expected error")
				}
				if err.Error() != "entity identifiers must be a valid url: parse \"\\x7f\": net/url: invalid control character in URL" {
					t.Errorf("expected error, got %v", err)
				}
				if identifier != nil {
					t.Error("identifier should be nil")
				}
			},
		},
	}

	for testName, tt := range tests {
		t.Run(testName, func(t *testing.T) {
			result, err := ValidateEntityIdentifier(tt.input)
			tt.validate(t, result, err)
		})
	}
}

func TestValidateEntityIdentifier_Section1_2(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		expectErr string
	}{
		{name: "a plain https identifier", value: "https://leaf.example.com"},
		{name: "a port and path are permitted", value: "https://leaf.example.com:8443/tenant"},
		{name: "an empty host name with a port", value: "https://:443", expectErr: "host component"},
		{name: "an empty host name", value: "https://", expectErr: "host component"},
		{name: "an empty but present query", value: "https://leaf.example.com?", expectErr: "Query"},
		{name: "a populated query", value: "https://leaf.example.com?x=1", expectErr: "Query"},
		{name: "an empty but present fragment", value: "https://leaf.example.com#", expectErr: "Fragment"},
		{name: "a populated fragment", value: "https://leaf.example.com#f", expectErr: "Fragment"},
		{name: "a query inside a path", value: "https://leaf.example.com/a?b", expectErr: "Query"},
		{name: "the http scheme", value: "http://leaf.example.com", expectErr: "https scheme"},
		{name: "an opaque https url", value: "https:leaf.example.com", expectErr: "host component"},
		{name: "userinfo with a password", value: "https://leaf.example.com:secret@evil.example", expectErr: "Userinfo"},
		{name: "userinfo without a password", value: "https://leaf.example.com@evil.example", expectErr: "Userinfo"},
		{name: "an empty userinfo", value: "https://@evil.example", expectErr: "Userinfo"},
		{name: "userinfo ahead of a port", value: "https://user@evil.example:8443", expectErr: "Userinfo"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ValidateEntityIdentifier(tc.value)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("expected %q to be a valid entity identifier, got %v", tc.value, err)
				}
				if string(*parsed) != tc.value {
					t.Errorf("expected %q to be returned unchanged, got %q", tc.value, string(*parsed))
				}
				return
			}
			if err == nil {
				t.Fatalf("expected %q to be rejected, got a valid identifier", tc.value)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("expected an error about %q, got %v", tc.expectErr, err)
			}
		})
	}
}
