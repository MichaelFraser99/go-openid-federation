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
				if err.Error() != "entity identifiers must be a valid url" {
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
		{name: "a raw space in the path", value: "https://leaf.example.com/lea f", expectErr: "RFC 3986"},
		{name: "a raw space in the host", value: "https://lea f.example.com", expectErr: "valid url"},
		{name: "a less-than sign", value: "https://leaf.example.com/a<b", expectErr: "RFC 3986"},
		{name: "a greater-than sign", value: "https://leaf.example.com/a>b", expectErr: "RFC 3986"},
		{name: "a double quote", value: "https://leaf.example.com/a\"b", expectErr: "RFC 3986"},
		{name: "an opening brace", value: "https://leaf.example.com/a{b", expectErr: "RFC 3986"},
		{name: "a closing brace", value: "https://leaf.example.com/a}b", expectErr: "RFC 3986"},
		{name: "a vertical bar", value: "https://leaf.example.com/a|b", expectErr: "RFC 3986"},
		{name: "a caret", value: "https://leaf.example.com/a^b", expectErr: "RFC 3986"},
		{name: "a grave accent", value: "https://leaf.example.com/a`b", expectErr: "RFC 3986"},
		{name: "a backslash", value: "https://leaf.example.com/a\\b", expectErr: "RFC 3986"},
		{name: "an opening bracket in the path", value: "https://leaf.example.com/a[b", expectErr: "RFC 3986"},
		{name: "a closing bracket in the path", value: "https://leaf.example.com/a]b", expectErr: "RFC 3986"},
		{name: "a bracket in a host name", value: "https://a[b].example.com", expectErr: "valid url"},
		{name: "a raw non-ASCII path", value: "https://leaf.example.com/caf\u00e9", expectErr: "RFC 3986"},
		{name: "a raw non-ASCII host", value: "https://\u00e4.example.com", expectErr: "RFC 3986"},
		{name: "a percent-encoded space", value: "https://leaf.example.com/lea%20f"},
		{name: "a percent-encoded non-ASCII path", value: "https://leaf.example.com/caf%C3%A9"},
		{name: "a punycode host", value: "https://xn--4ca.example.com"},
		{name: "an IPv6 host", value: "https://[::1]"},
		{name: "an IPv6 host with a port and path", value: "https://[2001:db8::1]:8443/x"},
		{name: "every sub-delimiter in the path", value: "https://leaf.example.com/!$&'()*+,;="},
		{name: "a colon and at sign in the path", value: "https://leaf.example.com/a:b@c"},
		{name: "every unreserved symbol", value: "https://leaf.example.com/-._~"},
		{name: "an uppercase scheme", value: "HTTPS://leaf.example.com"},
		{name: "port zero", value: "https://leaf.example.com:0"},
		{name: "the highest port", value: "https://leaf.example.com:65535"},
		{name: "a port with a leading zero", value: "https://leaf.example.com:0443"},
		{name: "an empty port, which RFC 3986 permits", value: "https://leaf.example.com:"},
		{name: "a port above 65535", value: "https://leaf.example.com:65536", expectErr: "port between 0 and 65535"},
		{name: "a port too long to be a number", value: "https://leaf.example.com:99999999999999999999", expectErr: "port between 0 and 65535"},
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
