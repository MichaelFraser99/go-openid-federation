package model

import (
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
