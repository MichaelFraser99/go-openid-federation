package entity_statement

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestExtractDetails(t *testing.T) {
	// Helper to create a valid JWT token for testing
	createToken := func(head, body map[string]any) string {
		headBytes, _ := json.Marshal(head)
		bodyBytes, _ := json.Marshal(body)
		headEncoded := base64.RawURLEncoding.EncodeToString(headBytes)
		bodyEncoded := base64.RawURLEncoding.EncodeToString(bodyBytes)
		return headEncoded + "." + bodyEncoded + ".signature"
	}

	tests := map[string]struct {
		token    string
		validate func(t *testing.T, keyID, subject, issuer *string, err error)
	}{
		"extracts details from valid token": {
			token: createToken(
				map[string]any{"kid": "key-123"},
				map[string]any{"sub": "https://example.com", "iss": "https://issuer.com"},
			),
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if keyID == nil {
					t.Fatal("expected keyID to be non-nil")
				}
				if *keyID != "key-123" {
					t.Errorf("expected keyID 'key-123', got %q", *keyID)
				}
				if subject == nil {
					t.Fatal("expected subject to be non-nil")
				}
				if *subject != "https://example.com" {
					t.Errorf("expected subject 'https://example.com', got %q", *subject)
				}
				if issuer == nil {
					t.Fatal("expected issuer to be non-nil")
				}
				if *issuer != "https://issuer.com" {
					t.Errorf("expected issuer 'https://issuer.com', got %q", *issuer)
				}
			},
		},
		"extracts details with numeric kid": {
			token: createToken(
				map[string]any{"kid": "12345"},
				map[string]any{"sub": "https://example.com", "iss": "https://issuer.com"},
			),
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if keyID == nil {
					t.Fatal("expected keyID to be non-nil")
				}
				if *keyID != "12345" {
					t.Errorf("expected keyID '12345', got %q", *keyID)
				}
			},
		},
		"extracts details with special characters in URLs": {
			token: createToken(
				map[string]any{"kid": "key-abc-123"},
				map[string]any{
					"sub": "https://example.com/path/to/entity?param=value",
					"iss": "https://issuer.com/issuer",
				},
			),
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if subject == nil {
					t.Fatal("expected subject to be non-nil")
				}
				if *subject != "https://example.com/path/to/entity?param=value" {
					t.Errorf("expected subject with query params, got %q", *subject)
				}
			},
		},
		"fails on invalid JWT structure - too few parts": {
			token: "only.two",
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err == nil {
					t.Fatal("expected error for invalid JWT structure, got nil")
				}
				if keyID != nil || subject != nil || issuer != nil {
					t.Error("expected all return values to be nil on error")
				}
			},
		},
		"fails on invalid JWT structure - too many parts": {
			token: "one.two.three.four",
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err == nil {
					t.Fatal("expected error for invalid JWT structure, got nil")
				}
			},
		},
		"fails on invalid JWT structure - single part": {
			token: "onlyonepart",
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err == nil {
					t.Fatal("expected error for invalid JWT structure, got nil")
				}
			},
		},
		"fails on invalid base64 encoding in head": {
			token: "not-valid-base64.dGVzdA.signature",
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err == nil {
					t.Fatal("expected error for invalid base64 head, got nil")
				}
			},
		},
		"fails on invalid base64 encoding in body": {
			token: createToken(
				map[string]any{"kid": "key-123"},
				map[string]any{"sub": "https://example.com", "iss": "https://issuer.com"},
			)[:10] + "not-valid-base64" + ".signature",
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err == nil {
					t.Fatal("expected error for invalid base64 body, got nil")
				}
			},
		},
		"fails on invalid JSON in head": {
			token: base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." +
				base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"https://example.com","iss":"https://issuer.com"}`)) +
				".signature",
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err == nil {
					t.Fatal("expected error for invalid JSON in head, got nil")
				}
			},
		},
		"fails on invalid JSON in body": {
			token: base64.RawURLEncoding.EncodeToString([]byte(`{"kid":"key-123"}`)) + "." +
				base64.RawURLEncoding.EncodeToString([]byte("not json")) +
				".signature",
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err == nil {
					t.Fatal("expected error for invalid JSON in body, got nil")
				}
			},
		},
		"fails when kid claim is missing": {
			token: createToken(
				map[string]any{},
				map[string]any{"sub": "https://example.com", "iss": "https://issuer.com"},
			),
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err == nil {
					t.Fatal("expected error for missing kid claim, got nil")
				}
			},
		},
		"fails when sub claim is missing": {
			token: createToken(
				map[string]any{"kid": "key-123"},
				map[string]any{"iss": "https://issuer.com"},
			),
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err == nil {
					t.Fatal("expected error for missing sub claim, got nil")
				}
			},
		},
		"fails when iss claim is missing": {
			token: createToken(
				map[string]any{"kid": "key-123"},
				map[string]any{"sub": "https://example.com"},
			),
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err == nil {
					t.Fatal("expected error for missing iss claim, got nil")
				}
			},
		},
		"fails when all claims are missing": {
			token: createToken(
				map[string]any{},
				map[string]any{},
			),
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err == nil {
					t.Fatal("expected error for missing all claims, got nil")
				}
			},
		},
		"extracts details with empty string values": {
			token: createToken(
				map[string]any{"kid": ""},
				map[string]any{"sub": "", "iss": ""},
			),
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err != nil {
					t.Fatalf("expected no error for empty string values, got %q", err.Error())
				}
				if keyID == nil || subject == nil || issuer == nil {
					t.Fatal("expected all values to be non-nil")
				}
				if *keyID != "" {
					t.Errorf("expected empty keyID, got %q", *keyID)
				}
				if *subject != "" {
					t.Errorf("expected empty subject, got %q", *subject)
				}
				if *issuer != "" {
					t.Errorf("expected empty issuer, got %q", *issuer)
				}
			},
		},
		"extracts details with long values": {
			token: createToken(
				map[string]any{"kid": "very-long-key-id-with-many-characters-0123456789abcdef"},
				map[string]any{
					"sub": "https://very-long-domain-name-with-many-subdomains.example.com/very/long/path/to/entity/resource",
					"iss": "https://very-long-issuer-domain-name.example.com/issuer/path",
				},
			),
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expectedKid := "very-long-key-id-with-many-characters-0123456789abcdef"
				expectedSub := "https://very-long-domain-name-with-many-subdomains.example.com/very/long/path/to/entity/resource"
				expectedIss := "https://very-long-issuer-domain-name.example.com/issuer/path"
				if *keyID != expectedKid {
					t.Errorf("expected long keyID, got %q", *keyID)
				}
				if *subject != expectedSub {
					t.Errorf("expected long subject, got %q", *subject)
				}
				if *issuer != expectedIss {
					t.Errorf("expected long issuer, got %q", *issuer)
				}
			},
		},
		"extracts details with unicode characters": {
			token: createToken(
				map[string]any{"kid": "key-日本語-123"},
				map[string]any{
					"sub": "https://example.com/entity/日本語",
					"iss": "https://issuer.com/発行者",
				},
			),
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err != nil {
					t.Fatalf("expected no error with unicode, got %q", err.Error())
				}
				if *keyID != "key-日本語-123" {
					t.Errorf("expected keyID with unicode, got %q", *keyID)
				}
			},
		},
		"handles token with additional claims in body": {
			token: createToken(
				map[string]any{"kid": "key-123", "alg": "RS256", "typ": "JWT"},
				map[string]any{
					"sub":    "https://example.com",
					"iss":    "https://issuer.com",
					"exp":    1234567890,
					"iat":    1234567890,
					"custom": "value",
				},
			),
			validate: func(t *testing.T, keyID, subject, issuer *string, err error) {
				if err != nil {
					t.Fatalf("expected no error with additional claims, got %q", err.Error())
				}
				if *keyID != "key-123" {
					t.Errorf("expected keyID 'key-123', got %q", *keyID)
				}
				if *subject != "https://example.com" {
					t.Errorf("expected subject 'https://example.com', got %q", *subject)
				}
				if *issuer != "https://issuer.com" {
					t.Errorf("expected issuer 'https://issuer.com', got %q", *issuer)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			keyID, subject, issuer, err := ExtractDetails(tt.token)
			tt.validate(t, keyID, subject, issuer, err)
		})
	}
}
