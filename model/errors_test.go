package model

import (
	"errors"
	"testing"
)

func TestNewInvalidRequestError(t *testing.T) {
	tests := map[string]struct {
		message  string
		validate func(t *testing.T, err error)
	}{
		"creates error with message": {
			message: "test message",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidRequest) {
					t.Errorf("expected error to wrap ErrInvalidRequest")
				}
				if err.Error() != "test message" {
					t.Errorf("expected error message 'test message', got %q", err.Error())
				}
			},
		},
		"creates error with empty message": {
			message: "",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidRequest) {
					t.Errorf("expected error to wrap ErrInvalidRequest")
				}
			},
		},
		"creates error with special characters": {
			message: "error: 'test' & \"quotes\" <xml>",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidRequest) {
					t.Errorf("expected error to wrap ErrInvalidRequest")
				}
				if err.Error() != "error: 'test' & \"quotes\" <xml>" {
					t.Errorf("expected error message with special characters, got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewInvalidRequestError(tt.message)
			tt.validate(t, err)
		})
	}
}

func TestNewInvalidClientError(t *testing.T) {
	tests := map[string]struct {
		message  string
		validate func(t *testing.T, err error)
	}{
		"creates error with message": {
			message: "invalid client identifier",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidClient) {
					t.Errorf("expected error to wrap ErrInvalidClient")
				}
				if err.Error() != "invalid client identifier" {
					t.Errorf("expected error message 'invalid client identifier', got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewInvalidClientError(tt.message)
			tt.validate(t, err)
		})
	}
}

func TestNewInvalidIssuerError(t *testing.T) {
	tests := map[string]struct {
		message  string
		validate func(t *testing.T, err error)
	}{
		"creates error with message": {
			message: "issuer not recognized",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidIssuer) {
					t.Errorf("expected error to wrap ErrInvalidIssuer")
				}
				if err.Error() != "issuer not recognized" {
					t.Errorf("expected error message 'issuer not recognized', got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewInvalidIssuerError(tt.message)
			tt.validate(t, err)
		})
	}
}

func TestNewInvalidSubjectError(t *testing.T) {
	tests := map[string]struct {
		message  string
		validate func(t *testing.T, err error)
	}{
		"creates error with message": {
			message: "subject cannot be empty",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidSubject) {
					t.Errorf("expected error to wrap ErrInvalidSubject")
				}
				if err.Error() != "subject cannot be empty" {
					t.Errorf("expected error message 'subject cannot be empty', got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewInvalidSubjectError(tt.message)
			tt.validate(t, err)
		})
	}
}

func TestNewInvalidTrustAnchorError(t *testing.T) {
	tests := map[string]struct {
		message  string
		validate func(t *testing.T, err error)
	}{
		"creates error with message": {
			message: "trust anchor not in list",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidTrustAnchor) {
					t.Errorf("expected error to wrap ErrInvalidTrustAnchor")
				}
				if err.Error() != "trust anchor not in list" {
					t.Errorf("expected error message 'trust anchor not in list', got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewInvalidTrustAnchorError(tt.message)
			tt.validate(t, err)
		})
	}
}

func TestNewInvalidTrustChainError(t *testing.T) {
	tests := map[string]struct {
		message  string
		validate func(t *testing.T, err error)
	}{
		"creates error with message": {
			message: "chain validation failed",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidTrustChain) {
					t.Errorf("expected error to wrap ErrInvalidTrustChain")
				}
				if err.Error() != "chain validation failed" {
					t.Errorf("expected error message 'chain validation failed', got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewInvalidTrustChainError(tt.message)
			tt.validate(t, err)
		})
	}
}

func TestNewInvalidMetadataError(t *testing.T) {
	tests := map[string]struct {
		message  string
		validate func(t *testing.T, err error)
	}{
		"creates error with message": {
			message: "metadata missing required field",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidMetadata) {
					t.Errorf("expected error to wrap ErrInvalidMetadata")
				}
				if err.Error() != "metadata missing required field" {
					t.Errorf("expected error message 'metadata missing required field', got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewInvalidMetadataError(tt.message)
			tt.validate(t, err)
		})
	}
}

func TestNewNotFoundError(t *testing.T) {
	tests := map[string]struct {
		message  string
		validate func(t *testing.T, err error)
	}{
		"creates error with message": {
			message: "entity not found",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrNotFound) {
					t.Errorf("expected error to wrap ErrNotFound")
				}
				if err.Error() != "entity not found" {
					t.Errorf("expected error message 'entity not found', got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewNotFoundError(tt.message)
			tt.validate(t, err)
		})
	}
}

func TestNewServerError(t *testing.T) {
	tests := map[string]struct {
		message  string
		validate func(t *testing.T, err error)
	}{
		"creates error with message": {
			message: "internal server error",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrServerError) {
					t.Errorf("expected error to wrap ErrServerError")
				}
				if err.Error() != "internal server error" {
					t.Errorf("expected error message 'internal server error', got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewServerError(tt.message)
			tt.validate(t, err)
		})
	}
}

func TestNewTemporarilyUnavailableError(t *testing.T) {
	tests := map[string]struct {
		message  string
		validate func(t *testing.T, err error)
	}{
		"creates error with message": {
			message: "service temporarily unavailable",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrTemporarilyUnavailable) {
					t.Errorf("expected error to wrap ErrTemporarilyUnavailable")
				}
				if err.Error() != "service temporarily unavailable" {
					t.Errorf("expected error message 'service temporarily unavailable', got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewTemporarilyUnavailableError(tt.message)
			tt.validate(t, err)
		})
	}
}

func TestNewUnsupportedParameterError(t *testing.T) {
	tests := map[string]struct {
		message  string
		validate func(t *testing.T, err error)
	}{
		"creates error with message": {
			message: "parameter not supported",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrUnsupportedParameter) {
					t.Errorf("expected error to wrap ErrUnsupportedParameter")
				}
				if err.Error() != "parameter not supported" {
					t.Errorf("expected error message 'parameter not supported', got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := NewUnsupportedParameterError(tt.message)
			tt.validate(t, err)
		})
	}
}

func TestErrorConstants(t *testing.T) {
	tests := map[string]struct {
		constant string
		expected string
	}{
		"InvalidRequest constant": {
			constant: InvalidRequest,
			expected: "invalid_request",
		},
		"InvalidClient constant": {
			constant: InvalidClient,
			expected: "invalid_client",
		},
		"InvalidIssuer constant": {
			constant: InvalidIssuer,
			expected: "invalid_issuer",
		},
		"InvalidSubject constant": {
			constant: InvalidSubject,
			expected: "invalid_subject",
		},
		"InvalidTrustAnchor constant": {
			constant: InvalidTrustAnchor,
			expected: "invalid_trust_anchor",
		},
		"InvalidTrustChain constant": {
			constant: InvalidTrustChain,
			expected: "invalid_trust_chain",
		},
		"InvalidMetadata constant": {
			constant: InvalidMetadata,
			expected: "invalid_metadata",
		},
		"NotFound constant": {
			constant: NotFound,
			expected: "not_found",
		},
		"ServerError constant": {
			constant: ServerError,
			expected: "server_error",
		},
		"TemporarilyUnavailable constant": {
			constant: TemporarilyUnavailable,
			expected: "temporarily_unavailable",
		},
		"UnsupportedParameter constant": {
			constant: UnsupportedParameter,
			expected: "unsupported_parameter",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("expected constant value %q, got %q", tt.expected, tt.constant)
			}
		})
	}
}
