package model

import (
	"context"
	"errors"
	"testing"
)

var _ EntityIdentifierResolver = StandardEntityIdentifierResolver{}

func TestStandardEntityIdentifierResolver(t *testing.T) {
	tests := map[string]struct {
		param   EntityIdentifierParam
		raw     string
		wantErr bool
		wantID  EntityIdentifier
		wantMsg string
	}{
		"valid sub resolves to identifier": {
			param:  EntityIdentifierParamSub,
			raw:    "https://example.com/",
			wantID: "https://example.com/",
		},
		"valid trust anchor resolves to identifier": {
			param:  EntityIdentifierParamTrustAnchor,
			raw:    "https://anchor.example.com/",
			wantID: "https://anchor.example.com/",
		},
		"malformed sub names the sub parameter in the error": {
			param:   EntityIdentifierParamSub,
			raw:     "not-a-url",
			wantErr: true,
			wantMsg: "malformed 'sub' parameter",
		},
		"malformed trust anchor names the trust_anchor parameter in the error": {
			param:   EntityIdentifierParamTrustAnchor,
			raw:     "not-a-url",
			wantErr: true,
			wantMsg: "malformed 'trust_anchor' parameter",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			id, err := StandardEntityIdentifierResolver{}.ResolveEntityIdentifier(context.Background(), tt.param, tt.raw)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if err.Error() != tt.wantMsg {
					t.Errorf("error = %q, want %q", err.Error(), tt.wantMsg)
				}
				if !errors.Is(err, ErrInvalidRequest) {
					t.Errorf("error is not an ErrInvalidRequest: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			if id == nil || *id != tt.wantID {
				t.Fatalf("id = %v, want %v", id, tt.wantID)
			}
		})
	}
}
