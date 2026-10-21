package trust_marks

import (
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_TrustMarkKeyUseAndStrengthAreHonoured(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		members   map[string]any
		expectErr string
	}{
		{
			name:      "a key with no use is unconstrained",
			reference: "RFC 7517 4.2",
			members:   map[string]any{"use": nil},
		},
		{
			name:      "a key published for signing",
			reference: "RFC 7517 4.2",
			members:   map[string]any{"use": "sig"},
		},
		{
			name:      "a key the issuer published for encryption",
			reference: "RFC 7517 4.2",
			members:   map[string]any{"use": "enc"},
			expectErr: "declares a 'use' of \"enc\"",
		},
		{
			name:      "a key the issuer published for an unknown use",
			reference: "RFC 7517 4.2",
			members:   map[string]any{"use": "deriveBits"},
			expectErr: "declares a 'use' of \"deriveBits\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{})
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("ta"))}})
			for _, key := range ta.JWKs.Keys {
				for member, value := range tc.members {
					if value == nil {
						delete(key, member)
						continue
					}
					key[member] = value
				}
			}

			tm := federationTrustMark(t, f.ecKey["ta"], "test-key", f.id("ta"), rvType, rvSub)
			_, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, tm, ValidateOptions{
				ExpectedType:             rvType,
				ExpectedSubject:          rvSub,
				AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(f.id("ta"))},
				TrustAnchor:              ta.Sub,
				TrustAnchorConfiguration: ta,
			}, nil)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the trust mark to validate, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] a trust mark signed with a key its issuer published as unusable for signing must be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
			if !strings.Contains(err.Error(), "trust mark 'kid'") {
				t.Errorf("[%s] expected the refusal to name the trust mark rather than a chain entry, got %v", tc.reference, err)
			}
		})
	}
}
