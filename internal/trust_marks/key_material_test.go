package trust_marks

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
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

func TestValidate_ATrustMarkSignedBelowItsAlgorithmsMinimumModulusIsRefused(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		bits      int
		expectErr string
	}{
		{name: "a 2048 bit RSA issuer key", reference: "RFC 7518 3.3", bits: 2048},
		{name: "a 1024 bit RSA issuer key", reference: "RFC 7518 3.3", bits: 1024, expectErr: "1024 bit RSA modulus"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{})
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("ta"))}})

			key, err := rsa.GenerateKey(rand.Reader, tc.bits)
			if err != nil {
				t.Fatal(err)
			}
			published, err := jwk.PublicJwk(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			(*published)["kid"] = "sized"
			ta.JWKs.Keys = append(ta.JWKs.Keys, *published)

			tm := federationTrustMark(t, key, "sized", f.id("ta"), rvType, rvSub)
			_, err = Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, tm, ValidateOptions{
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
				t.Fatalf("[%s] a trust mark goes through the same key rules as a statement, so an undersized modulus must refuse it", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func TestFilterByTrusted_ATrustMarkRefusedForItsKeyIsDroppedFromTheResolve(t *testing.T) {
	f := newRvFed(t, map[string]string{})
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("ta"))}})

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	published, err := jwk.PublicJwk(weak.Public())
	if err != nil {
		t.Fatal(err)
	}
	(*published)["kid"] = "weak"
	ta.JWKs.Keys = append(ta.JWKs.Keys, *published)

	resolved := &model.ResolveResponse{
		Sub: rvSub,
		Exp: time.Now().Add(time.Hour).UTC().Unix(),
		TrustMarks: []model.TrustMarkHolder{
			{TrustMarkType: rvType, TrustMark: federationTrustMark(t, weak, "weak", f.id("ta"), rvType, rvSub)},
			{TrustMarkType: rvType, TrustMark: federationTrustMark(t, f.ecKey["ta"], "test-key", f.id("ta"), rvType, rvSub)},
		},
	}

	if err := FilterByTrusted(t.Context(), model.Configuration{HttpClient: f.server.Client()}, resolved, ta, nil); err != nil {
		t.Fatalf("[8.3] a mark the resolver cannot verify is dropped rather than refusing the resolve, got %v", err)
	}
	if len(resolved.TrustMarks) != 1 {
		t.Fatalf("[8.3] expected the weakly signed mark to be dropped and the other kept, got %d marks", len(resolved.TrustMarks))
	}
}
