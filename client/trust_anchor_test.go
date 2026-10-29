package client

import (
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestClient_ResolveMetadata_RefusesAMissingOrMalformedTrustAnchor(t *testing.T) {
	const (
		subject     = model.EntityIdentifier("https://leaf.example.com")
		trustAnchor = model.EntityIdentifier("https://ta.example.com")
	)

	chain := bindingChain(t, subject, trustAnchor)
	c := New(model.ClientConfiguration{})

	tests := []struct {
		name      string
		reference string
		anchor    string
		expectErr error
	}{
		{name: "the anchor the chain ends in", reference: "8.3", anchor: string(trustAnchor)},
		{name: "no anchor at all", reference: "8.3", anchor: "", expectErr: model.ErrInvalidRequest},
		{name: "an anchor over plain http", reference: "1.2", anchor: "http://ta.example.com", expectErr: model.ErrInvalidRequest},
		{name: "an anchor carrying a fragment", reference: "1.2", anchor: "https://ta.example.com#f", expectErr: model.ErrInvalidRequest},
		{name: "an anchor that is not a URL", reference: "1.2", anchor: "not a url", expectErr: model.ErrInvalidRequest},
		{name: "an anchor the chain does not reach", reference: "10.2", anchor: "https://impostor.example.com", expectErr: model.ErrInvalidTrustAnchor},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveTrustingSuppliedAnchor(t, c, t.Context(), string(subject), tc.anchor, chain)
			if tc.expectErr == nil {
				if err != nil {
					t.Fatalf("[%s] expected the chain to resolve, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the trust anchor to be refused", tc.reference)
			}
			if !errors.Is(err, tc.expectErr) {
				t.Errorf("[%s] expected %v so a consumer can match it with errors.Is, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func TestClient_ResolveMetadata_ASubjectMustNotBeItsOwnTrustAnchor(t *testing.T) {
	const (
		subject     = model.EntityIdentifier("https://leaf.example.com")
		trustAnchor = model.EntityIdentifier("https://ta.example.com")
		higher      = model.EntityIdentifier("https://higher.example.com")
	)

	tests := []struct {
		name      string
		reference string
		subject   model.EntityIdentifier
		anchor    model.EntityIdentifier
		chain     func(t *testing.T) []string
		expectErr error
	}{
		{
			name:      "a leaf resolved against its trust anchor",
			reference: "4",
			subject:   subject,
			anchor:    trustAnchor,
			chain:     func(t *testing.T) []string { return bindingChain(t, subject, trustAnchor) },
		},
		{
			name:      "a trust anchor resolved against a higher anchor, which section 4.1 allows",
			reference: "4.1",
			subject:   trustAnchor,
			anchor:    higher,
			chain:     func(t *testing.T) []string { return bindingChain(t, trustAnchor, higher) },
		},
		{
			name:      "a subject named as its own trust anchor",
			reference: "4",
			subject:   trustAnchor,
			anchor:    trustAnchor,
			chain:     func(t *testing.T) []string { return bindingChain(t, subject, trustAnchor)[2:] },
			expectErr: model.ErrInvalidRequest,
		},
	}

	c := New(model.ClientConfiguration{})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveTrustingSuppliedAnchor(t, c, t.Context(), string(tc.subject), string(tc.anchor), tc.chain(t))
			if tc.expectErr == nil {
				if err != nil {
					t.Fatalf("[%s] expected the chain to resolve, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] section 4 requires a trust chain to include the subordinate statement the trust anchor issued about its subject, which no entity issues about itself, so a chain of one cannot be a trust chain", tc.reference)
			}
			if !errors.Is(err, tc.expectErr) {
				t.Errorf("[%s] expected %v, matching what /resolve answers for the same request, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}
