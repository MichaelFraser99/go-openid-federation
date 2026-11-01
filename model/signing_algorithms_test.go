package model

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
)

func TestConfiguration_AcceptedSigningAlgorithms(t *testing.T) {
	tests := map[string]struct {
		configured []jwa.Algorithm
		expect     []jwa.Algorithm
	}{
		"unset accepts the default":                       {configured: nil, expect: DefaultSigningAlgorithms},
		"a list narrows it":                               {configured: []jwa.Algorithm{jwa.ES256, jwa.Ed25519}, expect: []jwa.Algorithm{jwa.ES256, jwa.Ed25519}},
		"the floor holds even when HS is configured":      {configured: []jwa.Algorithm{jwa.HS256, jwa.ES256, jwa.HS512}, expect: []jwa.Algorithm{jwa.ES256}},
		"an algorithm go-jose does not define is dropped": {configured: []jwa.Algorithm{jwa.Unknown, jwa.PS256}, expect: []jwa.Algorithm{jwa.PS256}},
		"a repeated algorithm is listed once":             {configured: []jwa.Algorithm{jwa.RS256, jwa.RS256}, expect: []jwa.Algorithm{jwa.RS256}},
		"an empty list accepts nothing":                   {configured: []jwa.Algorithm{}, expect: []jwa.Algorithm{}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Configuration{SigningAlgorithms: tc.configured}
			if got := cfg.AcceptedSigningAlgorithms(); !slices.Equal(got, tc.expect) {
				t.Errorf("[RFC 8725 3.1] expected %v, got %v", tc.expect, got)
			}
		})
	}

	t.Run("the default holds no symmetric algorithm", func(t *testing.T) {
		for _, refused := range []jwa.Algorithm{jwa.HS256, jwa.HS384, jwa.HS512, jwa.Unknown} {
			if slices.Contains(DefaultSigningAlgorithms, refused) {
				t.Errorf("[3.2] the default must never accept %v", refused)
			}
		}
	})

	t.Run("the returned list is the caller's to change", func(t *testing.T) {
		cfg := Configuration{}
		accepted := cfg.AcceptedSigningAlgorithms()
		accepted[0] = jwa.HS256
		if DefaultSigningAlgorithms[0] == jwa.HS256 {
			t.Error("writing into the accepted list changed the default")
		}
	})
}

func TestConfiguration_VerifySigningAlgorithms(t *testing.T) {
	tests := map[string]struct {
		configured []jwa.Algorithm
		expectErr  string
	}{
		"unset":                   {configured: nil},
		"every default algorithm": {configured: DefaultSigningAlgorithms},
		"a narrowed list":         {configured: []jwa.Algorithm{jwa.ES256}},
		"empty":                   {configured: []jwa.Algorithm{}, expectErr: "set but empty"},
		"HS256":                   {configured: []jwa.Algorithm{jwa.ES256, jwa.HS256}, expectErr: "HS256, which this library never accepts"},
		"HS384":                   {configured: []jwa.Algorithm{jwa.HS384}, expectErr: "HS384"},
		"HS512":                   {configured: []jwa.Algorithm{jwa.HS512}, expectErr: "HS512"},
		"undefined":               {configured: []jwa.Algorithm{jwa.Unknown}, expectErr: "an algorithm go-jose does not define"},
		"ML-DSA":                  {configured: []jwa.Algorithm{jwa.MLDSA44}, expectErr: "ML-DSA-44, which this library cannot verify with"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Configuration{SigningAlgorithms: tc.configured}
			err := cfg.VerifySigningAlgorithms()
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("expected the list to be usable, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrServerError) {
				t.Fatalf("[8.9] an unusable list is this deployment's own fault, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("expected the error to say %q, got %v", tc.expectErr, err)
			}
		})
	}
}
