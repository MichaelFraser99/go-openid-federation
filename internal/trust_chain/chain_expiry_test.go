package trust_chain

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestBuildTrustChain_TheExpiryIsTheEarliestInTheWholeChain(t *testing.T) {
	now := time.Now().UTC()
	soon, later, latest := now.Add(10*time.Minute).Unix(), now.Add(time.Hour).Unix(), now.Add(2*time.Hour).Unix()

	tests := map[string]struct {
		leafExp, subordinateExp, anchorExp int64
		expect                             int64
		expectErr                          string
	}{
		"the subordinate statement expires first":            {leafExp: later, subordinateExp: soon, anchorExp: latest, expect: soon},
		"only the leaf's configuration expires first":        {leafExp: soon, subordinateExp: latest, anchorExp: later, expect: soon},
		"only the anchor's configuration expires first":      {leafExp: later, subordinateExp: latest, anchorExp: soon, expect: soon},
		"an expired subordinate statement refuses the chain": {leafExp: later, subordinateExp: now.Add(-10 * time.Second).Unix(), anchorExp: later, expectErr: "failed to retrieve a usable subordinate statement"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			client, leaf, anchor := federationWithClaims(t, "example.com", federationClaims{
				leaf:        map[string]any{"exp": tc.leafExp},
				subordinate: map[string]any{"exp": tc.subordinateExp},
				anchor:      map[string]any{"exp": tc.anchorExp},
			})
			chain, _, expiry, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: client}, leaf, anchor, resolvecache.New())
			if tc.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[10.4] expected a chain holding an expired statement to be refused with %q, got %v", tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the chain to build, got %v", err)
			}
			if *expiry != tc.expect {
				t.Errorf("[10.4] expected the minimum exp within the chain, %d, got %d", tc.expect, *expiry)
			}

			resolved, err := resolveTrustingSuppliedAnchor(t, t.Context(), model.Configuration{HttpClient: client}, anchor, anchor, chain, resolvecache.New())
			if err != nil {
				t.Fatalf("expected the chain to resolve, got %v", err)
			}
			if resolved.Exp != *expiry {
				t.Errorf("expected BuildTrustChain and ResolveMetadata to agree on the expiry, got %d and %d", *expiry, resolved.Exp)
			}
		})
	}
}

func TestBuildTrustChain_RefusesAChainWhoseExpiryHasPassed(t *testing.T) {
	tests := map[string]struct {
		subordinateExpiredFor time.Duration
	}{
		"a subordinate statement just past its exp":              {subordinateExpiredFor: time.Second},
		"a subordinate statement 30 seconds past its exp":        {subordinateExpiredFor: 30 * time.Second},
		"a subordinate statement near the edge of the allowance": {subordinateExpiredFor: model.ClockSkewLeeway - 5*time.Second},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			past := time.Now().Add(-tc.subordinateExpiredFor).Unix()
			client, leaf, anchor := federationWithClaims(t, "example.com", federationClaims{subordinate: map[string]any{"exp": past, "iat": past - 600}})
			chain, _, expiry, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: client}, leaf, anchor, resolvecache.New())
			if err == nil {
				t.Fatalf("[10.4] a chain whose expiry has passed must be refused, got expiry %d (now %d)", *expiry, time.Now().Unix())
			}
			if !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[10.4] expected a chain whose expiry has passed to be invalid_trust_chain, got %v", err)
			}
			if chain != nil || expiry != nil {
				t.Errorf("[10.4] expected no chain alongside the refusal, got %d entries and expiry %v", len(chain), expiry)
			}
		})
	}
}

func TestVerifyChainExpiryMarksTheChainExpired(t *testing.T) {
	for name, exp := range map[string]int64{
		"past the clock skew leeway":   1,
		"inside the clock skew leeway": time.Now().UTC().Unix() - 5,
	} {
		t.Run(name, func(t *testing.T) {
			err := VerifyChainExpiry(exp)
			if !errors.Is(err, model.ErrExpired) || !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[10.4] a chain whose exp has passed is expired as well as invalid, got %v", err)
			}
		})
	}
}

func TestChainHasExpired_TheAllowanceIsExactlySixtySeconds(t *testing.T) {
	tests := map[string]struct {
		offset  int64
		expired bool
	}{
		"an exp 59 seconds past": {offset: -59, expired: false},
		"an exp 60 seconds past": {offset: -60, expired: true},
		"an exp 61 seconds past": {offset: -61, expired: true},
		"an exp in the future":   {offset: 60, expired: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			for attempt := 0; attempt < 5; attempt++ {
				now := time.Now().Unix()
				expired := chainHasExpired(now + tc.offset)
				if time.Now().Unix() != now {
					continue
				}
				if expired != tc.expired {
					t.Fatalf("[RFC 7519 4.1.4] expected an exp %+ds from now to be expired %v, got %v", tc.offset, tc.expired, expired)
				}
				return
			}
			t.Fatal("the wall-clock second ticked over on every attempt")
		})
	}
}

func TestCalculateChainExpiration(t *testing.T) {
	now := time.Now().UTC().Unix()
	future1 := now + 3600
	future2 := now + 7200
	future3 := now + 10800

	tests := map[string]struct {
		chain    []model.EntityStatement
		validate func(t *testing.T, result int64)
	}{
		"returns expiration from single statement chain": {
			chain: []model.EntityStatement{
				{Exp: future1},
			},
			validate: func(t *testing.T, result int64) {
				if result != future1 {
					t.Errorf("expected expiration %d, got %d", future1, result)
				}
			},
		},
		"returns minimum expiration from chain with multiple statements": {
			chain: []model.EntityStatement{
				{Exp: future3},
				{Exp: future1},
				{Exp: future2},
			},
			validate: func(t *testing.T, result int64) {
				if result != future1 {
					t.Errorf("expected minimum expiration %d, got %d", future1, result)
				}
			},
		},
		"returns minimum when first statement has minimum": {
			chain: []model.EntityStatement{
				{Exp: future1},
				{Exp: future2},
				{Exp: future3},
			},
			validate: func(t *testing.T, result int64) {
				if result != future1 {
					t.Errorf("expected minimum expiration %d, got %d", future1, result)
				}
			},
		},
		"returns minimum when last statement has minimum": {
			chain: []model.EntityStatement{
				{Exp: future3},
				{Exp: future2},
				{Exp: future1},
			},
			validate: func(t *testing.T, result int64) {
				if result != future1 {
					t.Errorf("expected minimum expiration %d, got %d", future1, result)
				}
			},
		},
		"handles chain with same expiration": {
			chain: []model.EntityStatement{
				{Exp: future2},
				{Exp: future2},
				{Exp: future2},
			},
			validate: func(t *testing.T, result int64) {
				if result != future2 {
					t.Errorf("expected expiration %d, got %d", future2, result)
				}
			},
		},
		"handles chain with expired statements": {
			chain: []model.EntityStatement{
				{Exp: now - 3600},
				{Exp: future1},
				{Exp: future2},
			},
			validate: func(t *testing.T, result int64) {
				if result != now-3600 {
					t.Errorf("expected minimum expiration %d, got %d", now-3600, result)
				}
			},
		},
		"handles chain with two statements": {
			chain: []model.EntityStatement{
				{Exp: future2},
				{Exp: future1},
			},
			validate: func(t *testing.T, result int64) {
				if result != future1 {
					t.Errorf("expected minimum expiration %d, got %d", future1, result)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := calculateChainExpiration(tt.chain)
			tt.validate(t, result)
		})
	}
}
