package model

import (
	"errors"
	"fmt"
	"testing"
)

func TestReclassifyWithDescription(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		err       error
		expect    error
		expectNil bool
	}{
		{name: "an invalid request", reference: "8.9", err: NewInvalidRequestError("x"), expect: ErrInvalidRequest},
		{name: "a not found", reference: "8.9", err: NewNotFoundError("x"), expect: ErrNotFound},
		{name: "a server error", reference: "8.9", err: NewServerError("x"), expect: ErrServerError},
		{name: "a temporarily unavailable", reference: "8.9", err: NewTemporarilyUnavailableError("x"), expect: ErrTemporarilyUnavailable},
		{name: "a wrapped class", reference: "8.9", err: fmt.Errorf("wrapped: %w", NewInvalidSubjectError("x")), expect: ErrInvalidSubject},
		{name: "a limit, which carries a class and a marker", reference: "8.9", err: NewLimitReachedError("x"), expect: ErrInvalidTrustAnchor},
		{name: "no class at all", reference: "8.9", err: errors.New("dial tcp: connection refused"), expectNil: true},
		{name: "a nil error", reference: "8.9", err: nil, expectNil: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for range 64 {
				got := ReclassifyWithDescription(tc.err, "fixed description")
				if tc.expectNil {
					if got != nil {
						t.Fatalf("[%s] expected no class, got %v", tc.reference, got)
					}
					continue
				}
				if got == nil {
					t.Fatalf("[%s] expected the class to be kept", tc.reference)
				}
				if !errors.Is(got, tc.expect) {
					t.Fatalf("[%s] expected %v, got %v: the lookup must be deterministic, so an error carrying more than one sentinel cannot depend on map iteration order", tc.reference, tc.expect, got)
				}
				if got.Error() != "fixed description" {
					t.Errorf("[%s] expected the supplied description and nothing of the original, got %q", tc.reference, got.Error())
				}
			}
		})
	}
}

func TestReclassifyWithDescription_IsDeterministicForAnErrorCarryingTwoClasses(t *testing.T) {
	both := fmt.Errorf("%w%w%s", ErrInvalidSubject, ErrTemporarilyUnavailable, "two classes")

	first := ReclassifyWithDescription(both, "fixed")
	if first == nil {
		t.Fatal("expected a class to be chosen")
	}
	for range 256 {
		got := ReclassifyWithDescription(both, "fixed")
		if got.Error() != first.Error() || !errors.Is(got, ErrInvalidSubject) {
			t.Fatalf("expected the same class every time, got %v after %v: a map range would vary between runs", got, first)
		}
	}
}
