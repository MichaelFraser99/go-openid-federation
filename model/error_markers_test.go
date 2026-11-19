package model

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorMarkersSurviveReclassification(t *testing.T) {
	markers := map[string]error{"ErrLimitReached": ErrLimitReached, "ErrPeerUnreachable": ErrPeerUnreachable, "ErrPeerTimeout": ErrPeerTimeout, "ErrExpired": ErrExpired}

	for name, marker := range markers {
		t.Run(name, func(t *testing.T) {
			cause := fmt.Errorf("%w%w%s", marker, ErrNotFound, "peer-chosen text")

			for operation, got := range map[string]error{
				"ReclassifyWithDescription": ReclassifyWithDescription(cause, "fixed description"),
				"CarryMarkers":              CarryMarkers(cause, NewNotFoundError("fixed description")),
			} {
				if !errors.Is(got, marker) || !errors.Is(got, ErrNotFound) {
					t.Errorf("%s: expected both the class and the %s marker, got %v", operation, name, got)
				}
				if got.Error() != "fixed description" {
					t.Errorf("%s: a marker carries no text, so the description must be exactly the fixed one, got %q", operation, got.Error())
				}
				for other, sentinel := range markers {
					if other != name && errors.Is(got, sentinel) {
						t.Errorf("%s: expected only the %s marker, got %s as well", operation, name, other)
					}
				}
			}
		})
	}

	if got := CarryMarkers(errors.New("no marker"), NewNotFoundError("fixed description")); got.Error() != "fixed description" || errors.Is(got, ErrPeerUnreachable) || errors.Is(got, ErrPeerTimeout) || errors.Is(got, ErrExpired) || errors.Is(got, ErrLimitReached) {
		t.Errorf("an error with no marker must gain none, got %v", got)
	}
}
