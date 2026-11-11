package resolvecache

import (
	"context"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestCache_AFailedOwnBuildIsRememberedUntilTheBuilderIsReplaced(t *testing.T) {
	const own model.EntityIdentifier = "https://own.example.com"
	failure := model.NewServerError("unable to produce the entity configuration at this time")
	cache := New()

	failing := 0
	cache.SetOwn(own, func(context.Context) (*string, *model.EntityStatement, error) {
		failing++
		return nil, nil, failure
	}, nil)
	build, _ := cache.Own(own)
	for range 3 {
		if _, _, err := build(t.Context()); !errors.Is(err, failure) {
			t.Fatalf("expected the builder's failure, got %v", err)
		}
	}
	if failing != 1 {
		t.Errorf("expected a failing build run once and then remembered, ran %d times", failing)
	}

	signed := "signed"
	working := 0
	cache.SetOwn(own, func(context.Context) (*string, *model.EntityStatement, error) {
		working++
		return &signed, &model.EntityStatement{}, nil
	}, nil)
	build, _ = cache.Own(own)
	if got, _, err := build(t.Context()); err != nil || got != &signed {
		t.Errorf("expected a replaced builder to run rather than return the earlier failure, got %v", err)
	}
	if working != 1 {
		t.Errorf("expected the replacement builder to run, ran %d times", working)
	}

	cache.SetOwn(own, nil, nil)
	if _, ok := cache.Own(own); ok {
		t.Errorf("expected no own builder once it is removed")
	}
}
