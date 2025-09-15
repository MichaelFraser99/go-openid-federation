package model_test

import (
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func NewAdd(t *testing.T, values []any) model.Add {
	t.Helper()
	operator, err := model.NewAdd(values)
	if err != nil {
		t.Fatalf("Failed to create Add policy Operator: %s", err.Error())
	}
	return *operator
}

func NewValue(t *testing.T, value any) model.Value {
	t.Helper()
	operator, err := model.NewValue(value)
	if err != nil {
		t.Fatalf("Failed to create Value policy Operator: %s", err.Error())
	}
	return *operator
}

func NewOneOf(t *testing.T, values []any) model.OneOf {
	t.Helper()
	operator, err := model.NewOneOf(values)
	if err != nil {
		t.Fatalf("Failed to create OneOf policy Operator: %s", err.Error())
	}
	return *operator
}

func NewSupersetOf(t *testing.T, values []any) model.SupersetOf {
	t.Helper()
	operator, err := model.NewSupersetOf(values)
	if err != nil {
		t.Fatalf("Failed to create SupersetOf policy Operator: %s", err.Error())
	}
	return *operator
}

func NewSubsetOf(t *testing.T, values []any) model.SubsetOf {
	t.Helper()
	operator, err := model.NewSubsetOf(values)
	if err != nil {
		t.Fatalf("Failed to create SubsetOf policy Operator: %s", err.Error())
	}
	return *operator
}

func NewEssential(t *testing.T, value any) model.Essential {
	t.Helper()
	operator, err := model.NewEssential(value)
	if err != nil {
		t.Fatalf("Failed to create Essential policy Operator: %s", err.Error())
	}
	return *operator
}

func NewDefault(t *testing.T, value any) model.Default {
	t.Helper()
	operator, err := model.NewDefault(value)
	if err != nil {
		t.Fatalf("Failed to create Default policy Operator: %s", err.Error())
	}
	return *operator
}
