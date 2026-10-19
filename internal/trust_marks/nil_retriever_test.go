package trust_marks

import (
	"context"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type nilSubordinateStub struct{}

func (nilSubordinateStub) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return nil, nil
}

func (nilSubordinateStub) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return nil, nil
}

func (nilSubordinateStub) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, nil
}

func TestStatusAndIssue_TreatAnAbsentResultAsNotFound(t *testing.T) {
	calls := []struct {
		name      string
		reference string
		call      func(cfg model.ServerConfiguration) error
	}{
		{
			name:      "an unknown trust mark status",
			reference: "8.4.2",
			call: func(cfg model.ServerConfiguration) error {
				_, err := Status(t.Context(), cfg, "a.b.c")
				return err
			},
		},
		{
			name:      "an entity that does not hold the trust mark",
			reference: "8.6.2",
			call: func(cfg model.ServerConfiguration) error {
				_, err := Issue(t.Context(), cfg, "https://tm.example.com/a", "https://leaf.example.com")
				return err
			},
		},
	}

	shapes := []struct {
		name  string
		value *string
	}{
		{name: "a nil result", value: nil},
		{name: "an empty result", value: model.Pointer("")},
		{name: "a whitespace only result", value: model.Pointer("   ")},
	}

	for _, tc := range calls {
		for _, shape := range shapes {
			t.Run(tc.name+"/"+shape.name, func(t *testing.T) {
				cfg := model.ServerConfiguration{
					TrustMarkRetriever: &mockTrustMarkRetriever{
						getStatusFunc: func(context.Context, string) (*string, error) { return shape.value, nil },
						issueTrustMarkFunc: func(context.Context, string, model.EntityIdentifier) (*string, error) {
							return shape.value, nil
						},
					},
				}

				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("[%s] %s panicked: %v", tc.reference, shape.name, r)
					}
				}()

				err := tc.call(cfg)
				if err == nil {
					t.Fatalf("[%s] expected %s to be reported as not found", tc.reference, shape.name)
				}
				if !errors.Is(err, model.ErrNotFound) {
					t.Fatalf("[%s] the specification requires a 404 here, which needs the not found class, got %v", tc.reference, err)
				}
			})
		}
	}
}

func TestStatusAndIssue_ReturnALegitimateResult(t *testing.T) {
	cfg := model.ServerConfiguration{
		TrustMarkRetriever: &mockTrustMarkRetriever{
			getStatusFunc: func(context.Context, string) (*string, error) { return model.Pointer("active"), nil },
			issueTrustMarkFunc: func(context.Context, string, model.EntityIdentifier) (*string, error) {
				return model.Pointer("a.b.c"), nil
			},
		},
	}

	status, err := Status(t.Context(), cfg, "a.b.c")
	if err != nil {
		t.Fatalf("expected a real status to be returned, got %v", err)
	}
	if status.Status != "active" {
		t.Errorf("expected the status to be carried, got %q", status.Status)
	}

	mark, err := Issue(t.Context(), cfg, "https://tm.example.com/a", "https://leaf.example.com")
	if err != nil {
		t.Fatalf("expected a real trust mark to be returned, got %v", err)
	}
	if *mark != "a.b.c" {
		t.Errorf("expected the trust mark to be carried, got %q", *mark)
	}
}

func TestGetSubordinate_NilResultCarriesTheNotFoundClass(t *testing.T) {
	tests := []struct {
		name string
		cfg  model.ServerConfiguration
	}{
		{
			name: "a retriever returning a nil subordinate",
			cfg: model.ServerConfiguration{
				MetadataRetriever:         nilSubordinateStub{},
				IntermediateConfiguration: &model.IntermediateConfiguration{},
			},
		},
		{
			name: "no retriever configured",
			cfg: model.ServerConfiguration{
				IntermediateConfiguration: &model.IntermediateConfiguration{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.cfg.GetSubordinate(t.Context(), "https://leaf.example.com")
			if err == nil {
				t.Fatal("expected an absent subordinate to be reported as not found")
			}
			if !errors.Is(err, model.ErrNotFound) {
				t.Fatalf("expected the not found class so a consumer can use errors.Is, got %v", err)
			}
		})
	}
}
