package trust_marks

import (
	"context"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestStatusAndIssue_TreatANilResultAsNotFound(t *testing.T) {
	tests := []struct {
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.ServerConfiguration{
				TrustMarkRetriever: &mockTrustMarkRetriever{
					getStatusFunc: func(context.Context, string) (*string, error) { return nil, nil },
					issueTrustMarkFunc: func(context.Context, string, model.EntityIdentifier) (*string, error) {
						return nil, nil
					},
				},
			}

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[%s] a nil result with no error panicked: %v", tc.reference, r)
				}
			}()

			err := tc.call(cfg)
			if err == nil {
				t.Fatalf("[%s] expected a nil result with no error to be reported as not found", tc.reference)
			}
			if !errors.Is(err, model.ErrNotFound) {
				t.Fatalf("[%s] the specification requires a 404 here, which needs the not found class, got %v", tc.reference, err)
			}
		})
	}
}

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

func TestGetSubordinate_NilResultCarriesTheNotFoundClass(t *testing.T) {
	cfg := model.ServerConfiguration{
		MetadataRetriever:         nilSubordinateStub{},
		IntermediateConfiguration: &model.IntermediateConfiguration{},
	}

	_, err := cfg.GetSubordinate(t.Context(), "https://leaf.example.com")
	if err == nil {
		t.Fatal("expected a nil subordinate with no error to be reported as not found")
	}
	if !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("expected the not found class so a consumer can use errors.Is, got %v", err)
	}
}
