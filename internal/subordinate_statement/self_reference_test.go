package subordinate_statement

import (
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_RefusesAStatementAboutTheIssuingEntityItself(t *testing.T) {
	const own = model.EntityIdentifier("https://ta.example.com")

	tests := map[string]struct {
		subject model.EntityIdentifier
		refused bool
	}{
		"the issuing entity's own identifier": {subject: own, refused: true},
		"another entity":                      {subject: "https://leaf.example.com"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			consulted := false
			retriever := func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
				consulted = true
				return nil, nil, nil
			}
			cfg := model.ServerConfiguration{
				EntityIdentifier:          own,
				IntermediateConfiguration: &model.IntermediateConfiguration{},
			}

			_, err := New(t.Context(), test.subject, retriever, cfg)

			if !test.refused {
				if !consulted {
					t.Error("a genuine subject must still be looked up in the store")
				}
				return
			}
			if err == nil {
				t.Fatal("[4] no entity issues a subordinate statement about itself, so this must be refused")
			}
			if !errors.Is(err, model.ErrInvalidSubject) {
				t.Errorf("[8.9] a subject this entity cannot issue about is invalid_subject, got %T: %v", err, err)
			}
			if errors.Is(err, model.ErrServerError) || errors.Is(err, model.ErrTemporarilyUnavailable) {
				t.Errorf("[8.9] being asked about itself is not a fault of this server, got %v", err)
			}
			if errors.Is(err, model.ErrNotFound) {
				t.Errorf("[8.1.2] the server's own identifier is not an unknown subject, got %v", err)
			}
			if !strings.Contains(err.Error(), "entity configuration") {
				t.Errorf("[3.2 step 6] the refusal must name the entity configuration rule it enforces, got %v", err)
			}
			if consulted {
				t.Error("the self-reference is decided from configuration alone, so the store must not be consulted for it")
			}
		})
	}
}
