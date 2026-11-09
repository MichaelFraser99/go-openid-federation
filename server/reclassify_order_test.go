package server

import (
	"errors"
	"fmt"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestReclassifyWithDescription_AnswersWhatTheResponseTableAnswersForEveryClassButPageNotFound(t *testing.T) {
	sentinels := map[string]error{
		"invalid_request":         model.ErrInvalidRequest,
		"invalid_client":          model.ErrInvalidClient,
		"invalid_issuer":          model.ErrInvalidIssuer,
		"invalid_subject":         model.ErrInvalidSubject,
		"invalid_trust_anchor":    model.ErrInvalidTrustAnchor,
		"invalid_trust_chain":     model.ErrInvalidTrustChain,
		"invalid_metadata":        model.ErrInvalidMetadata,
		"page_not_found":          model.ErrPageNotFound,
		"not_found":               model.ErrNotFound,
		"server_error":            model.ErrServerError,
		"temporarily_unavailable": model.ErrTemporarilyUnavailable,
		"unsupported_parameter":   model.ErrUnsupportedParameter,
	}
	const description = "this library's own description"

	for firstName, first := range sentinels {
		for secondName, second := range sentinels {
			t.Run(firstName+" with "+secondName, func(t *testing.T) {
				err := fmt.Errorf("%w%wa peer's text", first, second)
				var answered []error
				for _, sentinel := range []error{first, second} {
					if sentinel != model.ErrPageNotFound {
						answered = append(answered, sentinel)
					}
				}

				reclassified := model.ReclassifyWithDescription(err, description)
				if len(answered) == 0 {
					if reclassified != nil {
						t.Errorf("page_not_found is defined for the extended listing only, so a transport error carrying nothing else must stay unclassified, got %v", reclassified)
					}
					return
				}
				if reclassified == nil {
					t.Fatalf("expected an error carrying %s and %s to be reclassified", firstName, secondName)
				}
				if errors.Is(reclassified, model.ErrPageNotFound) {
					t.Errorf("page_not_found is defined for the extended listing only, so it must not survive reclassification, got %v", reclassified)
				}
				wantStatus, wantCode := errorStatusAndCode(fmt.Errorf("%w%w", answered[0], answered[len(answered)-1]))
				gotStatus, gotCode := errorStatusAndCode(reclassified)
				if gotStatus != wantStatus || gotCode != wantCode {
					t.Errorf("expected reclassification to keep the answer %d %s, got %d %s", wantStatus, wantCode, gotStatus, gotCode)
				}
				if reclassified.Error() != description {
					t.Errorf("expected the description %q, got %q", description, reclassified.Error())
				}
				if errors.Is(reclassified, model.ErrLimitReached) {
					t.Errorf("expected no limit to be reported where none was reached, got %v", reclassified)
				}
			})
		}
	}
}

func TestReclassifyWithDescription_KeepsALimitBeingReached(t *testing.T) {
	tests := map[string]error{
		"the walk's limit":                   model.NewLimitReachedError("reached the maximum number of entities"),
		"the trust mark issuer limit":        fmt.Errorf("%w%w%s", model.ErrInvalidSubject, model.ErrLimitReached, "too many issuers"),
		"a limit reported as a server fault": fmt.Errorf("%w%w%s", model.ErrServerError, model.ErrLimitReached, "too many bytes"),
	}

	for name, err := range tests {
		t.Run(name, func(t *testing.T) {
			wantStatus, wantCode := errorStatusAndCode(err)
			reclassified := model.ReclassifyWithDescription(err, "described")
			if !errors.Is(reclassified, model.ErrLimitReached) {
				t.Errorf("expected the reclassified error to still report a limit being reached, got %v", reclassified)
			}
			if gotStatus, gotCode := errorStatusAndCode(reclassified); gotStatus != wantStatus || gotCode != wantCode {
				t.Errorf("expected reclassification to keep the answer %d %s, got %d %s", wantStatus, wantCode, gotStatus, gotCode)
			}
			if reclassified.Error() != "described" {
				t.Errorf("expected the description %q, got %q", "described", reclassified.Error())
			}
		})
	}
}

func TestReclassifyWithDescription_LeavesAnUnclassifiedErrorAlone(t *testing.T) {
	for name, err := range map[string]error{
		"an unclassified error":       errors.New("a peer's text"),
		"a limit with no other class": fmt.Errorf("%w%s", model.ErrLimitReached, "a bound"),
		"a page that is not found":    model.NewPageNotFoundError("the pagination pointer is no longer known"),
	} {
		t.Run(name, func(t *testing.T) {
			if reclassified := model.ReclassifyWithDescription(err, "described"); reclassified != nil {
				t.Errorf("expected no class to be invented, got %v", reclassified)
			}
		})
	}
}
