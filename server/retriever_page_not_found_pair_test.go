package server

import (
	"fmt"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestRetrieverError_PageNotFoundBesideAnotherClassAnswersAsTheOtherClass(t *testing.T) {
	const fallback = "the endpoint's fixed description"
	tests := []struct {
		name        string
		err         error
		code        string
		description string
	}{
		{name: "beside not found", err: fmt.Errorf("%w%wno such record", model.ErrPageNotFound, model.ErrNotFound), code: model.NotFound, description: "no such record"},
		{name: "beside a server error", err: fmt.Errorf("%w%wdial tcp 10.0.0.7:5432", model.ErrPageNotFound, model.ErrServerError), code: model.ServerError, description: fallback},
		{name: "beside a throttle", err: fmt.Errorf("%w%wdial tcp 10.0.0.7:5432", model.ErrPageNotFound, model.ErrTemporarilyUnavailable), code: model.TemporarilyUnavailable, description: fallback},
		{name: "alone", err: model.NewPageNotFoundError("the cursor is stale"), code: model.ServerError, description: fallback},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := (&Server{}).retrieverError(tc.err, fallback)
			if _, code := errorStatusAndCode(got); code != tc.code || got.Error() != tc.description {
				t.Errorf("[8.9] page_not_found is defined for the extended listing only, so expected %s %q, got %s %q", tc.code, tc.description, code, got.Error())
			}
		})
	}
}
