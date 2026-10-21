package trust_marks

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestFilterByTrusted_TheIssuerCapRefusalNamesTheBoundAndNotTheSubject(t *testing.T) {
	const (
		subjectMarker = "subject-issuer-cap-marker"
		openType      = "https://tm.example.com/open"
	)

	tests := []struct {
		name      string
		reference string
		issuers   int
		limit     int
		expectErr bool
	}{
		{name: "fewer issuers than the bound", reference: "8.3", issuers: 1, limit: 2},
		{name: "more issuers than the bound", reference: "8.9", issuers: 3, limit: 2, expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{})
			subject := model.EntityIdentifier("https://" + subjectMarker + ".example.com")

			marks := make([]model.TrustMarkHolder, 0, tc.issuers)
			for i := range tc.issuers {
				marks = append(marks, model.TrustMarkHolder{
					TrustMarkType: openType,
					TrustMark:     federationTrustMark(t, f.ecKey["ta"], "test-key", fmt.Sprintf("https://issuer-%d.example.com", i), openType, string(subject)),
				})
			}

			resolved := &model.ResolveResponse{Sub: subject, Exp: time.Now().Add(time.Hour).UTC().Unix(), TrustMarks: marks}
			ta := model.EntityStatement{Sub: model.EntityIdentifier(f.id("ta")), TrustMarkIssuers: map[string][]model.EntityIdentifier{openType: {}}}

			cfg := model.Configuration{HttpClient: f.server.Client(), MaxTrustMarkIssuers: tc.limit}
			err := FilterByTrusted(t.Context(), cfg, resolved, ta, nil)

			if !tc.expectErr {
				if err != nil {
					t.Fatalf("[%s] expected a subject within the bound to resolve, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the issuer bound to refuse", tc.reference)
			}
			if !errors.Is(err, model.ErrInvalidSubject) {
				t.Errorf("[%s] expected invalid_subject, got %v", tc.reference, err)
			}
			if !errors.Is(err, model.ErrLimitReached) {
				t.Errorf("[%s] a configured bound must be matchable with errors.Is(err, model.ErrLimitReached), got %v", tc.reference, err)
			}
			if strings.Contains(err.Error(), subjectMarker) {
				t.Errorf("[%s] the refusal echoes the caller's own subject identifier into the description: %v", tc.reference, err)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(tc.limit)) {
				t.Errorf("[%s] expected the refusal to name the bound, got %v", tc.reference, err)
			}
		})
	}
}
