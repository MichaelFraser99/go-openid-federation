package trust_marks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestFilterByTrusted_ThisServersOwnFaultInAnIssuerWalkAnswersAsItsOwnFault(t *testing.T) {
	const (
		subject      = model.EntityIdentifier("https://subject.example.com")
		accreditedTM = "https://tm.employer.example/accredited"
	)

	tests := []struct {
		name      string
		reference string
		ownErr    error
		want      error
	}{
		{
			name:      "this server unable to produce its own entity configuration",
			reference: "8.9 server_error",
			ownErr:    model.NewServerError("unable to produce the entity configuration at this time"),
			want:      model.ErrServerError,
		},
		{
			name:      "this server temporarily unable to produce its own entity configuration",
			reference: "8.9 temporarily_unavailable",
			ownErr:    model.NewTemporarilyUnavailableError("unable to produce the entity configuration at this time"),
			want:      model.ErrTemporarilyUnavailable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fed := newTrustMarkFederation(t, federationNode{name: "first"}, federationNode{name: "second"})

			builds := 0
			cache := resolvecache.New()
			cache.SetOwn(fed.id["trust_anchor"], func(context.Context) (*string, *model.EntityStatement, error) {
				builds++
				return nil, nil, tc.ownErr
			})

			resolved := &model.ResolveResponse{
				Sub: subject,
				Exp: time.Now().Add(24 * time.Hour).UTC().Unix(),
				TrustMarks: []model.TrustMarkHolder{
					{TrustMarkType: accreditedTM, TrustMark: federationTrustMark(t, fed.keys["first"], "test-key", string(fed.id["first"]), accreditedTM, string(subject))},
					{TrustMarkType: accreditedTM, TrustMark: federationTrustMark(t, fed.keys["second"], "test-key", string(fed.id["second"]), accreditedTM, string(subject))},
				},
			}
			trustAnchorConfiguration := model.EntityStatement{
				Sub:              model.EntityIdentifier("https://another-anchor.example.com"),
				TrustMarkIssuers: map[string][]model.EntityIdentifier{accreditedTM: {fed.id["first"], fed.id["second"]}},
			}

			err := FilterByTrusted(t.Context(), model.Configuration{HttpClient: fed.client()}, resolved, trustAnchorConfiguration, cache)

			if !errors.Is(err, tc.want) {
				t.Fatalf("[%s] a mark that cannot be verified because of this server's own fault must not vanish behind a 200, expected %v, got %v", tc.reference, tc.want, err)
			}
			for _, issuer := range []model.EntityIdentifier{fed.id["first"], fed.id["second"], fed.id["trust_anchor"]} {
				if strings.Contains(err.Error(), string(issuer)) {
					t.Errorf("[%s] expected a fixed description, got %q", tc.reference, err.Error())
				}
			}
			if resolved.TrustMarks != nil {
				t.Errorf("[%s] expected no trust marks left on a response that will not be sent, got %d", tc.reference, len(resolved.TrustMarks))
			}
			if builds != 1 {
				t.Errorf("[#195] expected the request to end at the first own fault, got %d attempts to build the entity configuration", builds)
			}
		})
	}
}
