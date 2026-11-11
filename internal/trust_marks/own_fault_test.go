package trust_marks

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
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
		issued    bool
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
		{
			name:      "this server unable to issue its own subordinate statement",
			reference: "8.9 server_error",
			ownErr:    model.NewServerError("unable to produce the subordinate statement at this time"),
			issued:    true,
			want:      model.ErrServerError,
		},
		{
			name:      "this server temporarily unable to issue its own subordinate statement",
			reference: "8.9 temporarily_unavailable",
			ownErr:    model.NewTemporarilyUnavailableError("unable to produce the subordinate statement at this time"),
			issued:    true,
			want:      model.ErrTemporarilyUnavailable,
		},
		{
			name:      "this server not issuing a subordinate statement for an issuer that names it as superior",
			reference: "7.3",
			ownErr:    model.NewInvalidTrustChainError("this server does not issue a subordinate statement for the subject"),
			issued:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fed := newTrustMarkFederation(t, federationNode{name: "first"}, federationNode{name: "second"})

			builds := 0
			cache := resolvecache.New()
			anchor := model.EntityIdentifier("https://another-anchor.example.com")
			if tc.issued {
				anchor = fed.id["trust_anchor"]
				cache.SetOwn(anchor, nil, func(context.Context, model.EntityStatement, model.EntityIdentifier) (*string, *model.EntityStatement, error) {
					builds++
					return nil, nil, tc.ownErr
				})
			} else {
				cache.SetOwn(fed.id["trust_anchor"], func(context.Context) (*string, *model.EntityStatement, error) {
					builds++
					return nil, nil, tc.ownErr
				}, nil)
			}

			resolved := &model.ResolveResponse{
				Sub: subject,
				Exp: time.Now().Add(24 * time.Hour).UTC().Unix(),
				TrustMarks: []model.TrustMarkHolder{
					{TrustMarkType: accreditedTM, TrustMark: federationTrustMark(t, fed.keys["first"], "test-key", string(fed.id["first"]), accreditedTM, string(subject))},
					{TrustMarkType: accreditedTM, TrustMark: federationTrustMark(t, fed.keys["second"], "test-key", string(fed.id["second"]), accreditedTM, string(subject))},
				},
			}
			trustAnchorConfiguration := model.EntityStatement{
				Sub:              anchor,
				TrustMarkIssuers: map[string][]model.EntityIdentifier{accreditedTM: {fed.id["first"], fed.id["second"]}},
			}

			var logs bytes.Buffer
			err := FilterByTrusted(t.Context(), model.Configuration{HttpClient: fed.client(), Logger: slog.New(slog.NewJSONHandler(&logs, nil))}, resolved, trustAnchorConfiguration, cache)

			if tc.want == nil {
				if err != nil {
					t.Fatalf("[%s] a peer that names this server as superior without being its subordinate is the peer's fault, so only its mark is dropped, got %v", tc.reference, err)
				}
				if len(resolved.TrustMarks) != 0 {
					t.Errorf("[%s] expected both marks dropped, got %d", tc.reference, len(resolved.TrustMarks))
				}
				return
			}
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
			statement, description := "entity configuration", ownEntityConfigurationUnavailable
			if tc.issued {
				statement, description = "subordinate statement", ownSubordinateStatementUnavailable
			}
			if err.Error() != description {
				t.Errorf("[%s] expected the description to name the statement that failed, %q, got %q", tc.reference, description, err.Error())
			}
			if !strings.Contains(logs.String(), "could not produce its own "+statement+" for a trust mark issuer walk") {
				t.Errorf("[%s] expected the log to name the %s that failed, got %s", tc.reference, statement, logs.String())
			}
			if builds != 1 {
				t.Errorf("[#195] expected the request to end at the first own fault, got %d attempts to build the entity configuration", builds)
			}
		})
	}
}
