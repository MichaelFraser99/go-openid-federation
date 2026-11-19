package client

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type waitsForTheNextSecond struct {
	message string
}

func (h waitsForTheNextSecond) Enabled(context.Context, slog.Level) bool { return true }

func (h waitsForTheNextSecond) Handle(_ context.Context, record slog.Record) error {
	if record.Message == h.message {
		time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 50*time.Millisecond)))
	}
	return nil
}

func (h waitsForTheNextSecond) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h waitsForTheNextSecond) WithGroup(string) slog.Handler { return h }

func TestClient_AChainWhoseExpiryPassesTheAllowanceAfterItsStatementsParsedIsExpired(t *testing.T) {
	key := bindingKey(t)
	const chainExpired = "trust chain expired"

	tests := []struct {
		name    string
		before  string
		resolve func(t *testing.T, f *peerFederation, c *Client) error
	}{
		{
			name:   "building the chain",
			before: "trust chain walk finished",
			resolve: func(t *testing.T, f *peerFederation, c *Client) error {
				f.claims["leaf"] = expiringAtTheEdgeOfTheAllowance()
				_, _, _, err := c.BuildTrustChain(t.Context(), f.id("leaf"), f.id("ta"))
				return err
			},
		},
		{
			name:   "resolving a supplied chain",
			before: "checking chain expiration",
			resolve: func(t *testing.T, f *peerFederation, c *Client) error {
				f.claims["ta>leaf"] = expiringAtTheEdgeOfTheAllowance()
				_, err := resolveTrustingSuppliedAnchor(t, c, t.Context(), f.id("leaf"), f.id("ta"), []string{f.statement("leaf"), f.statement("ta>leaf"), f.statement("ta")})
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for attempt := 0; attempt < 6; attempt++ {
				f := newPeerFederation(t, key)
				c := New(model.ClientConfiguration{Configuration: model.Configuration{HttpClient: f.client, Logger: slog.New(waitsForTheNextSecond{message: tc.before})}})
				err := tc.resolve(t, f, c)
				if err != nil && err.Error() != chainExpired && errors.Is(err, model.ErrExpired) {
					continue
				}
				assertPeerFailure(t, err, model.ErrInvalidTrustChain, "ErrExpired", chainExpired)
				return
			}
			t.Fatal("the statement's allowance ran out before it was parsed on every attempt, so the chain-level check was never reached")
		})
	}
}

func expiringAtTheEdgeOfTheAllowance() map[string]any {
	exp := time.Now().UTC().Add(-model.ClockSkewLeeway + time.Second).Unix()
	return map[string]any{"iat": exp - 600, "exp": exp}
}
