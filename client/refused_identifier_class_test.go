package client

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestClient_AMalformedIdentifierIsRefusedAsAnInvalidRequest(t *testing.T) {
	const valid = "https://valid.example.com"
	malformed := map[string]string{
		"an empty identifier":        "",
		"a plain http identifier":    "http://leaf.example.com",
		"an identifier with a query": "https://leaf.example.com?a=b",
	}
	calls := []struct {
		name  string
		names string
		call  func(c *Client, identifier string) error
	}{
		{
			name:  "BuildTrustChain given a malformed leaf",
			names: "leaf",
			call: func(c *Client, identifier string) error {
				_, _, _, err := c.BuildTrustChain(context.Background(), identifier, valid)
				return err
			},
		},
		{
			name:  "BuildTrustChain given a malformed trust anchor",
			names: "trust anchor",
			call: func(c *Client, identifier string) error {
				_, _, _, err := c.BuildTrustChain(context.Background(), valid, identifier)
				return err
			},
		},
		{
			name:  "ResolveMetadata given a malformed subject",
			names: "subject",
			call: func(c *Client, identifier string) error {
				_, err := c.ResolveMetadata(context.Background(), identifier, valid, []string{"unused"})
				return err
			},
		},
		{
			name:  "ResolveMetadata given a malformed trust anchor",
			names: "trust anchor",
			call: func(c *Client, identifier string) error {
				_, err := c.ResolveMetadata(context.Background(), valid, identifier, []string{"unused"})
				return err
			},
		},
	}

	for _, call := range calls {
		for value, identifier := range malformed {
			t.Run(call.name+" as "+value, func(t *testing.T) {
				err := call.call(New(model.ClientConfiguration{}), identifier)
				if !errors.Is(err, model.ErrInvalidRequest) {
					t.Fatalf("expected a malformed identifier refused as an invalid request, got %v", err)
				}
				if !strings.Contains(err.Error(), call.names) {
					t.Errorf("expected the refusal to name the %s, got %q", call.names, err.Error())
				}
			})
		}
	}
}
