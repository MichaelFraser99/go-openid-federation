package entity_configuration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_ALeafPublishesNoFetchOrListEndpoint(t *testing.T) {
	const identifier = "https://entity.example.com"

	tests := []struct {
		name         string
		intermediate bool
		configured   model.FederationMetadata
		want         map[string]any
		absent       []string
		logged       []string
	}{
		{
			name:       "a leaf with a fetch endpoint typed in",
			configured: model.FederationMetadata{"federation_fetch_endpoint": "https://elsewhere.example.com/fetch", "organization_name": "Leaf"},
			want:       map[string]any{"organization_name": "Leaf"},
			absent:     []string{"federation_fetch_endpoint"},
			logged:     []string{"federation_fetch_endpoint"},
		},
		{
			name:       "a leaf with a list endpoint typed in",
			configured: model.FederationMetadata{"federation_list_endpoint": "https://elsewhere.example.com/list", "organization_name": "Leaf"},
			want:       map[string]any{"organization_name": "Leaf"},
			absent:     []string{"federation_list_endpoint"},
			logged:     []string{"federation_list_endpoint"},
		},
		{
			name: "a leaf with both typed in, and a resolve endpoint any entity may publish",
			configured: model.FederationMetadata{
				"federation_fetch_endpoint":   "https://elsewhere.example.com/fetch",
				"federation_list_endpoint":    "https://elsewhere.example.com/list",
				"federation_resolve_endpoint": "https://elsewhere.example.com/resolve",
			},
			want:   map[string]any{"federation_resolve_endpoint": "https://elsewhere.example.com/resolve"},
			absent: []string{"federation_fetch_endpoint", "federation_list_endpoint"},
			logged: []string{"federation_fetch_endpoint", "federation_list_endpoint"},
		},
		{
			name:       "a leaf with neither typed in",
			configured: model.FederationMetadata{"organization_name": "Leaf"},
			want:       map[string]any{"organization_name": "Leaf"},
			absent:     []string{"federation_fetch_endpoint", "federation_list_endpoint"},
		},
		{
			name:         "an intermediate with a fetch endpoint typed in",
			intermediate: true,
			configured:   model.FederationMetadata{"federation_fetch_endpoint": "https://elsewhere.example.com/fetch"},
			want:         map[string]any{"federation_fetch_endpoint": identifier + "/fetch", "federation_list_endpoint": identifier + "/list"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, _ := issuanceSigner(t)
			var logs bytes.Buffer
			cfg := model.ServerConfiguration{
				Configuration:               model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
				EntityIdentifier:            identifier,
				SignerConfiguration:         signer,
				EntityConfigurationLifetime: time.Hour,
				EntityConfiguration:         model.EntityStatement{Metadata: &model.Metadata{FederationMetadata: &tc.configured}},
			}
			if tc.intermediate {
				cfg.IntermediateConfiguration = &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour}
			}

			signed, err := New(context.Background(), cfg)
			if err != nil {
				t.Fatalf("expected the entity configuration to be issued, got %v", err)
			}
			payload, err := base64.RawURLEncoding.DecodeString(strings.Split(*signed, ".")[1])
			if err != nil {
				t.Fatalf("failed to decode the payload: %v", err)
			}
			var statement struct {
				Metadata struct {
					FederationEntity map[string]any `json:"federation_entity"`
				} `json:"metadata"`
			}
			if err := json.Unmarshal(payload, &statement); err != nil {
				t.Fatalf("failed to read the statement: %v", err)
			}

			published := statement.Metadata.FederationEntity
			for claim, value := range tc.want {
				if published[claim] != value {
					t.Errorf("expected %s to be published as %v, got %v", claim, value, published[claim])
				}
			}
			for _, claim := range tc.absent {
				if _, present := published[claim]; present {
					t.Errorf("[5.1.1] leaf entities MUST NOT publish %s, got %v", claim, published)
				}
			}

			if strings.Contains(logs.String(), `"level":"ERROR"`) {
				t.Errorf("expected New to drop the claims without logging, because NewServer reports them once, got %s", logs.String())
			}
			if reported := UnpublishedLeafEndpoints(cfg); !slices.Equal(reported, tc.logged) {
				t.Errorf("expected the claims reported for NewServer to log to be %v, got %v", tc.logged, reported)
			}
		})
	}
}
