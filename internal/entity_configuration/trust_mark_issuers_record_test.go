package entity_configuration

import (
	"bytes"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_OneTrustMarkIssuersRecordCannotTakeTheEntityConfigurationDown(t *testing.T) {
	const (
		good  = "https://tm.example.com/good"
		other = "https://tm.example.com/other"
	)

	tests := []struct {
		name      string
		reference string
		listed    map[string][]model.EntityIdentifier
		published map[string][]string
		omitted   int
	}{
		{
			name:      "every record valid",
			reference: "3.1.2",
			listed: map[string][]model.EntityIdentifier{
				good:  {"https://issuer.example.com"},
				other: {},
			},
			published: map[string][]string{good: {"https://issuer.example.com"}, other: {}},
		},
		{
			name:      "a record naming an http issuer beside a valid record",
			reference: "1.2",
			listed: map[string][]model.EntityIdentifier{
				good:                         {"https://issuer.example.com"},
				"https://tm.example.com/bad": {"http://SECRETHOST.example.com"},
			},
			published: map[string][]string{good: {"https://issuer.example.com"}},
			omitted:   1,
		},
		{
			name:      "a record whose valid issuers come before an invalid one",
			reference: "3.1.2",
			listed: map[string][]model.EntityIdentifier{
				good:                         {"https://issuer.example.com"},
				"https://tm.example.com/bad": {"https://first.example.com", "https://second.example.com", "https://SECRETHOST.example.com#fragment"},
			},
			published: map[string][]string{good: {"https://issuer.example.com"}},
			omitted:   1,
		},
		{
			name:      "a record whose only issuer is not a URL, which must not become an open type",
			reference: "3.1.2",
			listed: map[string][]model.EntityIdentifier{
				good:                         {"https://issuer.example.com"},
				"https://tm.example.com/bad": {"SECRETHOST"},
			},
			published: map[string][]string{good: {"https://issuer.example.com"}},
			omitted:   1,
		},
		{
			name:      "a record whose type is not valid UTF-8",
			reference: "RFC 8259 8.1",
			listed: map[string][]model.EntityIdentifier{
				good:                          {"https://issuer.example.com"},
				"https://tm.example.com/\xff": {"https://issuer.example.com"},
			},
			published: map[string][]string{good: {"https://issuer.example.com"}},
			omitted:   1,
		},
		{
			name:      "several invalid records",
			reference: "1.2",
			listed: map[string][]model.EntityIdentifier{
				good:                           {"https://issuer.example.com"},
				"https://tm.example.com/bad-a": {"http://SECRETHOST.example.com"},
				"https://tm.example.com/bad-b": {"https://SECRETHOST.example.com?query"},
			},
			published: map[string][]string{good: {"https://issuer.example.com"}},
			omitted:   2,
		},
		{
			name:      "every record invalid",
			reference: "1.2",
			listed: map[string][]model.EntityIdentifier{
				"https://tm.example.com/bad": {"http://SECRETHOST.example.com"},
			},
			published: map[string][]string{},
			omitted:   1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signerConfiguration, _ := issuanceSigner(t)
			var logs bytes.Buffer
			cfg := model.ServerConfiguration{
				EntityIdentifier:            "https://ta.example.com",
				SignerConfiguration:         signerConfiguration,
				EntityConfigurationLifetime: time.Hour,
				TrustMarkIssuerRetriever:    issuanceTrustMarkIssuerRetriever{issuers: tc.listed},
				Configuration:               model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, nil))},
			}

			token, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("[%s] one trust_mark_issuers record must not take the entity configuration down, got %v", tc.reference, err)
			}

			claim, _ := issuedClaims(t, *token)["trust_mark_issuers"].(map[string]any)
			published := map[string][]string{}
			for trustMarkType, issuers := range claim {
				listed, ok := issuers.([]any)
				if !ok {
					t.Fatalf("[%s] expected an array of issuers for %q, got %v", tc.reference, trustMarkType, issuers)
				}
				published[trustMarkType] = []string{}
				for _, issuer := range listed {
					published[trustMarkType] = append(published[trustMarkType], issuer.(string))
				}
			}
			if !maps.EqualFunc(published, tc.published, slices.Equal[[]string]) {
				t.Errorf("[%s] expected every valid record published whole and every invalid record left out, got %v", tc.reference, published)
			}

			errorLines := 0
			for line := range strings.Lines(logs.String()) {
				if strings.Contains(line, `"level":"ERROR"`) {
					errorLines++
				}
			}
			if tc.omitted == 0 {
				if errorLines != 0 {
					t.Errorf("[%s] expected no Error line when every record is published, got %s", tc.reference, logs.String())
				}
				return
			}
			if errorLines != 1 {
				t.Errorf("[%s] expected one Error line per response, got %d: %s", tc.reference, errorLines, logs.String())
			}
			if !strings.Contains(logs.String(), `"omitted_records":`+strconv.Itoa(tc.omitted)) {
				t.Errorf("[%s] expected the Error line to count %d omitted records, got %s", tc.reference, tc.omitted, logs.String())
			}
			if strings.Contains(logs.String(), "SECRETHOST") || strings.Contains(logs.String(), "tm.example.com/bad") {
				t.Errorf("[%s] expected the Error line to carry counts and no stored values, got %s", tc.reference, logs.String())
			}
		})
	}
}
