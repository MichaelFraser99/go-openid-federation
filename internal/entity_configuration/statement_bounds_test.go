package entity_configuration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func unsignedStatement(t *testing.T, head, body map[string]any) string {
	t.Helper()
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return encode(head) + "." + encode(body) + "." + base64.RawURLEncoding.EncodeToString([]byte("not a signature"))
}

func paddingOf(values int) []any {
	padding := make([]any, values)
	for i := range padding {
		padding[i] = 0
	}
	return padding
}

func TestValidate_AStatementHoldingTooManyValuesIsRefusedBeforeItsSignatureIsChecked(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")
	key := headerJwkKey(t)
	published := headerJwkPublicJwk(t, key.Public(), "leaf")

	head := func(padding int) map[string]any {
		h := map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"}
		if padding > 0 {
			h["pad"] = paddingOf(padding)
		}
		return h
	}
	body := func(padding int) map[string]any {
		b := map[string]any{
			"iss":      string(leaf),
			"sub":      string(leaf),
			"iat":      time.Now().Add(-time.Minute).UTC().Unix(),
			"exp":      time.Now().Add(time.Hour).UTC().Unix(),
			"jwks":     map[string]any{"keys": []any{published}},
			"metadata": map[string]any{},
		}
		if padding > 0 {
			b["pad"] = paddingOf(padding)
		}
		return b
	}

	tests := map[string]struct {
		cfg        model.Configuration
		headPad    int
		bodyPad    int
		signed     bool
		expectPart string
		limit      int
	}{
		"a padded body past the default":          {bodyPad: model.DefaultMaxStatementValues, expectPart: "JWT body", limit: model.DefaultMaxStatementValues},
		"a padded header past the default":        {headPad: model.DefaultMaxStatementValues, expectPart: "JWT header", limit: model.DefaultMaxStatementValues},
		"a padded body past a configured limit":   {cfg: model.Configuration{MaxStatementValues: 100}, bodyPad: 100, expectPart: "JWT body", limit: 100},
		"a signed body past a configured limit":   {cfg: model.Configuration{MaxStatementValues: 100}, bodyPad: 100, signed: true, expectPart: "JWT body", limit: 100},
		"a signed body within a configured limit": {cfg: model.Configuration{MaxStatementValues: 100}, bodyPad: 50, signed: true},
		"a signed body under the default":         {bodyPad: model.DefaultMaxStatementValues / 2, signed: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var token string
			if tc.signed {
				token = signStatementRaw(t, key, head(tc.headPad), body(tc.bodyPad))
			} else {
				token = unsignedStatement(t, head(tc.headPad), body(tc.bodyPad))
			}
			_, err := Validate(context.Background(), tc.cfg, leaf, token)
			if tc.expectPart == "" {
				if err != nil {
					t.Fatalf("expected the statement to be accepted, got %v", err)
				}
				return
			}
			expected := fmt.Sprintf("the %s holds more than the %d JSON values", tc.expectPart, tc.limit)
			if err == nil || !strings.Contains(err.Error(), expected) {
				t.Fatalf("expected a refusal containing %q, got %v", expected, err)
			}
		})
	}
}

func TestValidate_AnEntityConfigurationListingTooManyAuthorityHintsIsRefused(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")
	key := headerJwkKey(t)
	published := headerJwkPublicJwk(t, key.Public(), "leaf")

	hintsOf := func(n int) []any {
		hints := make([]any, n)
		for i := range hints {
			hints[i] = fmt.Sprintf("https://superior%d.example.com", i)
		}
		return hints
	}

	tests := map[string]struct {
		cfg       model.Configuration
		hints     int
		expectErr string
	}{
		"the default number of hints is accepted":    {hints: model.DefaultMaxAuthorityHints},
		"one past the default is refused":            {hints: model.DefaultMaxAuthorityHints + 1, expectErr: fmt.Sprintf("lists %d authority_hints, more than the %d", model.DefaultMaxAuthorityHints+1, model.DefaultMaxAuthorityHints)},
		"a configured number of hints is accepted":   {cfg: model.Configuration{MaxAuthorityHints: 3}, hints: 3},
		"one past a configured limit is refused":     {cfg: model.Configuration{MaxAuthorityHints: 3}, hints: 4, expectErr: "lists 4 authority_hints, more than the 3"},
		"a configured limit above the default holds": {cfg: model.Configuration{MaxAuthorityHints: 100}, hints: model.DefaultMaxAuthorityHints + 1},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			token := signStatementRaw(t, key, map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"}, map[string]any{
				"iss":             string(leaf),
				"sub":             string(leaf),
				"iat":             time.Now().Add(-time.Minute).UTC().Unix(),
				"exp":             time.Now().Add(time.Hour).UTC().Unix(),
				"jwks":            map[string]any{"keys": []any{published}},
				"metadata":        map[string]any{},
				"authority_hints": hintsOf(tc.hints),
			})
			_, err := Validate(context.Background(), tc.cfg, leaf, token)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("expected %d hints to be accepted, got %v", tc.hints, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("expected a refusal containing %q, got %v", tc.expectErr, err)
			}
		})
	}
}

func TestValidate_TrustMarksCarriedTogetherShareTheValueBound(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")
	key := headerJwkKey(t)
	published := headerJwkPublicJwk(t, key.Public(), "leaf")

	markHolding := func(values int) map[string]any {
		encode := func(v any) string {
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			return base64.RawURLEncoding.EncodeToString(raw)
		}
		token := encode(map[string]any{"alg": "RS256"}) + "." + encode(map[string]any{"trust_mark_type": "t", "pad": paddingOf(values - 3)}) + "." + encode("sig")
		return map[string]any{"trust_mark_type": "t", "trust_mark": token}
	}

	tests := map[string]struct {
		marks     []any
		expectErr bool
	}{
		"marks that together reach the limit": {marks: []any{markHolding(40), markHolding(60)}},
		"marks that together pass the limit":  {marks: []any{markHolding(60), markHolding(60)}, expectErr: true},
		"one mark past the limit":             {marks: []any{markHolding(101)}, expectErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			token := unsignedStatement(t, map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"}, map[string]any{
				"iss":         string(leaf),
				"sub":         string(leaf),
				"iat":         time.Now().Add(-time.Minute).UTC().Unix(),
				"exp":         time.Now().Add(time.Hour).UTC().Unix(),
				"jwks":        map[string]any{"keys": []any{published}},
				"trust_marks": tc.marks,
			})
			_, err := Validate(context.Background(), model.Configuration{MaxStatementValues: 100}, leaf, token)
			const expected = "the JWT body carries trust marks holding more than the 100 JSON values"
			if tc.expectErr {
				if err == nil || !strings.Contains(err.Error(), expected) {
					t.Fatalf("expected a refusal containing %q, got %v", expected, err)
				}
				return
			}
			if err == nil || strings.Contains(err.Error(), "JSON values") {
				t.Fatalf("expected the marks to pass the bound and the forged signature to be refused, got %v", err)
			}
		})
	}
}
