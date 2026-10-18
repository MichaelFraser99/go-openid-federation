package trust_marks

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

// Mock TrustMarkRetriever for testing
type mockTrustMarkRetriever struct {
	getStatusFunc      func(ctx context.Context, trustMark string) (*string, error)
	listTrustMarksFunc func(ctx context.Context, trustMarkIdentifier string, identifier *model.EntityIdentifier) ([]model.EntityIdentifier, error)
	issueTrustMarkFunc func(ctx context.Context, trustMarkIdentifier string, entityIdentifier model.EntityIdentifier) (*string, error)
}

func (m *mockTrustMarkRetriever) GetTrustMarkStatus(ctx context.Context, trustMark string) (*string, error) {
	if m.getStatusFunc != nil {
		return m.getStatusFunc(ctx, trustMark)
	}
	status := "active"
	return &status, nil
}

func (m *mockTrustMarkRetriever) ListTrustMarks(ctx context.Context, trustMarkIdentifier string, identifier *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	if m.listTrustMarksFunc != nil {
		return m.listTrustMarksFunc(ctx, trustMarkIdentifier, identifier)
	}
	return []model.EntityIdentifier{}, nil
}

func (m *mockTrustMarkRetriever) IssueTrustMark(ctx context.Context, trustMarkIdentifier string, entityIdentifier model.EntityIdentifier) (*string, error) {
	if m.issueTrustMarkFunc != nil {
		return m.issueTrustMarkFunc(ctx, trustMarkIdentifier, entityIdentifier)
	}
	token := "mock.trust.mark"
	return &token, nil
}

func TestStatus(t *testing.T) {
	tests := map[string]struct {
		setupConfig func() model.ServerConfiguration
		trustMark   string
		validate    func(t *testing.T, result *model.TrustMarkStatusResponse, err error)
	}{
		"returns status when trust mark retriever is configured": {
			setupConfig: func() model.ServerConfiguration {
				status := "active"
				return model.ServerConfiguration{
					TrustMarkRetriever: &mockTrustMarkRetriever{
						getStatusFunc: func(ctx context.Context, trustMark string) (*string, error) {
							return &status, nil
						},
					},
				}
			},
			trustMark: "test.trust.mark",
			validate: func(t *testing.T, result *model.TrustMarkStatusResponse, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if result.Status != "active" {
					t.Errorf("expected status 'active', got %q", result.Status)
				}
			},
		},
		"returns revoked status": {
			setupConfig: func() model.ServerConfiguration {
				status := "revoked"
				return model.ServerConfiguration{
					TrustMarkRetriever: &mockTrustMarkRetriever{
						getStatusFunc: func(ctx context.Context, trustMark string) (*string, error) {
							return &status, nil
						},
					},
				}
			},
			trustMark: "test.trust.mark",
			validate: func(t *testing.T, result *model.TrustMarkStatusResponse, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result.Status != "revoked" {
					t.Errorf("expected status 'revoked', got %q", result.Status)
				}
			},
		},
		"returns error when trust mark retriever is not configured": {
			setupConfig: func() model.ServerConfiguration {
				return model.ServerConfiguration{
					TrustMarkRetriever: nil,
				}
			},
			trustMark: "test.trust.mark",
			validate: func(t *testing.T, result *model.TrustMarkStatusResponse, err error) {
				if err == nil {
					t.Fatal("expected error when retriever not configured, got nil")
				}
			},
		},
		"returns error when retriever fails": {
			setupConfig: func() model.ServerConfiguration {
				return model.ServerConfiguration{
					TrustMarkRetriever: &mockTrustMarkRetriever{
						getStatusFunc: func(ctx context.Context, trustMark string) (*string, error) {
							return nil, fmt.Errorf("retriever error")
						},
					},
				}
			},
			trustMark: "test.trust.mark",
			validate: func(t *testing.T, result *model.TrustMarkStatusResponse, err error) {
				if err == nil {
					t.Fatal("expected error when retriever fails, got nil")
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := tt.setupConfig()
			result, err := Status(context.Background(), cfg, tt.trustMark)
			tt.validate(t, result, err)
		})
	}
}

func TestList(t *testing.T) {
	entityID1 := model.EntityIdentifier("https://example.com/entity1")
	entityID2 := model.EntityIdentifier("https://example.com/entity2")

	tests := map[string]struct {
		setupConfig             func() model.ServerConfiguration
		trustMarkIdentifier     string
		subjectEntityIdentifier *model.EntityIdentifier
		validate                func(t *testing.T, result []model.EntityIdentifier, err error)
	}{
		"returns list of entities with trust mark": {
			setupConfig: func() model.ServerConfiguration {
				return model.ServerConfiguration{
					TrustMarkRetriever: &mockTrustMarkRetriever{
						listTrustMarksFunc: func(ctx context.Context, trustMarkIdentifier string, identifier *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
							return []model.EntityIdentifier{entityID1, entityID2}, nil
						},
					},
				}
			},
			trustMarkIdentifier:     "https://trust-mark.example.com",
			subjectEntityIdentifier: nil,
			validate: func(t *testing.T, result []model.EntityIdentifier, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if len(result) != 2 {
					t.Fatalf("expected 2 entities, got %d", len(result))
				}
				if result[0] != entityID1 {
					t.Errorf("expected first entity %q, got %q", entityID1, result[0])
				}
				if result[1] != entityID2 {
					t.Errorf("expected second entity %q, got %q", entityID2, result[1])
				}
			},
		},
		"returns empty list when no entities have trust mark": {
			setupConfig: func() model.ServerConfiguration {
				return model.ServerConfiguration{
					TrustMarkRetriever: &mockTrustMarkRetriever{
						listTrustMarksFunc: func(ctx context.Context, trustMarkIdentifier string, identifier *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
							return []model.EntityIdentifier{}, nil
						},
					},
				}
			},
			trustMarkIdentifier:     "https://trust-mark.example.com",
			subjectEntityIdentifier: nil,
			validate: func(t *testing.T, result []model.EntityIdentifier, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if len(result) != 0 {
					t.Errorf("expected empty list, got %d entities", len(result))
				}
			},
		},
		"filters by subject entity identifier": {
			setupConfig: func() model.ServerConfiguration {
				return model.ServerConfiguration{
					TrustMarkRetriever: &mockTrustMarkRetriever{
						listTrustMarksFunc: func(ctx context.Context, trustMarkIdentifier string, identifier *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
							if identifier != nil && *identifier == entityID1 {
								return []model.EntityIdentifier{entityID1}, nil
							}
							return []model.EntityIdentifier{}, nil
						},
					},
				}
			},
			trustMarkIdentifier:     "https://trust-mark.example.com",
			subjectEntityIdentifier: &entityID1,
			validate: func(t *testing.T, result []model.EntityIdentifier, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if len(result) != 1 {
					t.Fatalf("expected 1 entity, got %d", len(result))
				}
				if result[0] != entityID1 {
					t.Errorf("expected entity %q, got %q", entityID1, result[0])
				}
			},
		},
		"returns error when trust mark retriever is not configured": {
			setupConfig: func() model.ServerConfiguration {
				return model.ServerConfiguration{
					TrustMarkRetriever: nil,
				}
			},
			trustMarkIdentifier:     "https://trust-mark.example.com",
			subjectEntityIdentifier: nil,
			validate: func(t *testing.T, result []model.EntityIdentifier, err error) {
				if err == nil {
					t.Fatal("expected error when retriever not configured, got nil")
				}
			},
		},
		"returns error when retriever fails": {
			setupConfig: func() model.ServerConfiguration {
				return model.ServerConfiguration{
					TrustMarkRetriever: &mockTrustMarkRetriever{
						listTrustMarksFunc: func(ctx context.Context, trustMarkIdentifier string, identifier *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
							return nil, fmt.Errorf("retriever error")
						},
					},
				}
			},
			trustMarkIdentifier:     "https://trust-mark.example.com",
			subjectEntityIdentifier: nil,
			validate: func(t *testing.T, result []model.EntityIdentifier, err error) {
				if err == nil {
					t.Fatal("expected error when retriever fails, got nil")
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := tt.setupConfig()
			result, err := List(context.Background(), cfg, tt.trustMarkIdentifier, tt.subjectEntityIdentifier)
			tt.validate(t, result, err)
		})
	}
}

func TestIssue(t *testing.T) {
	entityID := model.EntityIdentifier("https://example.com/entity")

	tests := map[string]struct {
		setupConfig             func() model.ServerConfiguration
		trustMarkIdentifier     string
		subjectEntityIdentifier model.EntityIdentifier
		validate                func(t *testing.T, result *string, err error)
	}{
		"issues trust mark successfully": {
			setupConfig: func() model.ServerConfiguration {
				token := "issued.trust.mark"
				return model.ServerConfiguration{
					TrustMarkRetriever: &mockTrustMarkRetriever{
						issueTrustMarkFunc: func(ctx context.Context, trustMarkIdentifier string, entityIdentifier model.EntityIdentifier) (*string, error) {
							return &token, nil
						},
					},
				}
			},
			trustMarkIdentifier:     "https://trust-mark.example.com",
			subjectEntityIdentifier: entityID,
			validate: func(t *testing.T, result *string, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if *result != "issued.trust.mark" {
					t.Errorf("expected trust mark 'issued.trust.mark', got %q", *result)
				}
			},
		},
		"returns error when trust mark retriever is not configured": {
			setupConfig: func() model.ServerConfiguration {
				return model.ServerConfiguration{
					TrustMarkRetriever: nil,
				}
			},
			trustMarkIdentifier:     "https://trust-mark.example.com",
			subjectEntityIdentifier: entityID,
			validate: func(t *testing.T, result *string, err error) {
				if err == nil {
					t.Fatal("expected error when retriever not configured, got nil")
				}
			},
		},
		"returns error when retriever fails": {
			setupConfig: func() model.ServerConfiguration {
				return model.ServerConfiguration{
					TrustMarkRetriever: &mockTrustMarkRetriever{
						issueTrustMarkFunc: func(ctx context.Context, trustMarkIdentifier string, entityIdentifier model.EntityIdentifier) (*string, error) {
							return nil, fmt.Errorf("issuance error")
						},
					},
				}
			},
			trustMarkIdentifier:     "https://trust-mark.example.com",
			subjectEntityIdentifier: entityID,
			validate: func(t *testing.T, result *string, err error) {
				if err == nil {
					t.Fatal("expected error when retriever fails, got nil")
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := tt.setupConfig()
			result, err := Issue(context.Background(), cfg, tt.trustMarkIdentifier, tt.subjectEntityIdentifier)
			tt.validate(t, result, err)
		})
	}
}

func TestValidate(t *testing.T) {
	// Generate test keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	tests := map[string]struct {
		setupTest func() (trustMark string, authorizedIssuers []model.EntityIdentifier, cfg model.Configuration)
		validate  func(t *testing.T, result *model.TrustMark, err error)
		expectErr string
	}{
		"validates trust mark with invalid JWT structure - too few parts": {
			setupTest: func() (string, []model.EntityIdentifier, model.Configuration) {
				return "invalid.jwt", []model.EntityIdentifier{"https://issuer.example.com"}, model.Configuration{}
			},
			validate: func(t *testing.T, result *model.TrustMark, err error) {
				if err == nil {
					t.Fatal("expected error for invalid JWT structure, got nil")
				}
			},
		},
		"fails validation when JWT body is not valid base64": {
			setupTest: func() (string, []model.EntityIdentifier, model.Configuration) {
				head := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"trust-mark+jwt","kid":"test-key"}`))
				return head + ".invalid-base64!@#.signature", []model.EntityIdentifier{"https://issuer.example.com"}, model.Configuration{}
			},
			expectErr: "failed to decode JWT body",
		},
		"fails validation when JWT body is not valid JSON": {
			setupTest: func() (string, []model.EntityIdentifier, model.Configuration) {
				head := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"trust-mark+jwt","kid":"test-key"}`))
				body := base64.RawURLEncoding.EncodeToString([]byte("not valid json"))
				return head + "." + body + ".signature", []model.EntityIdentifier{"https://issuer.example.com"}, model.Configuration{}
			},
			expectErr: "failed to unmarshal JWT body",
		},
		"fails validation when issuer claim is missing": {
			setupTest: func() (string, []model.EntityIdentifier, model.Configuration) {
				head := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"trust-mark+jwt","kid":"test-key"}`))
				body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"https://entity.example.com"}`))
				return head + "." + body + ".signature", []model.EntityIdentifier{"https://issuer.example.com"}, model.Configuration{}
			},
			expectErr: "missing or invalid required field 'iss'",
		},
		"fails validation when issuer is not a valid entity identifier": {
			setupTest: func() (string, []model.EntityIdentifier, model.Configuration) {
				head := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"trust-mark+jwt","kid":"test-key"}`))
				body := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"not a valid url","sub":"https://entity.example.com","trust_mark_type":"https://tm.example.com/a","iat":1}`))
				return head + "." + body + ".signature", []model.EntityIdentifier{"https://issuer.example.com"}, model.Configuration{}
			},
			expectErr: "invalid trust mark issuer",
		},
		"fails validation when issuer is not in authorized list": {
			setupTest: func() (string, []model.EntityIdentifier, model.Configuration) {
				issuer := "https://unauthorized.example.com"
				trustMark := createTrustMarkJWT(t, issuer, "tm-123", "https://entity.example.com", privateKey)
				authorizedIssuers := []model.EntityIdentifier{"https://authorized.example.com"}
				return trustMark, authorizedIssuers, model.Configuration{}
			},
			validate: func(t *testing.T, result *model.TrustMark, err error) {
				if err == nil {
					t.Fatal("expected error for unauthorized issuer, got nil")
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			trustMark, authorizedIssuers, cfg := tt.setupTest()
			result, err := Validate(context.Background(), cfg, trustMark, ValidateOptions{AuthorizedIssuers: authorizedIssuers}, nil)
			if tt.expectErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got trust mark %v", tt.expectErr, result)
				}
				if !strings.Contains(err.Error(), tt.expectErr) {
					t.Fatalf("expected an error containing %q, got %v", tt.expectErr, err)
				}
				return
			}
			tt.validate(t, result, err)
		})
	}
}

// Helper to create a valid trust mark JWT
func createTrustMarkJWT(t *testing.T, issuer, trustMarkType, sub string, privateKey crypto.Signer) string {
	t.Helper()

	body := map[string]any{
		"iss":             issuer,
		"sub":             sub,
		"trust_mark_type": trustMarkType,
		"iat":             int64(1234567890),
		"exp":             int64(9999999999),
	}
	head := map[string]any{
		"kid": "test-key",
		"typ": "trust-mark+jwt",
		"alg": "RS256",
	}
	token, err := jwt.New(privateKey, head, body, jwt.Opts{Algorithm: josemodel.RS256})
	if err != nil {
		t.Fatalf("failed to create trust mark JWT: %v", err)
	}
	return *token
}

func createTrustMarkJWTWithExp(t *testing.T, issuer, trustMarkType, sub string, privateKey crypto.Signer, exp *int64) string {
	t.Helper()

	body := map[string]any{
		"iss":             issuer,
		"sub":             sub,
		"trust_mark_type": trustMarkType,
		"iat":             int64(1234567890),
	}
	if exp != nil {
		body["exp"] = *exp
	}
	head := map[string]any{
		"kid": "test-key",
		"typ": "trust-mark+jwt",
		"alg": "RS256",
	}
	token, err := jwt.New(privateKey, head, body, jwt.Opts{Algorithm: josemodel.RS256})
	if err != nil {
		t.Fatalf("failed to create trust mark JWT: %v", err)
	}
	return *token
}

func TestFilterByTrusted(t *testing.T) {
	fed := newTrustMarkFederation(t, federationNode{name: "issuer1"}, federationNode{name: "issuer2"})

	issuer1Key, issuer2Key := fed.keys["issuer1"], fed.keys["issuer2"]
	issuer1ID, issuer2ID := fed.id["issuer1"], fed.id["issuer2"]
	trustAnchorID := fed.id["trust_anchor"]
	sharedClient := fed.client()

	subjectID := "https://subject.example.com"

	tests := map[string]struct {
		setupTest func() (*model.ResolveResponse, model.EntityStatement, model.Configuration)
		validate  func(t *testing.T, resolved *model.ResolveResponse, err error)
	}{
		"filters out untrusted trust marks": {
			setupTest: func() (*model.ResolveResponse, model.EntityStatement, model.Configuration) {
				trustMark1 := createTrustMarkJWT(t, string(issuer1ID), "trusted-mark", subjectID, issuer1Key)
				trustMark2 := createTrustMarkJWT(t, string(issuer2ID), "untrusted-mark", subjectID, issuer2Key)

				resolved := &model.ResolveResponse{
					Sub: model.EntityIdentifier(subjectID),
					TrustMarks: []model.TrustMarkHolder{
						{TrustMarkType: "trusted-mark", TrustMark: trustMark1},
						{TrustMarkType: "untrusted-mark", TrustMark: trustMark2},
					},
				}

				trustAnchorConfig := model.EntityStatement{
					Sub: trustAnchorID,
					TrustMarkIssuers: map[string][]model.EntityIdentifier{
						"trusted-mark": {issuer1ID},
					},
				}

				cfg := model.Configuration{HttpClient: sharedClient}

				return resolved, trustAnchorConfig, cfg
			},
			validate: func(t *testing.T, resolved *model.ResolveResponse, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if len(resolved.TrustMarks) != 1 {
					t.Fatalf("expected 1 trust mark, got %d", len(resolved.TrustMarks))
				}
				if resolved.TrustMarks[0].TrustMarkType != "trusted-mark" {
					t.Errorf("expected trust mark type 'trusted-mark', got %q", resolved.TrustMarks[0].TrustMarkType)
				}
			},
		},
		"keeps all trust marks when all are trusted": {
			setupTest: func() (*model.ResolveResponse, model.EntityStatement, model.Configuration) {
				trustMark1 := createTrustMarkJWT(t, string(issuer1ID), "trusted-mark-1", subjectID, issuer1Key)
				trustMark2 := createTrustMarkJWT(t, string(issuer2ID), "trusted-mark-2", subjectID, issuer2Key)

				resolved := &model.ResolveResponse{
					Sub: model.EntityIdentifier(subjectID),
					TrustMarks: []model.TrustMarkHolder{
						{TrustMarkType: "trusted-mark-1", TrustMark: trustMark1},
						{TrustMarkType: "trusted-mark-2", TrustMark: trustMark2},
					},
				}

				trustAnchorConfig := model.EntityStatement{
					Sub: trustAnchorID,
					TrustMarkIssuers: map[string][]model.EntityIdentifier{
						"trusted-mark-1": {issuer1ID},
						"trusted-mark-2": {issuer2ID},
					},
				}

				cfg := model.Configuration{HttpClient: sharedClient}

				return resolved, trustAnchorConfig, cfg
			},
			validate: func(t *testing.T, resolved *model.ResolveResponse, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if len(resolved.TrustMarks) != 2 {
					t.Fatalf("expected 2 trust marks, got %d", len(resolved.TrustMarks))
				}
			},
		},
		"lowers exp to an included trust mark exp when earlier than the chain": {
			setupTest: func() (*model.ResolveResponse, model.EntityStatement, model.Configuration) {
				trustMark := createTrustMarkJWTWithExp(t, string(issuer1ID), "trusted-mark", subjectID, issuer1Key, model.Pointer(int64(8000000000)))

				resolved := &model.ResolveResponse{
					Sub: model.EntityIdentifier(subjectID),
					Exp: 9999999999,
					TrustMarks: []model.TrustMarkHolder{
						{TrustMarkType: "trusted-mark", TrustMark: trustMark},
					},
				}
				trustAnchorConfig := model.EntityStatement{
					Sub: trustAnchorID,
					TrustMarkIssuers: map[string][]model.EntityIdentifier{
						"trusted-mark": {issuer1ID},
					},
				}
				return resolved, trustAnchorConfig, model.Configuration{HttpClient: sharedClient}
			},
			validate: func(t *testing.T, resolved *model.ResolveResponse, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if resolved.Exp != 8000000000 {
					t.Errorf("expected exp lowered to 8000000000, got %d", resolved.Exp)
				}
			},
		},
		"keeps chain exp when the trust mark exp is later": {
			setupTest: func() (*model.ResolveResponse, model.EntityStatement, model.Configuration) {
				trustMark := createTrustMarkJWTWithExp(t, string(issuer1ID), "trusted-mark", subjectID, issuer1Key, model.Pointer(int64(9999999999)))

				resolved := &model.ResolveResponse{
					Sub: model.EntityIdentifier(subjectID),
					Exp: 8000000000,
					TrustMarks: []model.TrustMarkHolder{
						{TrustMarkType: "trusted-mark", TrustMark: trustMark},
					},
				}
				trustAnchorConfig := model.EntityStatement{
					Sub: trustAnchorID,
					TrustMarkIssuers: map[string][]model.EntityIdentifier{
						"trusted-mark": {issuer1ID},
					},
				}
				return resolved, trustAnchorConfig, model.Configuration{HttpClient: sharedClient}
			},
			validate: func(t *testing.T, resolved *model.ResolveResponse, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if resolved.Exp != 8000000000 {
					t.Errorf("expected exp to remain 8000000000, got %d", resolved.Exp)
				}
			},
		},
		"ignores trust marks without an exp": {
			setupTest: func() (*model.ResolveResponse, model.EntityStatement, model.Configuration) {
				trustMark := createTrustMarkJWTWithExp(t, string(issuer1ID), "trusted-mark", subjectID, issuer1Key, nil)

				resolved := &model.ResolveResponse{
					Sub: model.EntityIdentifier(subjectID),
					Exp: 8000000000,
					TrustMarks: []model.TrustMarkHolder{
						{TrustMarkType: "trusted-mark", TrustMark: trustMark},
					},
				}
				trustAnchorConfig := model.EntityStatement{
					Sub: trustAnchorID,
					TrustMarkIssuers: map[string][]model.EntityIdentifier{
						"trusted-mark": {issuer1ID},
					},
				}
				return resolved, trustAnchorConfig, model.Configuration{HttpClient: sharedClient}
			},
			validate: func(t *testing.T, resolved *model.ResolveResponse, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if resolved.Exp != 8000000000 {
					t.Errorf("expected exp to remain 8000000000, got %d", resolved.Exp)
				}
			},
		},
		"handles empty trust marks list": {
			setupTest: func() (*model.ResolveResponse, model.EntityStatement, model.Configuration) {
				resolved := &model.ResolveResponse{
					Sub:        model.EntityIdentifier(subjectID),
					TrustMarks: []model.TrustMarkHolder{},
				}
				trustAnchorConfig := model.EntityStatement{
					Sub:              trustAnchorID,
					TrustMarkIssuers: map[string][]model.EntityIdentifier{},
				}
				cfg := model.Configuration{}
				return resolved, trustAnchorConfig, cfg
			},
			validate: func(t *testing.T, resolved *model.ResolveResponse, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if len(resolved.TrustMarks) != 0 {
					t.Errorf("expected empty trust marks, got %d", len(resolved.TrustMarks))
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			resolved, trustAnchorConfig, cfg := tt.setupTest()
			err := FilterByTrusted(context.Background(), cfg, resolved, trustAnchorConfig, nil)
			tt.validate(t, resolved, err)
		})
	}
}
