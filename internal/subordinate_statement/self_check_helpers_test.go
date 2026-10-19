package subordinate_statement

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func parseIssuedStatement(t *testing.T, token string) model.EntityStatement {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a three part JWT, got %d parts", len(parts))
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode the issued body: %v", err)
	}
	var statement model.EntityStatement
	if err := statement.UnmarshalJSON(body); err != nil {
		t.Fatalf("the issued statement is rejected by this library's own parser: %v", err)
	}
	return statement
}
