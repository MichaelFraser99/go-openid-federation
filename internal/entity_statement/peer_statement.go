package entity_statement

import (
	"mime"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

const entityStatementMediaType = "application/entity-statement+jwt"

func IsEntityStatementMediaType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == entityStatementMediaType
}

func StatementCost(signed string, statement *model.EntityStatement) int64 {
	cost := 2 * int64(len(signed))
	if statement != nil {
		cost += int64(statement.DecodedValues()) * model.DecodedValueCost
	}
	return cost
}
