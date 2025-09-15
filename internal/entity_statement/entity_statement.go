package entity_statement

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"strings"
)

func ExtractDetails(token string) (keyID, subject, issuer *string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("invalid JWT structure")
	}

	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode JWT head: %s", err.Error())
	}

	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode JWT body: %s", err.Error())
	}

	var headMap, bodyMap map[string]any
	if err := json.Unmarshal(head, &headMap); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal JWT head to json: %s", err.Error())
	}

	if err := json.Unmarshal(body, &bodyMap); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal JWT body to json: %s", err.Error())
	}

	if headMap["kid"] == nil {
		return nil, nil, nil, fmt.Errorf("missing 'kid' claim")
	}

	if bodyMap["iss"] == nil {
		return nil, nil, nil, fmt.Errorf("missing 'iss' claim")
	}

	if bodyMap["sub"] == nil {
		return nil, nil, nil, fmt.Errorf("missing 'sub' claim")
	}

	return josemodel.Pointer(headMap["kid"].(string)), josemodel.Pointer(bodyMap["sub"].(string)), josemodel.Pointer(bodyMap["iss"].(string)), nil
}
