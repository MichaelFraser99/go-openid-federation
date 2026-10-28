package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func CountJSONValues(data []byte, limit int) (count int, exceeded bool) {
	type frame struct {
		object    bool
		expectKey bool
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var stack []frame

	valueCompleted := func() {
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].expectKey = true
		}
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			return count, false
		}

		if delimiter, isDelimiter := token.(json.Delim); isDelimiter {
			switch delimiter {
			case '{', '[':
				count++
				if count > limit {
					return count, true
				}
				stack = append(stack, frame{object: delimiter == '{', expectKey: delimiter == '{'})
			case '}', ']':
				stack = stack[:len(stack)-1]
				valueCompleted()
			}
			continue
		}

		if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
			stack[len(stack)-1].expectKey = false
			continue
		}
		count++
		if count > limit {
			return count, true
		}
		valueCompleted()
	}
}

func VerifyJSONValueCount(data []byte, limit int) error {
	if _, exceeded := CountJSONValues(data, limit); exceeded {
		return fmt.Errorf("holds more than the %d JSON values a statement may hold", limit)
	}
	return nil
}

func VerifyTrustMarkValueCount(claims map[string]any, limit int) error {
	marks, _ := claims["trust_marks"].([]any)
	budget := limit
	for _, entry := range marks {
		holder, _ := entry.(map[string]any)
		token, _ := holder["trust_mark"].(string)
		body, ok := chargeTokenValues(token, &budget)
		if !ok {
			return fmt.Errorf("carries trust marks holding more than the %d JSON values a statement may hold", limit)
		}
		var markClaims map[string]any
		if json.Unmarshal(body, &markClaims) != nil {
			continue
		}
		delegation, _ := markClaims["delegation"].(string)
		if _, ok := chargeTokenValues(delegation, &budget); !ok {
			return fmt.Errorf("carries trust marks holding more than the %d JSON values a statement may hold", limit)
		}
	}
	return nil
}

func chargeTokenValues(token string, budget *int) (body []byte, withinBudget bool) {
	parts := strings.SplitN(token, ".", 4)
	if len(parts) != 3 {
		return nil, true
	}
	for i, part := range parts[:2] {
		decoded, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			continue
		}
		count, exceeded := CountJSONValues(decoded, *budget)
		if exceeded {
			return nil, false
		}
		*budget -= count
		if i == 1 {
			body = decoded
		}
	}
	return body, true
}

func VerifyTokenValueCount(token string, limit int) error {
	parts := strings.SplitN(token, ".", 4)
	if len(parts) != 3 {
		return nil
	}
	for i, name := range []string{"header", "body"} {
		decoded, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			continue
		}
		if err := VerifyJSONValueCount(decoded, limit); err != nil {
			return fmt.Errorf("has a %s that %s", name, err.Error())
		}
	}
	return nil
}
