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
	total := 0
	for _, entry := range marks {
		holder, _ := entry.(map[string]any)
		token, _ := holder["trust_mark"].(string)
		parts := strings.SplitN(token, ".", 4)
		if len(parts) != 3 {
			continue
		}
		body, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			continue
		}
		count, exceeded := CountJSONValues(body, limit-total)
		if exceeded {
			return fmt.Errorf("carries trust marks holding more than the %d JSON values a statement may hold", limit)
		}
		total += count
	}
	return nil
}
