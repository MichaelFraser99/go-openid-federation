package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const policyLevels = 3

var errDuplicatePolicyMember = errors.New("the 'metadata_policy' claim holds a duplicate member name, which section 6.1.2 forbids at each of its three levels")

func statementPolicyHasDuplicateMember(statement []byte) (bool, error) {
	decoder := newTokenDecoder(statement)
	if !nextIsDelim(decoder, '{') {
		return false, nil
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return false, err
		}
		if key == "metadata_policy" {
			duplicate, err := objectHasDuplicateMember(decoder, policyLevels)
			if err != nil || duplicate {
				return duplicate, err
			}
			continue
		}
		if err := skipValue(decoder); err != nil {
			return false, err
		}
	}
	return false, nil
}

func policyHasDuplicateMember(policy []byte) (bool, error) {
	return objectHasDuplicateMember(newTokenDecoder(policy), policyLevels)
}

func newTokenDecoder(data []byte) *json.Decoder {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder
}

func nextIsDelim(decoder *json.Decoder, delim json.Delim) bool {
	token, err := decoder.Token()
	return err == nil && token == delim
}

func objectHasDuplicateMember(decoder *json.Decoder, levels int) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	if token != json.Delim('{') {
		return false, skipRest(decoder, token)
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return false, err
		}
		name, _ := key.(string)
		if _, repeated := seen[name]; repeated {
			return true, nil
		}
		seen[name] = struct{}{}
		if levels > 1 {
			duplicate, err := objectHasDuplicateMember(decoder, levels-1)
			if err != nil || duplicate {
				return duplicate, err
			}
			continue
		}
		if err := skipValue(decoder); err != nil {
			return false, err
		}
	}
	_, err = decoder.Token()
	return false, err
}

func skipValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	return skipRest(decoder, token)
}

func skipRest(decoder *json.Decoder, first json.Token) error {
	if delim, ok := first.(json.Delim); !ok || (delim != '{' && delim != '[') {
		return nil
	}
	for depth := 1; depth > 0; {
		token, err := decoder.Token()
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}
