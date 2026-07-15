package model

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

func verifyRequiredClaims(m map[string]any, keys ...string) error {
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("missing required '%s' claim", k)
		}
	}
	return nil
}

func metadataStringSlice(v any) ([]string, bool) {
	switch t := v.(type) {
	case []string:
		return t, true
	case []any:
		out := make([]string, len(t))
		for i, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out[i] = s
		}
		return out, true
	default:
		return nil, false
	}
}

func verifyStringArrayClaim(m map[string]any, key string) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	if _, ok := metadataStringSlice(v); !ok {
		return fmt.Errorf("'%s' must be an array of strings", key)
	}
	return nil
}

func verifyNonEmptyStringArrayClaim(m map[string]any, key string) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	slice, ok := metadataStringSlice(v)
	if !ok {
		return fmt.Errorf("'%s' must be an array of strings", key)
	}
	if len(slice) == 0 {
		return fmt.Errorf("'%s' must not be empty", key)
	}
	return nil
}

func verifyObjectClaim(m map[string]any, key string) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	if _, ok = v.(map[string]any); !ok {
		return fmt.Errorf("'%s' must be a JSON object", key)
	}
	return nil
}

func verifyHTTPSURLClaim(m map[string]any, key string, allowQuery bool) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	return verifyHTTPSURLValue(key, v, allowQuery)
}

func verifyHTTPSURLValue(key string, v any, allowQuery bool) error {
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("'%s' must be a string", key)
	}
	parsedURL, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("'%s' is not a valid url: %s", key, err.Error())
	}
	if parsedURL.Scheme != "https" {
		return fmt.Errorf("'%s' must use the 'https' scheme", key)
	}
	if !allowQuery && parsedURL.RawQuery != "" {
		return fmt.Errorf("'%s' must not contain a query component", key)
	}
	if parsedURL.RawFragment != "" || parsedURL.Fragment != "" {
		return fmt.Errorf("'%s' must not contain a fragment component", key)
	}
	return nil
}

func verifyAlgValuesClaim(m map[string]any, key string, allowNone bool) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	slice, ok := metadataStringSlice(v)
	if !ok {
		return fmt.Errorf("'%s' must be an array of strings", key)
	}
	if !allowNone && slices.Contains(slice, "none") {
		return fmt.Errorf("'%s' must not contain the value 'none'", key)
	}
	return nil
}

func hasKeyMechanism(m map[string]any) bool {
	for _, key := range []string{"jwks", "jwks_uri", "signed_jwks_uri"} {
		if _, ok := m[key]; ok {
			return true
		}
	}
	return false
}

func responseTypesRequireTokenEndpoint(m map[string]any) bool {
	v, ok := m["response_types_supported"]
	if !ok || v == nil {
		return true
	}
	slice, ok := metadataStringSlice(v)
	if !ok {
		return true
	}
	for _, responseType := range slice {
		if slices.Contains(strings.Fields(responseType), "code") {
			return true
		}
	}
	return false
}
