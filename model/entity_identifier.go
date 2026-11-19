package model

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type EntityIdentifier string

func ValidateEntityIdentifier(value string) (*EntityIdentifier, error) {
	parsedUrl, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("entity identifiers must be a valid url")
	}

	if parsedUrl.Scheme != "https" {
		return nil, fmt.Errorf("entity identifiers must use the https scheme")
	}

	if parsedUrl.Hostname() == "" {
		return nil, fmt.Errorf("entity identifiers must have a host component")
	}

	if strings.Contains(value, "#") {
		return nil, fmt.Errorf("entity identifiers must not contain Fragment components")
	}

	if strings.Contains(value, "?") {
		return nil, fmt.Errorf("entity identifiers must not contain Query components")
	}

	if parsedUrl.User != nil {
		return nil, fmt.Errorf("entity identifiers must not contain Userinfo components")
	}

	if !holdsOnlyURICharacters(value) {
		return nil, fmt.Errorf("entity identifiers must contain only the characters RFC 3986 allows in a URI")
	}

	if port := parsedUrl.Port(); port != "" {
		if number, err := strconv.Atoi(port); err != nil || number > 65535 {
			return nil, fmt.Errorf("entity identifiers must have a port between 0 and 65535")
		}
	}

	return (*EntityIdentifier)(&value), nil
}

func holdsOnlyURICharacters(value string) bool {
	authorityEnd := len(value)
	if start := strings.Index(value, "://"); start >= 0 {
		if slash := strings.IndexByte(value[start+3:], '/'); slash >= 0 {
			authorityEnd = start + 3 + slash
		}
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("-._~:/?#@!$&'()*+,;=%", c) >= 0:
		case (c == '[' || c == ']') && i < authorityEnd:
		default:
			return false
		}
	}
	return true
}
