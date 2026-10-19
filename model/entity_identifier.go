package model

import (
	"fmt"
	"net/url"
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

	return (*EntityIdentifier)(&value), nil
}
