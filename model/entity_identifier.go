package model

import (
	"fmt"
	"net/url"
)

type EntityIdentifier string

func ValidateEntityIdentifier(value string) (*EntityIdentifier, error) {
	parsedUrl, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("entity identifiers must be a valid url: %s", err.Error())
	}

	if parsedUrl.Scheme != "https" {
		return nil, fmt.Errorf("entity identifiers must use the https scheme")
	}

	if parsedUrl.Host == "" {
		return nil, fmt.Errorf("entity identifiers must have a host component")
	}

	if parsedUrl.RawFragment != "" || parsedUrl.Fragment != "" {
		return nil, fmt.Errorf("entity identifiers must not contain Fragment components")
	}

	if parsedUrl.RawQuery != "" {
		return nil, fmt.Errorf("entity identifiers must not contain Query components")
	}

	return (*EntityIdentifier)(&value), nil
}
