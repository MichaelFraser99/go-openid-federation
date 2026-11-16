package model

import (
	"fmt"
	"net"
	"net/url"
	"path"
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

func NamesTheSameEntity(a, b EntityIdentifier) bool {
	return canonicalEntityIdentifier(a) == canonicalEntityIdentifier(b)
}

func canonicalEntityIdentifier(identifier EntityIdentifier) string {
	parsed, err := url.Parse(string(identifier))
	if err != nil {
		return string(identifier)
	}

	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		switch {
		case err != nil:
			host = net.JoinHostPort(host, port)
		case number != 443:
			host = net.JoinHostPort(host, strconv.Itoa(number))
		}
	}

	cleaned := strings.ToLower(path.Clean("/" + strings.TrimPrefix(decodeUnreservedOctets(parsed.EscapedPath()), "/")))

	return "https://" + host + cleaned
}

func decodeUnreservedOctets(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '%' || i+2 >= len(value) {
			out.WriteByte(value[i])
			continue
		}
		decoded, err := strconv.ParseUint(value[i+1:i+3], 16, 8)
		if err != nil || !isUnreserved(byte(decoded)) {
			out.WriteByte(value[i])
			continue
		}
		out.WriteByte(byte(decoded))
		i += 2
	}
	return out.String()
}

func isUnreserved(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	default:
		return false
	}
}
