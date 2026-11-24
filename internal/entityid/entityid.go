package entityid

import (
	"fmt"
	"maps"
	"net"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/MichaelFraser99/go-openid-federation/internal/truncate"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func NamesTheSameEntity(a, b model.EntityIdentifier) bool {
	return canonicalEntityIdentifier(a) == canonicalEntityIdentifier(b)
}

func canonicalEntityIdentifier(identifier model.EntityIdentifier) string {
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

func UnlistedSuperiorFaults(unlisted map[model.EntityIdentifier][]model.EntityIdentifier) []error {
	var faults []error
	for _, entity := range slices.Sorted(maps.Keys(unlisted)) {
		named := truncate.TruncateForResponse(string(entity))
		if _, err := model.ValidateEntityIdentifier(string(entity)); err != nil {
			faults = append(faults, fmt.Errorf("Experimental.UnlistedSuperiors[%q] is not an entity identifier: %s", named, err.Error()))
		}
		superiors := unlisted[entity]
		if len(superiors) == 0 {
			faults = append(faults, fmt.Errorf("Experimental.UnlistedSuperiors[%q] lists no superior", named))
		}
		for i, superior := range superiors {
			if _, err := model.ValidateEntityIdentifier(string(superior)); err != nil {
				faults = append(faults, fmt.Errorf("Experimental.UnlistedSuperiors[%q][%d] is not an entity identifier: %s", named, i, err.Error()))
			} else if NamesTheSameEntity(superior, entity) {
				faults = append(faults, fmt.Errorf("Experimental.UnlistedSuperiors[%q][%d] names the entity itself", named, i))
			}
		}
	}
	return faults
}
