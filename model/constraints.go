package model

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
)

type NamingConstraints struct {
	Permitted []string
	Excluded  []string
}

type Constraints struct {
	MaxPathLength      *int
	NamingConstraints  *NamingConstraints
	AllowedEntityTypes []string
}

const maxPathLengthLimit = float64(1 << 31)

func (c Constraints) MarshalJSON() ([]byte, error) {
	members := map[string]any{}
	if c.MaxPathLength != nil {
		members["max_path_length"] = *c.MaxPathLength
	}
	if c.NamingConstraints != nil {
		naming := map[string]any{}
		if c.NamingConstraints.Permitted != nil {
			naming["permitted"] = c.NamingConstraints.Permitted
		}
		if c.NamingConstraints.Excluded != nil {
			naming["excluded"] = c.NamingConstraints.Excluded
		}
		members["naming_constraints"] = naming
	}
	if c.AllowedEntityTypes != nil {
		members["allowed_entity_types"] = c.AllowedEntityTypes
	}
	return json.Marshal(members)
}

func ParseConstraints(value any) (*Constraints, error) {
	members, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'constraints' claim must be a JSON object")
	}
	constraints := &Constraints{}

	if raw, present := members["max_path_length"]; present {
		length, ok := raw.(float64)
		if !ok || length != math.Trunc(length) {
			return nil, fmt.Errorf("'constraints' member 'max_path_length' must be an integer")
		}
		if length < 0 {
			return nil, fmt.Errorf("'constraints' member 'max_path_length' must not be negative")
		}
		parsed := math.MaxInt32
		if length < maxPathLengthLimit {
			parsed = int(length)
		}
		constraints.MaxPathLength = &parsed
	}

	if raw, present := members["naming_constraints"]; present {
		naming, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("'constraints' member 'naming_constraints' must be a JSON object")
		}
		parsed := &NamingConstraints{}
		for _, list := range []struct {
			name   string
			target *[]string
		}{{"permitted", &parsed.Permitted}, {"excluded", &parsed.Excluded}} {
			entries, present := naming[list.name]
			if !present {
				continue
			}
			names, err := parseDomainNameConstraints(list.name, entries)
			if err != nil {
				return nil, err
			}
			*list.target = names
		}
		constraints.NamingConstraints = parsed
	}

	if raw, present := members["allowed_entity_types"]; present {
		entries, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("'constraints' member 'allowed_entity_types' must be an array of strings")
		}
		allowed := make([]string, 0, len(entries))
		for _, entry := range entries {
			entityType, ok := entry.(string)
			if !ok || entityType == "" {
				return nil, fmt.Errorf("'constraints' member 'allowed_entity_types' must be an array of non-empty strings")
			}
			if entityType == "federation_entity" {
				return nil, fmt.Errorf("'constraints' member 'allowed_entity_types' must not list 'federation_entity', which is always allowed")
			}
			allowed = append(allowed, entityType)
		}
		constraints.AllowedEntityTypes = allowed
	}

	return constraints, nil
}

func parseDomainNameConstraints(name string, value any) ([]string, error) {
	entries, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("'naming_constraints' member '%s' must be an array of strings", name)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		domain, ok := entry.(string)
		if !ok || !validDomainNameConstraint(domain) {
			return nil, fmt.Errorf("'naming_constraints' member '%s' must hold fully qualified domain names, optionally led by a period", name)
		}
		names = append(names, domain)
	}
	return names, nil
}

func validDomainNameConstraint(constraint string) bool {
	return validDomainName(strings.TrimSuffix(strings.TrimPrefix(constraint, "."), "."))
}

func validDomainName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			character := label[i]
			isLetterOrDigit := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
			if !isLetterOrDigit && character != '-' {
				return false
			}
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

func NormaliseConstraintHost(host string) (string, bool) {
	normalised := strings.ToLower(strings.TrimSuffix(host, "."))
	if !validDomainName(normalised) {
		return "", false
	}
	return normalised, true
}

func domainNameConstraintMatches(constraint, host string) bool {
	constraint = strings.ToLower(strings.TrimSuffix(constraint, "."))
	if domain, isDomain := strings.CutPrefix(constraint, "."); isDomain {
		return strings.HasSuffix(host, "."+domain)
	}
	return host == constraint
}

func (n NamingConstraints) Permits(host string) bool {
	if slices.ContainsFunc(n.Excluded, func(constraint string) bool { return domainNameConstraintMatches(constraint, host) }) {
		return false
	}
	if n.Permitted == nil {
		return true
	}
	return slices.ContainsFunc(n.Permitted, func(constraint string) bool { return domainNameConstraintMatches(constraint, host) })
}

func (m *Metadata) RetainEntityTypes(allowed []string) *Metadata {
	if m == nil {
		return nil
	}
	result := &Metadata{}
	for entityType, parameters := range m.byEntityType() {
		if entityType == "federation_entity" || slices.Contains(allowed, entityType) {
			result.setEntityType(entityType, parameters)
		}
	}
	return result
}
