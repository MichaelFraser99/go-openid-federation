package keyops

import (
	"fmt"
	"slices"

	"github.com/MichaelFraser99/go-openid-federation/internal/truncate"
)

func Validate(key map[string]any) error {
	member, present := key["key_ops"]
	if !present {
		return nil
	}
	ops, ok := member.([]any)
	if !ok {
		return fmt.Errorf("has a 'key_ops' member that is not an array")
	}
	seen := make(map[string]struct{}, len(ops))
	for _, op := range ops {
		named, ok := op.(string)
		if !ok {
			return fmt.Errorf("has a 'key_ops' member holding a value that is not a string")
		}
		if _, duplicate := seen[named]; duplicate {
			return fmt.Errorf("lists %q more than once in 'key_ops', which RFC 7517 section 4.3 forbids", truncate.TruncateForResponse(named))
		}
		seen[named] = struct{}{}
	}
	return nil
}

func PermitVerify(key map[string]any) bool {
	member, present := key["key_ops"]
	if !present {
		return true
	}
	ops, _ := member.([]any)
	return slices.Contains(ops, any("verify"))
}
