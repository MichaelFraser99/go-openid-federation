package trust_chain

import (
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestVerifyChainConstraints_JudgesTheHostARequestWouldReach(t *testing.T) {
	naming := func(permitted, excluded []string) *model.Constraints {
		return &model.Constraints{NamingConstraints: &model.NamingConstraints{Permitted: permitted, Excluded: excluded}}
	}

	toASCII := func(converted string, err error) func(string) (string, error) {
		return func(string) (string, error) { return converted, err }
	}

	tests := map[string]struct {
		subject     model.EntityIdentifier
		constraints *model.Constraints
		hostToASCII func(string) (string, error)
		expectErr   bool
	}{
		"an upper-case host is excluded as its lower case":       {subject: "https://LEAF.example.com", constraints: naming(nil, []string{"leaf.example.com"}), expectErr: true},
		"a host with a trailing dot is excluded without it":      {subject: "https://leaf.example.com.", constraints: naming(nil, []string{"leaf.example.com"}), expectErr: true},
		"a host with a trailing dot is permitted as itself":      {subject: "https://leaf.example.com.", constraints: naming([]string{"leaf.example.com"}, nil)},
		"a port does not take a host out of an exclusion":        {subject: "https://leaf.example.com:8443", constraints: naming(nil, []string{"leaf.example.com"}), expectErr: true},
		"a path does not take a host out of an exclusion":        {subject: "https://leaf.example.com/tenant", constraints: naming(nil, []string{"leaf.example.com"}), expectErr: true},
		"a port does not take a host out of a permission":        {subject: "https://leaf.example.com:8443", constraints: naming([]string{"leaf.example.com"}, nil)},
		"a Unicode host is refused under an exclusion":           {subject: "https://ëxample.com", constraints: naming(nil, []string{"other.org"}), expectErr: true},
		"a Unicode host is refused under a permission":           {subject: "https://ëxample.com", constraints: naming([]string{".com"}, nil), expectErr: true},
		"a Unicode host is unconstrained with no names":          {subject: "https://ëxample.com", constraints: &model.Constraints{MaxPathLength: new(int)}},
		"its punycode form is judged as a name":                  {subject: "https://xn--xample-ova.com", constraints: naming(nil, []string{"xn--xample-ova.com"}), expectErr: true},
		"an address is refused under a domain exclusion":         {subject: "https://192.0.2.1", constraints: naming(nil, []string{".evil.example"}), expectErr: true},
		"an IPv6 address is refused under a domain exclusion":    {subject: "https://[2001:db8::1]", constraints: naming(nil, []string{".evil.example"}), expectErr: true},
		"an address is refused under a numeric permission":       {subject: "https://192.0.2.1", constraints: naming([]string{"192.0.2.1"}, nil), expectErr: true},
		"a host read as a number by some resolvers is refused":   {subject: "https://3221225985", constraints: naming(nil, []string{".evil.example"}), expectErr: true},
		"a host with an empty label is refused":                  {subject: "https://leaf.example.com..", constraints: naming(nil, []string{".example.com"}), expectErr: true},
		"a host with an empty label escapes no host exclusion":   {subject: "https://leaf.example.com..", constraints: naming(nil, []string{"leaf.example.com"}), expectErr: true},
		"an address is unconstrained with no names":              {subject: "https://192.0.2.1", constraints: &model.Constraints{MaxPathLength: new(int)}},
		"an address never satisfies a domain permission":         {subject: "https://192.0.2.1", constraints: naming([]string{".example.com"}, nil), expectErr: true},
		"a converted Unicode host is excluded as its ASCII form": {subject: "https://ëxample.com", constraints: naming(nil, []string{"xn--xample-ova.com"}), hostToASCII: toASCII("xn--xample-ova.com", nil), expectErr: true},
		"a converted Unicode host outside an exclusion":          {subject: "https://ëxample.com", constraints: naming(nil, []string{"other.org"}), hostToASCII: toASCII("xn--xample-ova.com", nil)},
		"a converted Unicode host inside a permission":           {subject: "https://ëxample.com", constraints: naming([]string{".com"}, nil), hostToASCII: toASCII("xn--xample-ova.com", nil)},
		"a converted host is normalised before matching":         {subject: "https://ëxample.com", constraints: naming(nil, []string{"xn--xample-ova.com"}), hostToASCII: toASCII("XN--XAMPLE-OVA.COM.", nil), expectErr: true},
		"a host the converter refuses is refused":                {subject: "https://ëxample.com", constraints: naming(nil, []string{"other.org"}), hostToASCII: toASCII("", errors.New("invalid label")), expectErr: true},
		"a converter returning Unicode is not trusted":           {subject: "https://ëxample.com", constraints: naming(nil, []string{"other.org"}), hostToASCII: toASCII("ëxample.com", nil), expectErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			chain := []model.EntityStatement{
				{Iss: tc.subject, Sub: tc.subject},
				{Iss: chainAnchor, Sub: tc.subject, Constraints: tc.constraints},
				{Iss: chainAnchor, Sub: chainAnchor},
			}
			err := verifyChainConstraints(t.Context(), model.Configuration{HostToASCII: tc.hostToASCII}, chain)
			if tc.expectErr != (err != nil) {
				t.Fatalf("[6.2.2] expected a refusal %v, got %v", tc.expectErr, err)
			}
			if err != nil && !strings.Contains(err.Error(), "outside the naming constraints") {
				t.Errorf("expected the refusal to name the naming constraints, got %v", err)
			}
		})
	}
}

func TestVerifyChainConstraints_AnASCIIHostNeverReachesTheConverter(t *testing.T) {
	calls := 0
	cfg := model.Configuration{HostToASCII: func(host string) (string, error) {
		calls++
		return host, nil
	}}
	chain := []model.EntityStatement{
		{Iss: chainSubject, Sub: chainSubject},
		{Iss: chainAnchor, Sub: chainSubject, Constraints: &model.Constraints{NamingConstraints: &model.NamingConstraints{Excluded: []string{"leaf.example.com"}}}},
		{Iss: chainAnchor, Sub: chainAnchor},
	}
	if err := verifyChainConstraints(t.Context(), cfg, chain); err == nil {
		t.Fatalf("[6.2.2] expected the excluded host to be refused")
	}
	if calls != 0 {
		t.Errorf("expected an ASCII host to be matched without the converter, it was called %d times", calls)
	}
}
