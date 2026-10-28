package model

import "testing"

func TestNamesTheSameEntity_RefusesEverySpellingRFC3986MakesEquivalent(t *testing.T) {
	const own = EntityIdentifier("https://fed.example.com/ta")

	tests := map[string]struct {
		asked string
		same  bool
	}{
		"the identifier exactly as configured":       {asked: "https://fed.example.com/ta", same: true},
		"the host in a different case":               {asked: "https://FED.example.com/ta", same: true},
		"a fully qualified host, trailing dot":       {asked: "https://fed.example.com./ta", same: true},
		"the default https port stated":              {asked: "https://fed.example.com:443/ta", same: true},
		"the default port with a leading zero":       {asked: "https://fed.example.com:0443/ta", same: true},
		"a percent encoded unreserved character":     {asked: "https://fed.example.com/t%61", same: true},
		"every path character percent encoded":       {asked: "https://fed.example.com/%74%61", same: true},
		"a percent encoded dot segment":              {asked: "https://fed.example.com/x/%2e%2e/ta", same: true},
		"a trailing slash":                           {asked: "https://fed.example.com/ta/", same: true},
		"a doubled slash":                            {asked: "https://fed.example.com//ta", same: true},
		"dot segments that resolve to the same path": {asked: "https://fed.example.com/x/../ta", same: true},

		"a different path":                                  {asked: "https://fed.example.com/other"},
		"a different host":                                  {asked: "https://other.example.com/ta"},
		"a non default port":                                {asked: "https://fed.example.com:8443/ta"},
		"a percent encoded reserved character":              {asked: "https://fed.example.com/t%2Fa"},
		"a reserved character encoded to mimic a real path": {asked: "https://fed.example.com/ta%2Fsub"},
		"the path in a different case":                      {asked: "https://fed.example.com/TA"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := NamesTheSameEntity(own, EntityIdentifier(test.asked)); got != test.same {
				t.Errorf("[RFC 3986 6.2.2] %q against %q: expected same=%t, got %t", test.asked, own, test.same, got)
			}
		})
	}
}

func TestNamesTheSameEntity_DoesNotConflateIPv6HostsWithPorts(t *testing.T) {
	if NamesTheSameEntity("https://[::1]:8443/ta", "https://[::1:8443]/ta") {
		t.Error("[RFC 3986 3.2.2] a host with a port is not the same host as one whose literal contains those digits")
	}
	if !NamesTheSameEntity("https://[::1]:8443/ta", "https://[::1]:8443/ta") {
		t.Error("one IPv6 identifier must equal itself")
	}
}

func TestNamesTheSameEntity_DoesNotDecodeReservedOctets(t *testing.T) {
	const own = EntityIdentifier("https://fed.example.com/t/a")

	if NamesTheSameEntity(own, "https://fed.example.com/t%2Fa") {
		t.Error("[RFC 3986 2.2] '%2F' is not a path separator, so decoding it would make two different identifiers compare equal")
	}
	if !NamesTheSameEntity(own, "https://fed.example.com/t/a") {
		t.Error("an identifier with a real path separator must equal itself")
	}
}

func TestNamesTheSameEntity_DecodesEveryUnreservedOctet(t *testing.T) {
	tests := map[string]struct {
		own   EntityIdentifier
		asked string
	}{
		"a tilde":       {own: "https://fed.example.com/t~", asked: "https://fed.example.com/t%7e"},
		"a full stop":   {own: "https://fed.example.com/t.a", asked: "https://fed.example.com/t%2Ea"},
		"a hyphen":      {own: "https://fed.example.com/t-a", asked: "https://fed.example.com/t%2Da"},
		"an underscore": {own: "https://fed.example.com/t_a", asked: "https://fed.example.com/t%5Fa"},
		"a digit":       {own: "https://fed.example.com/t1", asked: "https://fed.example.com/t%31"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if !NamesTheSameEntity(test.own, EntityIdentifier(test.asked)) {
				t.Errorf("[RFC 3986 6.2.2.2] an unreserved octet is equivalent to the character it encodes, so %q must name the same entity as %q", test.asked, test.own)
			}
		})
	}
}

func TestNamesTheSameEntity_NormalisesAPortWhereverItIsKept(t *testing.T) {
	if !NamesTheSameEntity("https://fed.example.com:8443/ta", "https://fed.example.com:08443/ta") {
		t.Error("[RFC 3986 3.2.3] a port is a number, so leading zeros do not make a different authority")
	}
	if NamesTheSameEntity("https://fed.example.com:8443/ta", "https://fed.example.com:8444/ta") {
		t.Error("two different ports are two different authorities")
	}
}
