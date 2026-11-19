package model

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

type goPrivateMembers struct {
	D    string `json:"d"`
	P    string `json:"p"`
	Q    string `json:"q"`
	DP   string `json:"dp"`
	DQ   string `json:"dq"`
	QI   string `json:"qi"`
	Oth  string `json:"oth"`
	K    string `json:"k"`
	Priv string `json:"priv"`
}

func membersAGoConsumerReads(t *testing.T, name string) []string {
	t.Helper()
	raw, err := json.Marshal(map[string]string{name: "SECRETVALUE"})
	if err != nil {
		t.Fatalf("failed to write the key: %v", err)
	}
	var read goPrivateMembers
	if err := json.Unmarshal(raw, &read); err != nil {
		t.Fatalf("failed to read the key: %v", err)
	}
	var members []string
	for member, value := range map[string]string{"d": read.D, "p": read.P, "q": read.Q, "dp": read.DP, "dq": read.DQ, "qi": read.QI, "oth": read.Oth, "k": read.K, "priv": read.Priv} {
		if value != "" {
			members = append(members, member)
		}
	}
	return members
}

func TestPrivateJWKMembers_MatchesAMemberNameAsEncodingJSONDoes(t *testing.T) {
	tests := []struct {
		spelling string
		member   string
	}{
		{spelling: "D", member: "d"},
		{spelling: "P", member: "p"},
		{spelling: "Q", member: "q"},
		{spelling: "DP", member: "dp"},
		{spelling: "dP", member: "dp"},
		{spelling: "Dq", member: "dq"},
		{spelling: "QI", member: "qi"},
		{spelling: "OTH", member: "oth"},
		{spelling: "oTh", member: "oth"},
		{spelling: "K", member: "k"},
		{spelling: "\u212a", member: "k"},
		{spelling: "PRIV", member: "priv"},
		{spelling: "Priv", member: "priv"},
		{spelling: "kid"},
		{spelling: "kty"},
		{spelling: "dd"},
		{spelling: "x_d"},
		{spelling: "private"},
		{spelling: "dpop"},
		{spelling: "\uff44"},
		{spelling: "q\u0130"},
		{spelling: "pr\u0130v"},
		{spelling: "k "},
	}

	for _, tc := range tests {
		t.Run(tc.spelling, func(t *testing.T) {
			goReads := membersAGoConsumerReads(t, tc.spelling)
			var expect []string
			if tc.member != "" {
				expect = []string{tc.member}
			}
			if !slices.Equal(goReads, expect) {
				t.Fatalf("the fixture is wrong: encoding/json reads %q as %v, expected %v", tc.spelling, goReads, expect)
			}

			key := map[string]any{"kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", tc.spelling: "SECRETVALUE"}
			if got := PrivateJWKMembers(key); !slices.Equal(got, expect) {
				t.Errorf("[RFC 7518 6] a Go consumer reads %q as %v, so the private members found must be %v, got %v", tc.spelling, goReads, expect, got)
			}
			err := VerifyPublishableJWK(key)
			if tc.member == "" {
				if err != nil {
					t.Errorf("[RFC 7518 6] a member a Go consumer does not read as private must not refuse the key, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[RFC 7518 6] a key whose %q member a Go consumer reads as %q must be refused for publication", tc.spelling, tc.member)
			}
			if !strings.Contains(err.Error(), "["+tc.member+"]") || strings.Contains(err.Error(), "SECRETVALUE") {
				t.Errorf("[RFC 7518 6] expected the refusal to name %q and not carry the value, got %v", tc.member, err)
			}
		})
	}
}

func TestPrivateJWKMembers_NamesAMemberOnceHoweverManySpellingsCarryIt(t *testing.T) {
	key := map[string]any{"kty": "oct", "k": "a", "K": "b", "\u212a": "c", "d": "e", "D": "f"}
	for range 32 {
		if got := PrivateJWKMembers(key); !slices.Equal(got, []string{"d", "k"}) {
			t.Fatalf("[RFC 7518 6] expected each private member named once in a fixed order, got %v", got)
		}
	}
}
