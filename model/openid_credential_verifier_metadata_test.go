package model

import (
	"strings"
	"testing"
)

func TestOpenIDCredentialVerifierMetadata_VerifyMetadata(t *testing.T) {
	formats := map[string]any{"dc+sd-jwt": map[string]any{}}
	rsaKey := func(kid any, n string) map[string]any {
		key := map[string]any{"kty": "RSA", "n": n, "e": "AQAB"}
		if kid != nil {
			key["kid"] = kid
		}
		return key
	}
	keySet := func(keys ...any) map[string]any {
		return map[string]any{"keys": keys}
	}
	with := func(extra map[string]any) OpenIDCredentialVerifierMetadata {
		m := OpenIDCredentialVerifierMetadata{"vp_formats_supported": formats}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	tests := map[string]struct {
		reference string
		metadata  OpenIDCredentialVerifierMetadata
		says      string
	}{
		"empty metadata is valid": {
			reference: "OpenID Federation 1.1 5",
			metadata:  OpenIDCredentialVerifierMetadata{},
		},
		"valid metadata": {
			reference: "OpenID4VP 11.1",
			metadata:  with(nil),
		},
		"missing vp_formats_supported is not a syntax fault": {
			reference: "OpenID4VP 11.1",
			metadata:  OpenIDCredentialVerifierMetadata{"redirect_uris": []any{"https://verifier.example.com/cb"}},
		},
		"vp_formats_supported must be object": {
			reference: "OpenID4VP 11.1",
			metadata:  OpenIDCredentialVerifierMetadata{"vp_formats_supported": []any{"dc+sd-jwt"}},
			says:      "'vp_formats_supported' must be a JSON object",
		},
		"every draft 06 parameter in its defined shape": {
			reference: "Wallet draft 06 6.4.1",
			metadata: with(map[string]any{
				"jwks":                          keySet(rsaKey("a", "AQAB"), rsaKey("b", "AQAC")),
				"request_uris":                  []any{"https://verifier.example.com/request?id=1", "https://verifier.example.com/request#hash"},
				"response_uris":                 []any{"https://verifier.example.com/response?session=1"},
				"redirect_uris":                 []any{"https://verifier.example.com/cb?state=1"},
				"dcql_queries":                  []any{map[string]any{"credentials": []any{}}},
				"credential_verifier_providers": []any{"https://provider.example.com"},
			}),
		},
		"draft 06 parameters built as Go slices": {
			reference: "Wallet draft 06 6.4.1",
			metadata: with(map[string]any{
				"request_uris":                  []string{"https://verifier.example.com/request"},
				"response_uris":                 []string{"https://verifier.example.com/response"},
				"redirect_uris":                 []string{"https://verifier.example.com/cb"},
				"dcql_queries":                  []map[string]any{{"credentials": []any{}}},
				"credential_verifier_providers": []string{"https://provider.example.com"},
			}),
		},
		"an https scheme written in capitals": {
			reference: "RFC 3986 3.1",
			metadata:  with(map[string]any{"redirect_uris": []any{"HTTPS://verifier.example.com/cb"}}),
		},
		"redirect_uris must be array of strings": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"redirect_uris": "https://verifier.example.com/cb"}),
			says:      "'redirect_uris' must be an array of strings",
		},
		"request_uris holding a number": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"request_uris": []any{1}}),
			says:      "'request_uris' must be an array of strings",
		},
		"an empty request_uris": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"request_uris": []any{}}),
			says:      "'request_uris' must not be empty",
		},
		"an empty response_uris": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"response_uris": []any{}}),
			says:      "'response_uris' must not be empty",
		},
		"an empty redirect_uris": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"redirect_uris": []string{}}),
			says:      "'redirect_uris' must not be empty",
		},
		"a request_uris entry over http": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"request_uris": []any{"https://verifier.example.com/a", "http://verifier.example.com/b"}}),
			says:      "'request_uris' must hold only https URLs",
		},
		"a response_uris entry over http": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"response_uris": []any{"http://verifier.example.com/response"}}),
			says:      "'response_uris' must hold only https URLs",
		},
		"a redirect_uris entry with no host": {
			reference: "RFC 9110 4.2.2",
			metadata:  with(map[string]any{"redirect_uris": []any{"https:///cb"}}),
			says:      "'redirect_uris' must hold only https URLs",
		},
		"a redirect_uris entry that does not parse": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"redirect_uris": []any{"https://verifier.example.com/%zz"}}),
			says:      "'redirect_uris' must hold only https URLs",
		},
		"a redirect_uris entry with a fragment": {
			reference: "RFC 6749 3.1.2",
			metadata:  with(map[string]any{"redirect_uris": []any{"https://verifier.example.com/cb#done"}}),
			says:      "'redirect_uris' must not contain a fragment component",
		},
		"a redirect_uris entry with an empty fragment": {
			reference: "RFC 6749 3.1.2",
			metadata:  with(map[string]any{"redirect_uris": []any{"https://verifier.example.com/cb#"}}),
			says:      "'redirect_uris' must not contain a fragment component",
		},
		"an empty dcql_queries": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"dcql_queries": []any{}}),
			says:      "'dcql_queries' must not be empty",
		},
		"an empty dcql_queries built as a Go slice": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"dcql_queries": []map[string]any{}}),
			says:      "'dcql_queries' must not be empty",
		},
		"a dcql_queries entry that is not an object": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"dcql_queries": []any{map[string]any{}, "not-an-object"}}),
			says:      "'dcql_queries' must be an array of JSON objects",
		},
		"a dcql_queries that is an object": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"dcql_queries": map[string]any{"credentials": []any{}}}),
			says:      "'dcql_queries' must be an array of JSON objects",
		},
		"an empty credential_verifier_providers": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"credential_verifier_providers": []any{}}),
			says:      "'credential_verifier_providers' must not be empty",
		},
		"a credential_verifier_providers entry over http": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"credential_verifier_providers": []any{"http://provider.example.com"}}),
			says:      "'credential_verifier_providers' must hold only entity identifiers",
		},
		"a credential_verifier_providers entry with a query": {
			reference: "OpenID Federation 1.1 1.2",
			metadata:  with(map[string]any{"credential_verifier_providers": []any{"https://provider.example.com?tenant=1"}}),
			says:      "'credential_verifier_providers' must hold only entity identifiers",
		},
		"a credential_verifier_providers that is a string": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"credential_verifier_providers": "https://provider.example.com"}),
			says:      "'credential_verifier_providers' must be an array of strings",
		},
		"a jwks key with no kid": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"jwks": keySet(rsaKey("a", "AQAB"), rsaKey(nil, "AQAC"))}),
			says:      "'jwks' has an entry at position 1 of 'keys' with no 'kid' member",
		},
		"a jwks key of an unsupported type with no kid": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"jwks": keySet(map[string]any{"kty": "AKP", "pub": "AQAB"})}),
			says:      "'jwks' has an entry at position 0 of 'keys' with no 'kid' member",
		},
		"a jwks key of an unsupported type with a kid": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"jwks": keySet(map[string]any{"kty": "AKP", "pub": "AQAB", "kid": "pq"})}),
		},
		"a jwks key whose kid is a number": {
			reference: "RFC 7517 4.5",
			metadata:  with(map[string]any{"jwks": keySet(rsaKey(7, "AQAB"))}),
			says:      "'jwks' has an entry at position 0 of 'keys' with a malformed 'kid' member",
		},
		"two different jwks keys sharing a kid": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"jwks": keySet(rsaKey("a", "AQAB"), rsaKey("b", "AQAC"), rsaKey("a", "AQAD"))}),
			says:      "'jwks' has two different entries in 'keys' with the same 'kid'",
		},
		"two jwks keys sharing a kid and differing only in use": {
			reference: "Wallet draft 06 6.4.1",
			metadata: with(map[string]any{"jwks": keySet(
				map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB", "kid": "a", "use": "sig"},
				map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB", "kid": "a", "use": "enc"},
			)}),
			says: "'jwks' has two different entries in 'keys' with the same 'kid'",
		},
		"the same jwks key listed twice": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"jwks": keySet(rsaKey("a", "AQAB"), rsaKey("a", "AQAB"))}),
		},
		"a jwks with no keys": {
			reference: "Wallet draft 06 6.4.1",
			metadata:  with(map[string]any{"jwks": keySet()}),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.metadata.VerifyMetadata()
			if tt.says == "" {
				if err != nil {
					t.Errorf("[%s] expected the metadata to be accepted, got %v", tt.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected a refusal containing %q, got none", tt.reference, tt.says)
			}
			if !strings.Contains(err.Error(), tt.says) {
				t.Errorf("[%s] expected a refusal containing %q, got %v", tt.reference, tt.says, err)
			}
		})
	}
}

func TestOpenIDCredentialVerifierMetadata_VerifyResolvedMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata OpenIDCredentialVerifierMetadata
		wantErr  bool
	}{
		"an empty object does not satisfy a type that requires parameters": {
			metadata: OpenIDCredentialVerifierMetadata{},
			wantErr:  true,
		},
		"vp_formats_supported supplied": {
			metadata: OpenIDCredentialVerifierMetadata{
				"vp_formats_supported": map[string]any{"jwt_vc": map[string]any{}},
			},
			wantErr: false,
		},
		"missing vp_formats_supported": {
			metadata: OpenIDCredentialVerifierMetadata{
				"redirect_uris": []any{"https://verifier.example.com/cb"},
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.metadata.VerifyResolvedMetadata()
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyResolvedMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
