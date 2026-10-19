# go-openid-federation

[![Go Reference](https://pkg.go.dev/badge/github.com/MichaelFraser99/go-openid-federation.svg)](https://pkg.go.dev/github.com/MichaelFraser99/go-openid-federation)
[![Tests](https://github.com/MichaelFraser99/go-openid-federation/actions/workflows/tests.yml/badge.svg)](https://github.com/MichaelFraser99/go-openid-federation/actions/workflows/tests.yml)
[![golangci-lint](https://github.com/MichaelFraser99/go-openid-federation/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/MichaelFraser99/go-openid-federation/actions/workflows/golangci-lint.yml)

A Go implementation of [OpenID Federation](https://openid.net/specs/openid-federation-1_1.html), providing the entity statement model, metadata policy engine, trust chain resolution, and `net/http` handlers for the federation endpoints.

`model.ServerConfiguration` describes an entity's role in a federation. A leaf entity configures a signer and its metadata. An intermediate or trust anchor also configures subordinates, which enables the fetch, list and resolve endpoints.

## Installation

```sh
go get github.com/MichaelFraser99/go-openid-federation
```

Requires Go 1.25.3 or later.

## Packages

| Package | Purpose |
| --- | --- |
| `model` | Entity statements, metadata, metadata policy operators, entity identifiers, federation errors |
| `server` | `net/http` handlers for the federation endpoints |
| `server_test` | `TestServer` helper that stands up a four-entity federation over `httptest` |
| `model_test` | Test helpers for the model package |

## Quick start

### A leaf entity

A leaf publishes an entity configuration at `/.well-known/openid-federation` and nothing else.

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/server"
)

func main() {
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		log.Fatal(err)
	}

	cfg := model.ServerConfiguration{
		EntityIdentifier: "https://rp.example.com",
		SignerConfiguration: model.SignerConfiguration{
			Signer:    signer,
			KeyID:     "key-1",
			Algorithm: "ES256",
		},
		AuthorityHints:              []model.EntityIdentifier{"https://intermediate.example.com"},
		EntityConfigurationLifetime: 10 * time.Minute,
		EntityConfiguration: model.EntityStatement{
			Metadata: &model.Metadata{
				OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{
					"client_name":   "Example RP",
					"redirect_uris": []string{"https://rp.example.com/callback"},
				},
			},
		},
	}

	mux := http.NewServeMux()
	server.NewServer(cfg).Configure(mux)

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

`Configure` registers the handlers on the mux supplied to it. The federation endpoints can share a mux with an application's other routes.

### An intermediate or trust anchor

Setting `IntermediateConfiguration` marks an entity as an authority and enables `/fetch`, `/list` and `/resolve`. Subordinates can be held in memory or loaded on demand.

```go
intermediate := &model.IntermediateConfiguration{
	SubordinateStatementLifetime: time.Hour,
	SubordinateCacheTime:         5 * time.Minute,
}

intermediate.AddSubordinate("https://rp.example.com", &model.SubordinateConfiguration{
	JWKs: subordinateJWKs,
	Policies: model.MetadataPolicy{
		OpenIDRelyingPartyMetadata: map[string]model.PolicyOperators{
			"contacts": {Metadata: []model.MetadataPolicyOperator{addOperator}},
		},
	},
})

cfg := model.ServerConfiguration{
	EntityIdentifier:            "https://intermediate.example.com",
	SignerConfiguration:         signerConfiguration,
	EntityConfigurationLifetime: 10 * time.Minute,
	IntermediateConfiguration:   intermediate,
}
```

When an authority's entity configuration is generated, the federation endpoint claims are derived from the entity identifier: `federation_fetch_endpoint`, `federation_list_endpoint`, `federation_resolve_endpoint`, and the extension and trust mark endpoints where those are enabled. They do not need to be declared in `EntityConfiguration`.

## Endpoints

The handlers `Configure` registers depend on the configuration.

| Method and path | Registered when | Response content type |
| --- | --- | --- |
| `GET /.well-known/openid-federation` | always | `application/entity-statement+jwt` |
| `GET /fetch` | `IntermediateConfiguration` is set | `application/entity-statement+jwt` |
| `GET /list` | `IntermediateConfiguration` is set | `application/json` |
| `GET /resolve` | `IntermediateConfiguration` is set | `application/resolve-response+jwt` |
| `GET /extended-list` | `Extensions.ExtendedListing.Enabled` | `application/json` |
| `GET /subordinate-status` | `Extensions.SubordinateStatus.Enabled` | `application/entity-events-statement+jwt` |
| `GET /trust-mark` | `TrustMarkRetriever` is set | `application/trust-mark+jwt` |
| `GET /trust-mark-list` | `TrustMarkRetriever` is set | `application/json` |
| `POST /trust-mark-status` | `TrustMarkRetriever` is set | `application/trust-mark-status-response+jwt` |

### Query parameters

**`/fetch`**

| Parameter | Required | Notes |
| --- | --- | --- |
| `sub` | yes | Must be a valid entity identifier, and must not be the server's own identifier |

**`/list`**

| Parameter | Required | Notes |
| --- | --- | --- |
| `entity_type` | no | Repeatable |
| `trust_mark_type` | no | |
| `trust_marked` | no | Boolean |
| `intermediate` | no | Boolean |

Filters are honoured only when the configured `MetadataRetriever` also implements `model.SubordinateListingRetriever`. If a filter is supplied and it does not, the request is rejected with `unsupported_parameter`.

**`/resolve`**

| Parameter | Required | Notes |
| --- | --- | --- |
| `sub` | yes | The entity to resolve |
| `trust_anchor` | yes | The trust anchor to resolve against |
| `entity_type` | no | Repeatable; restricts the metadata returned |

Resolving metadata makes outbound HTTP requests for the caller-supplied `sub` and `trust_anchor` and for the federated authorities discovered while building the trust chain.

**`/extended-list`**

| Parameter | Required | Notes |
| --- | --- | --- |
| `from_entity_id` | no | Pagination cursor |
| `limit` | no | Defaults to `Extensions.ExtendedListing.SizeLimit` |
| `claims` | no | Comma separated. The value `subordinate_statement` issues a signed subordinate statement per entity |

Supplying `updated_after`, `updated_before` or `audit_timestamps` returns `unsupported_parameter`.

**`/trust-mark`**

| Parameter | Required |
| --- | --- |
| `sub` | yes |
| `trust_mark_type` | yes |

**`/trust-mark-list`**

| Parameter | Required |
| --- | --- |
| `trust_mark_type` | yes |
| `sub` | no |

**`/trust-mark-status`**

Takes `trust_mark` as a POST form value.

**`/subordinate-status`**

Takes `sub` as a required query parameter.

### The ResponseFunc pattern

Handlers do not write to the `http.ResponseWriter` directly. Each returns a `server.ResponseFunc`, a closure that performs the write when called:

```go
mux := http.NewServeMux()
server.Configure(mux)
```

The response is determined before it is written, so a caller can run code between the two.

Use `Configure` to mount the endpoints. It wraps every route it registers, so a panic in a retriever answers 500 with a JSON error body rather than dropping the connection. Mounting a handler by hand, as `func(w, r) { s.Fetch(w, r)() }`, has no such wrapper, so recover in your own middleware if you need to take that route.

## Configuration

### ServerConfiguration

| Field | Purpose |
| --- | --- |
| `HttpClient` | Client used for outbound federation requests. Required for trust-chain resolution and other remote federation lookups; callers should provide an SSRF-safe client that enforces their network policy for untrusted entity identifiers |
| `Logger` | Optional `*slog.Logger`. Logging is skipped when nil |
| `EntityTypes` | Extension entity types, merged over the built-in definitions |
| `DiscardUnrecognisedEntityTypes` | Removes entity types absent from the registry. Defaults to preserving them |
| `SignerConfiguration` | The entity's signing key, key ID and algorithm |
| `EntityIdentifier` | The entity's own identifier |
| `AuthorityHints` | Identifiers of the entity's immediate superiors |
| `TrustMarks` | Trust marks to publish in the entity configuration |
| `EntityConfiguration` | The entity statement to publish. The library sets `iss`, `sub`, `iat`, `exp`, `authority_hints`, `trust_marks` and `jwks`, and sets `trust_mark_issuers` when a `TrustMarkIssuerRetriever` is configured. It clears the subordinate-statement-only claims `metadata_policy`, `constraints` and `source_endpoint` |
| `EntityConfigurationLifetime` | How long a generated entity configuration remains valid. Defaults to `model.DefaultEntityConfigurationLifetime` when zero. A negative value, or a positive value under one second, is refused |
| `IntermediateConfiguration` | Set if the entity issues subordinate statements |
| `Extensions` | Opt-in extension endpoints |
| `MetadataRetriever` | Source of subordinate data, if not held in memory |
| `TrustMarkIssuerRetriever` | Populates `trust_mark_issuers` in the entity configuration |
| `TrustMarkRetriever` | Enables the trust mark endpoints |

The signer's public key is added to the published JWKS, keyed by `kid`, if not already present.

When the library resolves a trust chain, it follows federation endpoints derived from untrusted entity identifiers and metadata. `model.ValidateEntityIdentifier` validates identifier syntax only. It does not resolve hosts or restrict which addresses a hostname may target. Deployments that expose `/resolve` or use the client-side resolution helpers should provide an `HttpClient` whose transport rejects disallowed destinations, including private, loopback, link-local and other reserved address ranges, and whose redirect handling preserves the same policy.

### Limits

| Limit | Default | Applies to |
|---|---|---|
| `Configuration.MaxPeerResponseBytes` | `model.DefaultMaxPeerResponseBytes`, 1 MiB | The body of any response fetched from a peer |
| `Configuration.MaxTrustChainDepth` | unlimited | Entities traversed while walking `authority_hints` |
| `Configuration.MaxTrustMarkIssuers` | `model.DefaultMaxTrustMarkIssuers` | Distinct trust mark issuers resolved for one subject |

### Retriever interfaces

`Retriever` replaces in-memory subordinate storage. The others enable additional endpoints.

```go
type Retriever interface {
	GetSubordinate(ctx context.Context, identifier EntityIdentifier) (*SubordinateConfiguration, error)
	GetSubordinates(ctx context.Context) (map[EntityIdentifier]*SubordinateConfiguration, error)
	GetSubordinateSigners(ctx context.Context) ([]SignerConfiguration, error)
}

type SubordinateListingRetriever interface {
	ListSubordinates(ctx context.Context, filter SubordinateListingFilter) ([]EntityIdentifier, error)
}

type TrustMarkRetriever interface {
	GetTrustMarkStatus(ctx context.Context, trustMark string) (*string, error)
	IssueTrustMark(ctx context.Context, trustMarkIdentifier string, entityIdentifier EntityIdentifier) (*string, error)
	ListTrustMarks(ctx context.Context, trustMarkIdentifier string, identifier *EntityIdentifier) ([]EntityIdentifier, error)
}

type TrustMarkIssuerRetriever interface {
	ListTrustMarkIssuers(ctx context.Context) (map[string][]EntityIdentifier, error)
}

type ExtendedListingRetriever interface {
	GetExtendedSubordinates(ctx context.Context, filter ExtendedListingFilter) (*ExtendedListingResponse, error)
}

type SubordinateStatusRetriever interface {
	GetSubordinateStatus(ctx context.Context, sub EntityIdentifier) (*SubordinateStatusResponse, error)
}
```

Subordinates retrieved through a `Retriever` are cached for `IntermediateConfiguration.SubordinateCacheTime`. `FlushCache` invalidates the cache.

#### What to return when the subject is unknown

Return `model.NewNotFoundError(...)`. The library maps that to the status code each endpoint's specification requires: 404 for an unknown trust mark (section 8.4.2 makes this a MUST), 404 for an entity that does not hold the requested trust mark (section 8.6.2, also a MUST), and `not_found` for a subject the fetch endpoint cannot answer for (section 8.1.2 recommends it).

A retriever that returns `(nil, nil)` is treated the same way, so a store that signals "no row" with a nil result still produces a conforming response.

> **Breaking change.** Returning a bare `error` for an unknown subject now gives the caller a 500 rather than a 404. Earlier releases turned every retriever error into 404 `not_found`, which reported a store outage to federation peers as "this subordinate does not exist". If your retriever signals an unknown subject with a bare error — `sql.ErrNoRows`, an ORM's "record not found", or your own sentinel — wrap it with `model.NewNotFoundError(...)` or return `(nil, nil)`, or `/fetch` will answer 500 for every unknown subject.

The text of an unclassified retriever error is never sent to the caller, on any endpoint. It is logged, and the response carries a fixed description, because a driver error commonly contains a host name and a user name. An error carrying one of the `model.Err*` sentinels passes through unchanged, so returning `model.NewUnsupportedParameterError(...)` or `model.NewTemporarilyUnavailableError(...)` still chooses the status and description a peer sees.

`ExtendedListingRetriever` is the exception, in two ways. An unknown subject there is an empty listing rather than an error, so return an empty `ImmediateSubordinateEntities`. And a nil response is **not** treated as not found: it answers `server_error`, because a listing retriever that returns nothing at all is a misconfiguration rather than a statement about any one subject.

Entries in `ImmediateSubordinateEntities` are `map[string]any`, and each one must carry an `id` whose value is a `string` holding an Entity Identifier. A store that round-trips through JSON yields `float64` for a numeric value, so an `id` that looks like a number arrives as the wrong type and the whole listing is refused with a `server_error`.

### Per-subordinate signing keys

A `SubordinateConfiguration` may carry its own `SignerConfiguration`. When present, that key signs the subordinate statement instead of the server's key, and its public half is published in the authority's JWKS.

## Entity statements and metadata

`model.EntityStatement` covers both entity configurations and subordinate statements. Its `UnmarshalJSON` enforces the required claims `iss`, `sub`, `iat`, `exp` and `jwks`, and validates entity identifiers.

Parsing applies the claim rules from section 3.2 of the specification. Three of these reject statements that earlier releases accepted.

- A statement is rejected when it is expired or future-dated. Both comparisons allow `model.ClockSkewLeeway` of clock skew, and so does the trust chain expiry check, so the two layers agree on what expired means. The `iat` claim must be before the `exp` claim.
- A statement that carries a `crit` claim is rejected, with no opt-in. The library has no way to carry the critical extension claims themselves. See issue #132.
- A statement that carries a `metadata_policy_crit` claim is rejected. The claim names metadata policy operators that an implementation must understand, and this library understands none beyond the seven standard operators.

`EntityStatement` has no field for either `crit` or `metadata_policy_crit`. Both claims are refused on the way in, and the library cannot emit either, so there is no field to set.

Both issuance paths check their own output against these rules. `Server.HandleWellKnown` and the fetch endpoint fail rather than publish a statement that this library would refuse to read.

Entity identifiers are validated by `model.ValidateEntityIdentifier`. An identifier must be an HTTPS URL with a host. It must not carry a query, fragment or userinfo component. This validation is syntactic and does not make an identifier safe to fetch.

The following entity types are supported.

| Entity type identifier | Field on `model.Metadata` |
| --- | --- |
| `federation_entity` | `FederationMetadata` |
| `openid_relying_party` | `OpenIDRelyingPartyMetadata` |
| `openid_provider` | `OpenIDConnectOpenIDProviderMetadata` |
| `oauth_authorization_server` | `OAuthAuthorizationServerMetadata` |
| `oauth_client` | `OAuthClientMetadata` |
| `oauth_resource` | `OAuthResourceMetadata` |
| `openid_wallet_provider` | `OpenIDWalletProviderMetadata` |
| `openid_credential_issuer` | `OpenIDCredentialIssuerMetadata` |
| `openid_credential_verifier` | `OpenIDCredentialVerifierMetadata` |

Each is a `map[string]any` with its own validation, run when metadata is unmarshalled. An empty object is accepted, so an entity may declare a type without asserting anything about it.

Validation covers claim shape rather than claim semantics: required claims are present, URL claims are HTTPS with no query or fragment component, string array claims are arrays of strings, and signing algorithm claims exclude `none` where an algorithm is required.

## Custom entity types

OpenID Federation permits entity types beyond those the specification defines: "Additional Entity Type Identifiers MAY be defined to support use cases for other protocols."

Implement `model.EntityType` and add it to a configuration.

```go
type exampleService struct{}

func (exampleService) Identifier() string { return "example_service" }

func (exampleService) VerifyMetadata(metadata map[string]any) error {
	if len(metadata) == 0 {
		return nil
	}
	if err := model.VerifyRequiredClaims(metadata, "service_endpoint"); err != nil {
		return err
	}
	return model.VerifyHTTPSURLClaim(metadata, "service_endpoint", false)
}

func (exampleService) VerifyMetadataPolicy(policy map[string]model.PolicyOperators) error {
	return nil
}

func (exampleService) VerifyResolvedMetadata(metadata map[string]any) error {
	return nil
}
```

```go
cfg := model.ServerConfiguration{
	Configuration: model.Configuration{
		EntityTypes: model.EntityTypeRegistry{
			"example_service": exampleService{},
		},
	},
}
```

The hooks run at the following points.

| Hook | Runs on |
| --- | --- |
| `VerifyMetadata` | Metadata as declared, when an entity configuration or subordinate statement is validated |
| `VerifyMetadataPolicy` | A metadata policy an authority has written for the type |
| `VerifyResolvedMetadata` | The metadata remaining after policy has been applied, at the end of resolution |

Metadata policy can produce metadata that no longer satisfies the type's own rules, such as a `value` operator that removes a required claim. `VerifyResolvedMetadata` runs after policy application and before the resolve response is signed.

Registered types are handled the same way as built-in types: published in entity configurations, carried in subordinate statements, subject to metadata policy, filtered by the `entity_type` parameter on `/resolve`, and passed through the `entity_type` filter on `/list`.

### Unrecognised types

Entity types absent from the registry are preserved and relayed unmodified. An intermediate can carry a type it has no definition for.

Set `DiscardUnrecognisedEntityTypes` to remove them instead. Discarding does not produce an error.

The nine built-in types are always registered and are never discarded. A registry entry under a built-in identifier adds its validation to that built-in rather than replacing it, because `Metadata.UnmarshalJSON` always runs the built-in check. A registration can therefore tighten a standard type but not loosen it. See [#74](https://github.com/MichaelFraser99/go-openid-federation/issues/74).

`model.DefaultEntityTypeRegistry` returns the built-in definitions. Embedding one in a custom type delegates to its validation, which is useful when a type is close to a standardised one.

### Claim validators

The validators the built-in types use are exported for custom types to reuse.

| Function | Checks |
| --- | --- |
| `VerifyRequiredClaims(m, keys...)` | Every named claim is present |
| `VerifyObjectClaim(m, key)` | The claim, if present, is a JSON object |
| `VerifyStringArrayClaim(m, key)` | The claim, if present, is an array of strings |
| `VerifyNonEmptyStringArrayClaim(m, key)` | The claim, if present, is a non-empty array of strings |
| `VerifyHTTPSURLClaim(m, key, allowQuery)` | The claim, if present, is an HTTPS URL with no fragment and no userinfo component |
| `VerifyAlgValuesClaim(m, key, allowNone)` | The claim, if present, is an array of algorithm names. Rejects `none` unless `allowNone` is set |
| `VerifyAlgClaim(m, key, allowNone)` | The claim, if present, is a single algorithm name. Rejects `none` unless `allowNone` is set |

`MetadataStringSlice(v)` returns a `[]string` from either a `[]string` or a `[]any`. JSON unmarshalling produces the latter and Go-constructed metadata the former, so a validator handling only one will reject valid input.

## Metadata policy

### How operand values are compared

Policy operators compare their operand values by canonical JSON encoding. Two values are the same value when they encode identically, so `{"a": "b c"}` and `{"a b": "c"}` are different objects, member order does not matter, and `{"a": "1"}` differs from `{"a": 1}`.

That encoding is also the key of a set, so membership is a lookup rather than a scan: comparing two operators, merging two chain levels, and applying an operator to metadata are each linear in the number of values rather than quadratic.

A value with no JSON encoding, which a consumer can construct in Go but a peer cannot send, falls back to `reflect.DeepEqual`. A `NaN` is therefore not equal to itself, as in Go and IEEE 754.

All seven operators from the specification are implemented: `value`, `add`, `default`, `one_of`, `subset_of`, `superset_of` and `essential`.

Policies are combined down a trust chain by `model.ProcessAndExtractPolicy` and applied to a subject's metadata by `model.ApplyPolicy`. Operators resolve in a fixed order: `value`, `add`, `default`, `one_of`, `subset_of`, `superset_of`, then `essential`. Combinations that cannot be satisfied, such as a `subset_of` and a `superset_of` with no overlap, are rejected when the policies are merged.

`scope` is handled as a special case. It travels as a space delimited string but is operated on as a list, so operators are converted to their slice form before resolution and the result is rejoined afterwards.

To implement an operator outside this set, satisfy `model.MetadataPolicyOperator`:

```go
type MetadataPolicyOperator interface {
	String() string
	Resolve(metadataParameterValue any) (any, error)
	ResolutionHierarchy() int
	Merge(valueToMerge any) (MetadataPolicyOperator, error)
	OperatorValue() any
	ToSlice(key string) MetadataPolicyOperator
	CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error
}
```

## Trust chains

`/resolve` builds a chain from the subject up to the requested trust anchor by walking `authority_hints` depth first, backtracking on dead ends and skipping entities already checked. Each step is verified: signatures against the issuer's published keys, `iss` and `sub` against the expected entities, and the subject's signing key against the JWKS in the subordinate statement above it.

A resolved response expires at the earliest expiry in the chain rather than the subject's own. Where a trust mark expires sooner, the response expiry is reduced to match.

Trust marks in a resolve response are filtered against the trust anchor's `trust_mark_issuers` claim. A trust mark whose type the anchor does not list, or whose issuer it has not authorised, is dropped from the response. Resolution continues.

### Chains supplied by a caller are not anchored

`Client.ResolveMetadata` takes a chain the caller supplies, such as one received in a peer's `trust_chain` JWS header. The library does not read that header, so the caller must extract it. It verifies every link in that chain, but it cannot yet check which trust anchor the chain ends in, because trust anchors and their keys are not configurable. A chain that ends in a self-signed entity configuration is therefore accepted, and an attacker who supplies one needs no key material to have their own metadata returned for any subject they name.

Do not pass a chain from an untrusted source to `Client.ResolveMetadata`. Build the chain yourself with `Client.BuildTrustChain`, naming the trust anchor, and resolve that.

`BuildTrustChain` verifies every link as section 10.2 requires: each statement is signed by a key published for it in the statement above. It stops short only of the last step, confirming that the anchor at the top is one you trust, which needs the trust anchor configuration that is not yet available.

## Errors

Federation errors are sentinel values wrapped with a description, so they carry detail and can be matched with `errors.Is`.

```go
if errors.Is(err, model.ErrInvalidTrustAnchor) {
	// ...
}
```

| Error | Code | HTTP status |
| --- | --- | --- |
| `ErrInvalidRequest` | `invalid_request` | 400 |
| `ErrInvalidClient` | `invalid_client` | 401 |
| `ErrInvalidIssuer` | `invalid_issuer` | 404 |
| `ErrInvalidSubject` | `invalid_subject` | 404 |
| `ErrInvalidTrustAnchor` | `invalid_trust_anchor` | 404 |
| `ErrInvalidTrustChain` | `invalid_trust_chain` | 400 |
| `ErrInvalidMetadata` | `invalid_metadata` | 400 |
| `ErrNotFound` | `not_found` | 404 |
| `ErrTemporarilyUnavailable` | `temporarily_unavailable` | 503 |
| `ErrUnsupportedParameter` | `unsupported_parameter` | 400 |
| `ErrServerError` | `server_error` | 500 |

Errors are returned to callers as a JSON object with `error` and `error_description`.

## Extensions

Two endpoints beyond the core specification are available. Both are disabled by default.

**Extended listing** returns subordinate entities with selected claims inline, paginated, rather than as a flat list of identifiers. Enable it with `Extensions.ExtendedListing`, supplying a `SizeLimit` and an `ExtendedListingRetriever`. Requesting the `subordinate_statement` claim signs a statement for every entity in the page.

**Subordinate status** returns a signed record of registration events for a subordinate. Enable it with `Extensions.SubordinateStatus`, supplying a `SubordinateStatusRetriever` and optionally a `ResponseLifetime`.

## Testing

```sh
make test
```

`server_test.TestServer` stands up a four-entity federation over `httptest`: a leaf, two intermediates and a trust anchor, with signing keys and metadata policies at each level.

```go
func TestSomething(t *testing.T) {
	s := server_test.TestServer(t)
	defer s.Close()

	// s.URL + "/leaf", "/int1", "/int2", "/ta"
}
```

## Development

```sh
make test
```

Linting is handled by golangci-lint v2.6.1, run in CI and via pre-commit. To run the hooks locally:

```sh
pre-commit install
pre-commit run --all-files
```

## Specification coverage

Entity statements and configurations, subordinate statements, trust chain construction and validation, all seven metadata policy operators, metadata validation for the nine entity types listed above, registration of additional entity types, trust mark issuance, listing and status, and the fetch, list, resolve and well-known endpoints.

### Known gaps

| Area | Status | Issue |
|---|---|---|
| `constraints` claim | Parsed and carried, never enforced | [#50](https://github.com/MichaelFraser99/go-openid-federation/issues/50) |
| Configurable trust anchors and their keys | Not supported, so a caller-supplied chain cannot be anchored | [#48](https://github.com/MichaelFraser99/go-openid-federation/issues/48) |
| `metadata_policy` in an entity configuration | Rejected on read, but `ProcessAndExtractPolicy` still seeds from the first chain entry | [#51](https://github.com/MichaelFraser99/go-openid-federation/issues/51) |
| Clock skew tolerance | `model.ClockSkewLeeway` is a constant and cannot be configured | [#141](https://github.com/MichaelFraser99/go-openid-federation/issues/141) |
| JWS `alg` against the signing key | The `alg` header is not compared to the `alg` member of the selected JWK | [#142](https://github.com/MichaelFraser99/go-openid-federation/issues/142) |
| Resolved metadata validation | Entity type validation runs on parse, not after a metadata policy is applied | [#144](https://github.com/MichaelFraser99/go-openid-federation/issues/144) |
| Server configuration validation | A bad `ServerConfiguration` is reported when a peer first fetches, not at startup | [#145](https://github.com/MichaelFraser99/go-openid-federation/issues/145) |
| Extension claims | Dropped on parse and cannot be issued | [#132](https://github.com/MichaelFraser99/go-openid-federation/issues/132) |
| `trust_chain` and `peer_trust_chain` JOSE headers | Not read or written | [#139](https://github.com/MichaelFraser99/go-openid-federation/issues/139) |
| Trust mark type identifiers as object member names | Values are validated, member names are not | [#140](https://github.com/MichaelFraser99/go-openid-federation/issues/140) |
| JWK sets whose keys omit `kty` | Accepted on read, so the fault surfaces at verification | [#146](https://github.com/MichaelFraser99/go-openid-federation/issues/146) |
| A `jwks` member name that case-folds to `keys` | Supplies the verification keys through Go's case-insensitive decode | [#147](https://github.com/MichaelFraser99/go-openid-federation/issues/147) |
| Error classes on the fetch path | A peer's fault is reported as a server error | [#148](https://github.com/MichaelFraser99/go-openid-federation/issues/148) |

## License

MIT. See [LICENSE](LICENSE).
