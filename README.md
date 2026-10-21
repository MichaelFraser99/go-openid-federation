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

Each endpoint accepts the one method in the table. Any other method answers `405` with an `Allow` header and an `invalid_request` JSON body, rather than the `text/plain` body `http.ServeMux` writes by default, because section 8.9 wants a JSON object for an error and section 8.1.2 requires one on the fetch endpoint. `HEAD` is served wherever `GET` is.

`Configure` therefore registers each of the nine standard HTTP methods on each of these paths: the method in the table reaches the handler, and the other eight answer 405. A request carrying a method outside that set gets `http.ServeMux`'s own plain-text 405 instead, which is the one case the JSON guarantee does not cover. So the library owns those paths outright, and registering any handler of your own on one of them, with or without a method, makes `http.ServeMux` panic on the duplicate whichever order you register in. Broader patterns are unaffected: a catch-all such as `GET /`, `/{path...}` or a prefix like `/api/fetch` coexists, and keeps receiving everything the federation paths do not match.

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
| `trust_anchor` | yes | The trust anchor to resolve against. Section 8.3.1 permits the parameter more than once and leaves a resolver free to answer from any of them; this implementation uses the first and ignores the rest |
| `entity_type` | no | Repeatable; restricts the metadata returned |

Resolving metadata makes outbound HTTP requests for the caller-supplied `sub` and `trust_anchor` and for the federated authorities discovered while building the trust chain.

**`/extended-list`**

| Parameter | Required | Notes |
| --- | --- | --- |
| `from` | no | Opaque pagination cursor, taken from a previous response's `next` |
| `limit` | no | Defaults to `Extensions.ExtendedListing.SizeLimit` |
| `claims` | no | Comma separated, repeatable, or both. The value `subordinate_statement` issues a signed subordinate statement per entity |
| `entity_type` | no | Repeatable, as on `/list` |
| `trust_mark_type` | no | Repeatable, as on `/list` |
| `trust_marked` | no | `true` or `false`, as on `/list` |
| `intermediate` | no | `true` or `false`, as on `/list` |

The endpoint takes the `/list` filters as well as its own, which [Extended Subordinate Listing 1.0](https://openid.net/specs/openid-federation-extended-listing-1_0.html) section 3.2 requires. Supplying `updated_after`, `updated_before` or `audit_timestamps` returns `unsupported_parameter`.

`claims` names at most 64 distinct claims, across every form combined; duplicates and empty items do not count towards it. `entity_type` and `trust_mark_type` are each accepted at most 64 times. More than that answers `invalid_request`, because these parameters are otherwise bounded only by the request size and every value reaches your retriever.

A `from` the retriever no longer recognises answers `404 page_not_found`, which section 3.2 of that draft requires for a stale cursor. Return `model.NewPageNotFoundError(...)` for it; `model.NewNotFoundError(...)` answers `not_found` instead, which the draft reserves for an unknown subject. It is honoured for this retriever only: section 8.9 of the core specification does not define `page_not_found`, and says codes from the IANA registry MAY be used, so a caller of any other endpoint has no reason to understand it. Returned from any other retriever it is treated as an unclassified fault.

Like every classified error, the message you give `NewPageNotFoundError` is sent to the caller. Name the fault, not the cursor value or the store that rejected it.

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
| `TrustAnchors` | Keys held for each trust anchor this deployment trusts. Optional, but setting it restricts which anchors `/resolve` serves. See [Anchoring a chain a caller supplies](#anchoring-a-chain-a-caller-supplies) |

The signer's public key is added to the published JWKS, keyed by `kid`, if not already present.

When the library resolves a trust chain, it follows federation endpoints derived from untrusted entity identifiers and metadata. `model.ValidateEntityIdentifier` validates identifier syntax only. It does not resolve hosts or restrict which addresses a hostname may target. Deployments that expose `/resolve` or use the client-side resolution helpers should provide an `HttpClient` whose transport rejects disallowed destinations, including private, loopback, link-local and other reserved address ranges, and whose redirect handling preserves the same policy.

### Limits

| Limit | Default | Applies to |
|---|---|---|
| `Configuration.MaxPeerResponseBytes` | `model.DefaultMaxPeerResponseBytes`, 1 MiB | The body of any response fetched from a peer |
| `Configuration.MaxTrustChainDepth` | `model.DefaultMaxTrustChainDepth`, 10 | Entities on one path from the leaf to a trust anchor |
| `Configuration.MaxEntitiesTraversed` | `model.DefaultMaxEntitiesTraversed`, 1024 | Entity configurations one request may fetch while walking `authority_hints`, across every chain it builds |
| `Configuration.MaxTrustMarkIssuers` | `model.DefaultMaxTrustMarkIssuers` | Distinct trust mark issuers resolved for one subject |

> **Breaking change.** Two bounds that were absent now apply by default, and both `Server` and `Client` are subject to them.
>
> - `MaxTrustChainDepth` was unlimited by default and described as bounding the entities traversed. It bounds the length of one chain, which is a different thing, and it now defaults to 10. A federation whose legitimate chains are longer must raise it, or `/resolve` refuses every subject whose chain is longer.
> - `MaxEntitiesTraversed` is new and defaults to 1024.
> - Zero no longer means unlimited for either: it selects the default. Set a large value to restore the old behaviour.
> - A consumer who already set `MaxTrustChainDepth` themselves gets the same 404 as before, but with a description naming the bound rather than one that reads as an unknown trust anchor.
> - A trust mark whose issuer cannot be walked within the bounds is omitted from the response, as any unverifiable mark is. Section 8.3 requires a response to carry only verified trust marks, so the resolve still succeeds.

A request may also step into at most `MaxTrustChainDepth` × `MaxEntitiesTraversed` entities. One entity is stepped into many times when several paths lead to it, and the step bound is the backstop for a graph that defeats the memory of dead ends described below.

The default fetch bound is derived from the other two: a request may build one chain for the subject and one for each of `MaxTrustMarkIssuers` issuers, so a federation whose chains run to the full depth needs `(64 + 1) × 10 = 650` fetches before anything is wrong. Raising `MaxTrustChainDepth` or `MaxTrustMarkIssuers` without raising this one can starve the later issuer walks.

Reaching any of the three answers 404 `invalid_trust_anchor`, the code section 8.9 defines for a trust anchor that "cannot be found or used", with a description naming the bound. Four other conditions answer the same code: a chain that does not end in the named anchor, an anchor absent from a populated `TrustAnchors` map, an anchor whose entity configuration no configured key verifies, and a walk that reaches no anchor at all. Only the bounds also wrap `model.ErrLimitReached`. It is deliberately neither a `server_error` nor a `temporarily_unavailable`: the graph is the caller's choice, walking less of it than asked is not a fault of this server, and retrying gives the same answer. Consumers can separate the two cases with `errors.Is(err, model.ErrLimitReached)`. An operator reading a response body sees which bound was reached; a caller reading only the code cannot tell a bound from a genuinely unreachable anchor, which is deliberate, since the resolver does not know what lies past its own bound.

The bounds and the memory of dead ends span one resolve. `Server` builds a chain for the subject and another for each distinct trust mark issuer against a single budget, so one branch of the subject's graph can spend the budget that later issuer walks would have used. `Client.BuildTrustChain` and `Client.ResolveMetadata` each start their own, so a consumer calling both gets two budgets.

An entity proven not to reach the anchor is remembered for the rest of the request only when the verdict holds for any path to it. A verdict that depended on skipping a superior already on the path being walked, or on a bound cutting the walk short, is kept for that one walk and discarded afterwards: within a walk it is sound, because a superior that could reach the anchor would have reached it before the walk gave up, but another walk may arrive by a path where neither obstacle applies. A failure to fetch an entity configuration is remembered for the whole request, so a peer that is briefly unreachable during the subject's walk stays unreachable for the trust mark issuers' walks.

Subordinate statement fetches are outside both bounds. A request makes up to one per link of each chain it completes, so the bounds limit them only indirectly. See [#138](https://github.com/MichaelFraser99/go-openid-federation/issues/138).

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

An entity your `ExtendedListingRetriever` lists must also be resolvable through `Retriever`, or a request for the `subordinate_statement` claim returns that entity without one. Table 4 of the draft makes the attribute a MUST when the claim is asked for and does not qualify it, so this is a deliberate deviation: a listed entity the server cannot sign for is an inconsistency between two of your retrievers rather than a fault in the request, and failing the whole page for one entity is worse than omitting its statement. Keep the two retrievers consistent and the question does not arise. Any other failure while signing a statement is classified as usual, so a `model.Err*` sentinel from your `Retriever` chooses the status a peer sees.

Entries in `ImmediateSubordinateEntities` are `map[string]any`, and each one must carry an `id` whose value is a `string` holding an Entity Identifier. A store that round-trips through JSON yields `float64` for a numeric value, so an `id` that looks like a number arrives as the wrong type and the whole listing is refused with a `server_error`.

### Per-subordinate signing keys

A `SubordinateConfiguration` may carry its own `SignerConfiguration`. When present, that key signs the subordinate statement instead of the server's key, and its public half is published in the authority's JWKS.

## Entity statements and metadata

`model.EntityStatement` covers both entity configurations and subordinate statements. Its `UnmarshalJSON` enforces the required claims `iss`, `sub`, `iat`, `exp` and `jwks`, validates entity identifiers, and reads `jwks` as a JWK Set.

> **Breaking change.** Statements that earlier releases accepted are now refused.
>
> - A `jwks` **metadata parameter** must be a JWK Set: the `keys` member is required. Four entity types checked nothing there and accepted any JSON value; `"jwks": {}` is now refused everywhere. The `jwks` **claim** already required `keys`.
> - A key within a set that is not a usable JWK — no `kty`, or an EC key with no `crv` — is left out rather than refusing the statement, so a set carrying one retired entry still verifies through its good keys. "Usable" is only that much: `ValidateJWKShape` does not check the members RFC 7518 section 6 defines per key type, so an RSA key with no `n` is kept and fails later at verification.
> - Every key in a `jwks` **claim** must carry a unique, non-empty, string `kid`, which section 3.1.1 requires. A set that breaks this is refused rather than having the offending entry left out, because the rule is a Federation MUST about the whole set, not RFC 7517's advice about one key. A metadata `jwks` is unaffected: RFC 7517 section 4.5 keeps `kid` optional there.
> - A statement signed with a key that its publisher declares an `alg` for must use that `alg`. RFC 8725 section 3.1 requires a key to be used with exactly one algorithm and the check to be made where the operation happens. The comparison is exact, so a key published for `rs256` no longer verifies an `RS256` signature. **In a trust chain the key is the copy a superior published in its subordinate statement, so a superior's registration binds which algorithm its subordinate may sign with.** A trust anchor configured by hand with a subordinate's key and an `alg` the subordinate does not sign with refuses that subordinate with 400 `invalid_trust_chain`, where it previously resolved. A key with no `alg` is unconstrained.
> - `jwks_uri` and `signed_jwks_uri` must use https on every entity type that may carry them. Section 5.2.1 defines both, and forbids all three key parameters in `federation_entity` metadata. Six types gained the `signed_jwks_uri` check and three the `jwks_uri` check. Both go through the same URL check as the other claims, so a fragment or a userinfo component is refused too, which is what the relying party and provider types already did.
>
> A `kid` naming a key that was left out reads as no usable key with that `kid`, which is the same message as a `kid` that was never published. The library cannot say more, because the entry is gone by the time a key is selected.

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

Each is a `map[string]any` with its own validation, split across two points in the chain.

When metadata is unmarshalled, every statement is checked for claim shape: URL claims are HTTPS with no query or fragment component, string array claims are arrays of strings, object claims are objects, and signing algorithm claims exclude `none` where an algorithm is required. An empty object is accepted, so an entity may declare a type without asserting anything about it.

A consumer calling a built-in type's `VerifyMetadata` directly therefore gets claim shape only, not a full validation of that type.

> **Breaking change.** The required-claim checks moved out of `VerifyMetadata`, so `Metadata.UnmarshalJSON` no longer rejects a statement whose entity type is incomplete, and a consumer calling a type's `VerifyMetadata` as a full validator loses that half. Judge completeness with `VerifyResolvedMetadata`, or with `Metadata.VerifyResolved` for a whole metadata object.

Whether the required claims of a type are present is checked at the end of resolution, not on each statement. A subject may publish part of a type's metadata and leave its superior to supply the rest, through either a `metadata` claim or a metadata policy, so no single statement has to be complete on its own. The resolved metadata does, and `VerifyResolvedMetadata` is where that is judged. An empty object is accepted on a statement, and in the resolved metadata only for a type that has no required claims; for the rest it means none of them arrived.

## Custom entity types

OpenID Federation permits entity types beyond those the specification defines: "Additional Entity Type Identifiers MAY be defined to support use cases for other protocols."

Implement `model.EntityType` and add it to a configuration.

```go
type exampleService struct{}

func (exampleService) Identifier() string { return "example_service" }

func (exampleService) VerifyMetadata(metadata map[string]any) error {
	return model.VerifyHTTPSURLClaim(metadata, "service_endpoint", false)
}

func (exampleService) VerifyMetadataPolicy(policy map[string]model.PolicyOperators) error {
	return nil
}

func (exampleService) VerifyResolvedMetadata(metadata map[string]any) error {
	return model.VerifyRequiredClaims(metadata, "service_endpoint")
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

Put claim shape in `VerifyMetadata` and required claims in `VerifyResolvedMetadata`, as the example above does and as the built-in types do. A subject may publish part of a type and leave its superior to supply the rest, so a required claim checked in `VerifyMetadata` forces every statement to be complete on its own and refuses that arrangement.

Metadata policy can produce metadata that no longer satisfies the type's own rules, such as a `value` operator that removes a required claim. `VerifyResolvedMetadata` runs at the end of resolution, after the immediate superior's `metadata` claim and any policy have been applied, and before the resolve response is signed. It runs on every resolution path, including a chain carrying no policy at all. The built-in types check their required claims there.

An entity type with required claims that resolves to the empty object is refused for the same reason. The specification permits an entity to publish `{}` for a type its superiors will fill, but if nothing fills it the resolved metadata has none of the type's required claims, and section 6.1.4.2 requires resolved metadata that is incorrect to be treated as broken. `federation_entity`, `oauth_client` and `oauth_resource` have no required claims, so `{}` resolves for them.

> **Breaking change.** A subject that publishes `{}` for an entity type with required claims, and whose superiors supply none of them, previously resolved and now gets `invalid_metadata`. The resolution is refused as a whole rather than per type, so a caller asking for one entity type is refused because a different one is incomplete ([#158](https://github.com/MichaelFraser99/go-openid-federation/issues/158)).

Registered types are handled the same way as built-in types: published in entity configurations, carried in subordinate statements, subject to metadata policy, filtered by the `entity_type` parameter on `/resolve`, and passed through the `entity_type` filter on `/list`.

### Unrecognised types

Entity types absent from the registry are preserved and relayed unmodified. An intermediate can carry a type it has no definition for.

Set `DiscardUnrecognisedEntityTypes` to remove them instead. Discarding does not produce an error.

The nine built-in types are always registered and are never discarded. A registry entry under a built-in identifier adds its validation to that built-in rather than replacing it: `Metadata.UnmarshalJSON` always runs the built-in `VerifyMetadata`, and `Metadata.VerifyResolved` always runs the built-in `VerifyResolvedMetadata` alongside the registered one. A registration can therefore tighten a standard type but not loosen it. See [#74](https://github.com/MichaelFraser99/go-openid-federation/issues/74).

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
| `VerifyJWKSetClaims(m)` | `jwks`, if present, is a JWK Set, and `jwks_uri` and `signed_jwks_uri`, if present, are HTTPS URLs. Call it from a custom type that may carry keys. It does not enforce section 5.2.1's prohibition on these parameters in `federation_entity` metadata, which `FederationMetadata` carries |

`ParseJWKSet(v)` reads a JWK Set from a decoded JSON value. Use it rather than unmarshalling into a `jwks` struct field: Go matches struct fields with Unicode simple folding, so a member named `keyſ` decodes as `keys` and the keys a conforming parser reads are not the keys you get. It takes the keys from the exact `keys` member and leaves out an entry that `ValidateJWKShape` finds unusable, which RFC 7517 section 5 asks of an implementation. `ParseFederationEntityKeys(v)` is the stricter reading for a `jwks` claim: it adds section 3.1.1's rule that every key in the set carry a unique `kid`.

`MetadataStringSlice(v)` returns a `[]string` from either a `[]string` or a `[]any`. JSON unmarshalling produces the latter and Go-constructed metadata the former, so a validator handling only one will reject valid input.

## Metadata policy

### How operand values are compared

Operand equality is defined on the JSON value, and it is defined for the shapes a JSON decode produces: `nil`, `bool`, `string`, `float64`, `[]any` and `map[string]any`, plus the Go integer types. Such a value is compared by its canonical JSON encoding, which `encoding/json` writes with object member names sorted at every level.

Two operands are therefore the same operand when they encode identically. `{"a": "b c"}` and `{"a b": "c"}` are different objects, member order does not matter, and `{"a": "1"}` differs from `{"a": 1}`. Numbers compare as numbers, so `0` and `-0` are one operand, as are a Go `int` and a `float64` holding the same integer.

That encoding is also the key of a set, so membership is a lookup rather than a scan. Comparing two operators, merging two chain levels, and applying an operator to metadata are each linear in the number of operands, which a peer supplies.

Everything else compares by `reflect.DeepEqual`, which is exact on Go types and bytes and never treats two operands as one when they are not. A peer cannot reach this path, because every operand from a peer arrives through a JSON decode. A consumer building a policy in Go reaches it with:

- Any other Go type, such as a struct, a `[]string` or a `map[string]string`. These are compared by Go identity rather than by the JSON they would render, which is the conservative answer: a struct whose fields are all unexported renders as `{}`, so keying it would make every such struct one operand.
- A string holding bytes that are not valid UTF-8, anywhere in the value, including an object member name. `encoding/json` substitutes U+FFFD rather than failing, so the encoding would lose the distinction.
- A number with no JSON form. An infinity compares equal to itself. A `NaN` is equal to nothing, not even itself, as in Go and IEEE 754, so each one survives deduplication and satisfies no requirement.

Comparison on that path is a scan, so a policy built in Go from a large number of these values costs more than a policy of JSON values. Published policies hold JSON values by definition, so this affects only a consumer applying a policy it never serialises.

All seven operators from the specification are implemented: `value`, `add`, `default`, `one_of`, `subset_of`, `superset_of` and `essential`.

Policies are combined down a trust chain by `model.ProcessAndExtractPolicy` and applied to a subject's metadata by `model.ApplyPolicy`. Operators resolve in a fixed order: `value`, `add`, `default`, `one_of`, `subset_of`, `superset_of`, then `essential`. Combinations that cannot be satisfied, such as a `subset_of` and a `superset_of` with no overlap, are rejected when the policies are merged.

Policy comes from the subordinate statements in the chain and from nowhere else. `ProcessAndExtractPolicy` reads every statement whose `iss` differs from its `sub`, which is what makes a statement a subordinate statement, and skips the self-issued entity configurations at either end. So neither the subject nor the trust anchor can write policy for the subject through its own entity configuration, and a chain that omits the trust anchor's entity configuration, which the specification permits, still contributes every policy it holds. A policy carried in an entity configuration is also refused outright when the statement is validated.

> **Breaking change.** `ProcessAndExtractPolicy` previously read every statement, so an entity configuration carrying a policy contributed it. It now skips self-issued statements, and the former requirement of at least two statements is gone. A caller that builds statements by hand must set `iss` and `sub`, matched byte for byte: a statement with neither set is self-issued by that rule and carries no policy, and two spellings of one identifier that differ by a trailing slash are not.

It returns `(nil, nil)` for a chain that holds no subordinate statement, which includes a chain of entity configurations and any statement whose `iss` and `sub` are both unset. `ResolveMetadata` reads that as "no policy to apply"; a direct caller must check the result before dereferencing it.

`ProcessAndExtractPolicy` merges the policy of the statements it is given and establishes nothing about them. It cannot: it holds no keys, so it cannot check a signature, and it does not check that each statement is issued by the subject of the one above it. Feed it a chain from `BuildTrustChain`, which verifies every link. A hand-assembled chain carrying a statement about an unrelated entity will have that statement's policy applied to the subject, and the function will not object. It also writes the merged policy back into the first statement that carried one, so do not reuse a chain you have passed to it ([#156](https://github.com/MichaelFraser99/go-openid-federation/issues/156)).

Before any policy runs, the metadata parameters the subject's immediate superior supplies in its subordinate statement are applied over the subject's own, by `model.ApplySuperiorMetadata`. The superior's parameters take precedence, and only entity types the subject already publishes are affected, so a superior cannot give the subject an entity type the subject has not declared. A type declared as the empty object counts as declared, and the specification intends exactly that: an entity publishes `{}` for a type whose parameters its superiors will supply, so for such a type the superior writes all of it. Only the statement about the subject does this: a statement about an intermediate higher up has no effect on the leaf.

> **Breaking change.** The `metadata` claim of the subordinate statement about the subject was previously parsed and ignored. It is now applied. Any federation whose authorities populate that claim gets different resolved metadata after upgrading, because the superior's parameters override the subject's where they share a name.

Resolving by hand, rather than through `ResolveMetadata`, means four steps in this order: `model.ApplySuperiorMetadata` to apply the immediate superior's `metadata` claim over the subject's own, `model.ProcessAndExtractPolicy` to merge the chain's policy, `model.ApplyPolicy` to apply it, and `Metadata.VerifyResolved` to judge the result. Skipping the first drops a superior's pinned parameters; skipping the last accepts resolved metadata that no entity type would.

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

`/resolve` builds a chain from the subject up to the requested trust anchor by walking `authority_hints` depth first, backtracking on dead ends and skipping entities already checked. The walk is bounded (see [Limits](#limits)) and is refused with a 404 `invalid_trust_anchor` naming the bound when one is reached. Each step is verified: signatures against the issuer's published keys, `iss` and `sub` against the expected entities, and the subject's signing key against the JWKS in the subordinate statement above it.

A resolved response expires at the earliest expiry in the chain rather than the subject's own. Where a trust mark expires sooner, the response expiry is reduced to match.

Trust marks in a resolve response are filtered against the trust anchor's `trust_mark_issuers` claim. A trust mark whose type the anchor does not list, or whose issuer it has not authorised, is dropped from the response. Resolution continues.

### Anchoring a chain a caller supplies

`Client.ResolveMetadata` takes a chain the caller supplies, such as one from a peer's `trust_chain` JWS header. The library does not read that header, so the caller must extract it.

Two things are checked at the top of a chain, and only the second has cryptographic content.

The first is the identifier, and a chain may end in either of two shapes. Where the last statement is the trust anchor's own entity configuration, its `iss` and its `sub` must both equal the named anchor. Where the anchor's entity configuration is omitted and the last statement is the anchor's subordinate statement about the entity below it, only `iss` must equal the named anchor — the library then fetches the anchor's own entity configuration from its well-known URL and applies both checks to that. A chain that ends in neither shape is refused with `invalid_trust_anchor`, and so is one too short to carry a statement about its subject, before any request is made.

The second is the signature. `Configuration.TrustAnchors` holds the keys you have for each trust anchor you trust, and when the map holds keys for the named anchor the anchor's entity configuration must verify against one of them. Section 4 puts the distribution of those keys out of band, so the library cannot fetch them and has no way to obtain them itself.

> **The identifier check alone does not make a caller-supplied chain safe.** An attacker who writes the trust anchor's identifier into the `iss` and `sub` of their own self-signed entity configuration produces a chain that passes it, because nothing without the anchor's keys can tell that statement from the real one. **Do not pass a chain from an untrusted source to `Client.ResolveMetadata` unless `TrustAnchors` holds keys for the anchor you name.** Build the chain yourself with `Client.BuildTrustChain`, or configure the keys.

Section 10.2 draws the same distinction: an inner link verifies "with a public key in `ES[j+1]["jwks"]`", a key the chain itself carries, but the last statement must verify "with a public key of the Trust Anchor". Only `TrustAnchors` supplies the latter.

Four states, and the message says which one you are in:

| `TrustAnchors` | The named anchor | Result |
| --- | --- | --- |
| unset (nil) | — | Identifier check only. The entity configuration is accepted on its own signature, whether it came from the chain or from the anchor's well-known URL |
| set | has a key that can verify a signature | Identifier check, then the entity configuration must verify against one of those keys |
| set | absent, or mapped to an empty set | Refused: "not one this deployment is configured to trust" |
| set | present, but no key in it can verify a signature | Refused as `server_error` before any request: the deployment configured a key set it cannot use |

"Can verify a signature" means what the signing library means, not what the JWK syntax allows. A key is counted only if `github.com/MichaelFraser99/go-jose` can build a validator for it, which today covers the `ES`, `RS` and `PS` families. An Ed25519 key is valid JOSE and is **not** usable here, so configuring one is a `server_error` naming your own configuration rather than a 404 blaming the anchor.

A non-nil map with no entries refuses every anchor. That is deliberate: an anchor list that parsed to nothing is a configuration fault, not permission to check nothing.

Any key in the set may verify the entity configuration. Selection is not by `kid`, because section 4 hands you these keys out of band and RFC 7517 section 4.5 keeps `kid` optional, so a key you hold under a label of your own still works. A key the library cannot verify with is skipped rather than refusing the set, and a set left with none is the `server_error` above. The set is not checked against `use` or `key_ops`, so do not paste an anchor's encryption keys in alongside its signing keys; see [#188](https://github.com/MichaelFraser99/go-openid-federation/issues/188).

`BuildTrustChain` applies both checks to the top of the chain it builds, and refuses an anchor absent from a populated map before it makes any request.

> **Breaking change.** A chain of one entry now resolves only when the caller names that entry's own subject as the trust anchor. With `TrustAnchors` unset any entity is accepted as its own anchor, so this is an identifier check rather than a trust decision.

> **Breaking change.** `Client.ResolveMetadata` takes a `trustAnchor` argument between `subject` and `trustChain`. The trust anchor is a required parameter of the resolve request in section 8.3, and the chain cannot be anchored without it. An empty or malformed value is refused with `invalid_request`.

> **Breaking change.** Setting `TrustAnchors` on a `ServerConfiguration` restricts which anchors `/resolve` serves. Once the map is non-nil, a request naming an anchor it does not hold keys for is refused with 404 `invalid_trust_anchor`, on the subject's chain and on every trust mark issuer walk. A resolver that served any anchor in the federation becomes one that serves only the configured list. Leave the field unset to keep the old behaviour.

> **Breaking change.** `Client.ResolveMetadata` no longer returns nil metadata. Section 8.3.2 makes the claim required, so a subject that publishes no `metadata` now resolves to an empty `model.Metadata` rather than a nil pointer. A consumer treating nil as "this entity publishes nothing usable" must check the entity types instead.

The statements it returns are the chain as published, not the resolved result. A subject's metadata in them may be missing a required claim its superior supplies, and no policy has been applied, so read metadata from `ResolveMetadata` rather than from a statement in the chain.

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
| `ErrPageNotFound` | `page_not_found` | 404 |
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
| The anchor check with no `TrustAnchors` configured | Identifier only, so a caller-supplied chain is not cryptographically anchored | [#189](https://github.com/MichaelFraser99/go-openid-federation/issues/189) |
| Clock skew tolerance | `model.ClockSkewLeeway` is a constant and cannot be configured | [#141](https://github.com/MichaelFraser99/go-openid-federation/issues/141) |
| Server configuration validation | A bad `ServerConfiguration` is reported when a peer first fetches, not at startup | [#145](https://github.com/MichaelFraser99/go-openid-federation/issues/145) |
| Extension claims | Dropped on parse and cannot be issued | [#132](https://github.com/MichaelFraser99/go-openid-federation/issues/132) |
| `trust_chain` and `peer_trust_chain` JOSE headers | Not read or written | [#139](https://github.com/MichaelFraser99/go-openid-federation/issues/139) |
| Trust mark type identifiers as object member names | Member names in `trust_mark_issuers` and `trust_mark_owners` are not checked against a syntax, because §7.1 makes a URL RECOMMENDED rather than required and the one MUST, collision resistance, is not checkable | [#140](https://github.com/MichaelFraser99/go-openid-federation/issues/140) |
| Error classes on the fetch path | A peer's fault is reported as a server error | [#148](https://github.com/MichaelFraser99/go-openid-federation/issues/148) |
| `subordinate_statement` on an unlistable entity | Table 4 of the extended listing draft makes the attribute a MUST when requested, and an entity the subordinate store does not hold is returned without it | [#126](https://github.com/MichaelFraser99/go-openid-federation/issues/126) |
| Shape rules after a policy is applied | Required claims and the relying party key pair are checked on the resolved metadata, the remaining claim shape rules are not, so a policy can set a value the parser would refuse | [#144](https://github.com/MichaelFraser99/go-openid-federation/issues/144) |
| Policy merge against trust chain length | Cost grows faster than the chain. `MaxTrustChainDepth` now bounds the chain, which bounds the cost, but the merge still re-keys the whole accumulated array on every level | [#153](https://github.com/MichaelFraser99/go-openid-federation/issues/153) |

## License

MIT. See [LICENSE](LICENSE).
