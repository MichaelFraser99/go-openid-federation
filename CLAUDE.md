# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A Go library implementing the [OpenID Federation](https://openid.net/specs/openid-federation-1_1.html) specification. It provides the building blocks for participating in a federation as either a **server** (an entity/intermediate/trust anchor that publishes statements and serves federation endpoints) or a **client** (a relying party that builds and resolves trust chains). This is a library, not a runnable service — the `Makefile` `build` target that produces an AWS Lambda `bootstrap`/`main.zip` refers to a `main.go` that does not exist in this repo; treat it as a downstream-consumer packaging convention, not something you can run here.

## Commands

- **Test:** `go test ./...` (also `make test`). CI runs `go test -v ./...`.
- **Single test:** `go test ./model -run TestMetadataProcessingE2E` (add `-v` for verbose).
- **Lint:** `golangci-lint run` (version pinned to v2.13.1 in CI and pre-commit; match it locally). Run `pre-commit run --all-files` to reproduce the full pre-commit gate (end-of-file/trailing-whitespace fixers, yaml check, `no-commit-to-branch`, and `golangci-lint-full`).
- **Go version:** 1.26 (see `go.mod`).

## Architecture

Four packages, layered:

- **`model/`** — All exported types, JWT/entity-statement data structures, and the metadata-policy engine. This is the bulk of the code and where most logic lives. Depends on nothing else in the repo.
- **`internal/`** — The federation protocol mechanics, split by concern: `entity_configuration` (fetch/verify an entity's own `.well-known/openid-federation`), `subordinate_statement` (fetch a statement about a subordinate from its superior's fetch endpoint), `entity_statement` (low-level JWT parsing), `trust_chain` (chain building + metadata resolution), `trust_marks`. These consume `model` and perform the actual HTTP + signature verification.
- **`server/`** — HTTP handlers for the federation endpoints, wired up in `server/server.go`. `Server.Configure(*http.ServeMux)` registers routes conditionally based on config (see below).
- **`client/`** — Thin public wrapper exposing `BuildTrustChain` and `ResolveMetadata`, delegating to `internal/trust_chain`.

### Cryptography

All JWS/JWK/JWT signing and verification goes through the sibling library `github.com/MichaelFraser99/go-jose` (`jwk`, `jws`, `jwt`, `model` subpackages). Do not hand-roll crypto — entity statements and trust marks are signed JWTs handled via that dependency.

### Anchoring the top of a chain

Two functions, and the split matters. `verifyTrustAnchorRequested` judges the caller's argument alone — empty (`invalid_request`) or absent from a populated `TrustAnchors` map (`invalid_trust_anchor`) — and runs at the entry of `BuildTrustChain` and `ResolveMetadata`, before any network request, because both answers are decidable with no I/O and an unauthenticated caller must not be able to spend a full federation walk on an anchor this deployment was never going to accept. `verifyTrustAnchor` judges the statement at the top of the chain and runs where that statement is first available: once in `BuildTrustChain` after `verifyChainLinks`, and once in each of `ResolveMetadata`'s two branches for the last entry. All three invocation points have their own test, because mutation showed that deleting two of them left the suite green.

`verifyTrustAnchor` checks the identifier, then the signature, and **only the second has cryptographic content**. The identifier check requires `iss` and `sub` both to equal the named anchor, which is what makes the last entry an entity configuration rather than a statement about someone else; checking `iss` alone leaves `Sub` unpinned, which a mutant exploits. The signature check applies only when `Configuration.TrustAnchors` holds keys for that anchor, which §4 puts out of band and the library therefore cannot obtain itself.

So with `TrustAnchors` unset, a chain whose last statement is the attacker's own self-signed entity configuration labelled with the anchor's identifier **is accepted**. That is the documented default and `TestResolveMetadata_AForgedAnchorIsRefusedOnlyWhenKeysAreHeldForIt` pins both halves of it — the forgery resolving with no keys held, and being refused with them. Any README or commit text claiming #48's attack is closed in the default configuration is wrong.

`TrustAnchorsConfigured` tests `TrustAnchors != nil`, not its length, so a non-nil map with no entries refuses every anchor rather than falling back to the no-check mode. An anchor list that parsed to nothing is a configuration fault. `TrustAnchorKeys` returns `configured = false` for an anchor absent from the map or mapped to an empty set, and filters the set it returns through `ValidateJWKShape`, so a key the library cannot parse is dropped rather than poisoning the set. A set left empty by that filter is the operator's own fault and answers `server_error`, not `invalid_trust_anchor` — blaming a peer's anchor for a local misconfiguration tells them to stop asking about a perfectly good anchor.

`entity_statement.VerifyAgainstAnyKey` filters each candidate through `model.ValidateJWKShape` before handing it to go-jose, and that filter is load-bearing rather than tidy: go-jose asserts `kty.(string)` unchecked, so a configured key whose `kty` is an object or a number panics without it. `TestVerifyAgainstAnyKey` holds those two cases and a `recover` that fails the test. It is what the configured set goes through, **not** `VerifyAgainstJwks`. Selection by `kid` is wrong here: §10.2 asks only for "a public key of the Trust Anchor", RFC 7517 §4.5 keeps `kid` optional, and an operator holding the anchor's key under a label of their own, or pasting its published JWK Set verbatim, would otherwise have every resolve against that anchor refused with a message blaming the anchor.

Every call site passes the anchor the *caller* named, never the issuer of the chain's own last statement, which is the bypass this guards against. A test fixture for a one-entry chain names the subject as the anchor, because that chain's last statement is the subject's own entity configuration.

Refusals here log at Info, matching every other refusal in the walk, with one exception: a chain that ends in a configured anchor and is not signed by any key held for it logs at Error, because that is either a key rotation this deployment has not picked up or a forgery, and an operator must see it.

### Server configuration drives behavior

`model.ServerConfiguration` (in `model/model.go`) is the central config object. Capabilities are turned on by *presence of config*, not flags:

- `IntermediateConfiguration != nil` → registers `/list`, `/fetch`, `/resolve` (this entity acts as an intermediate/authority).
- `Extensions.ExtendedListing.Enabled` / `Extensions.SubordinateStatus.Enabled` → registers `/extended-list` / `/subordinate-status`.
- `TrustMarkRetriever != nil` → registers the `/trust-mark*` endpoints.

Data access is abstracted behind interfaces so consumers plug in their own storage: `Retriever` (subordinates + their signers), `TrustMarkRetriever`, `TrustMarkIssuerRetriever`, `ExtendedListingRetriever`, `SubordinateStatusRetriever`. Subordinate lookups are cached in-memory (`IntermediateConfiguration.subordinates`, TTL `SubordinateCacheTime`, `FlushCache()` to clear). `SetEntityIdentifier` / `SetHttpClient` on `Server` exist for test-server scenarios and are documented as not-for-production.

Trust chain walking is bounded three ways, all non-zero by default: `MaxTrustChainDepth` (entities on one path), `MaxEntitiesTraversed` (entity configurations fetched for one request, charged in `entity_configuration.Retrieve` on a cache miss) and their product (entities stepped into for one request, charged in `chainUpOne`). Reaching one produces `model.NewLimitReachedError`, which is `ErrInvalidTrustAnchor` and `ErrLimitReached` — never `ErrServerError` or `ErrTemporarilyUnavailable`, because the graph is the caller's choice and a bound is neither a fault nor temporary.

There are two memos, and the distinction is the subtle part. `internal/resolvecache` holds the per-request one, keyed by subject and target, and a verdict reaches it only when `tainted` is false. `walkMemo` is per walk, keyed by subject, target and the depth still available, and holds every verdict together with its taint. A tainted verdict is sound to reuse inside the walk that produced it — a superior that could reach the anchor would have reached it before the walk gave up — but not across walks, which may arrive by a path where the obstacle is absent. Without the per-walk memo a graph of mutually hinting entities re-walks every simple path; `internal/trust_chain/walk_differential_test.go` checks both memos against ground-truth reachability on random graphs, including several walks sharing one cache.

### Metadata policy engine (the most intricate part)

The heart of the library is applying OpenID Federation **metadata policies** down a trust chain. Key pieces:

- **`MetadataPolicyOperator` interface** (`model/model.go`): each policy operator implements `Resolve` (apply to a metadata value), `Merge` (combine two operators of the same kind when policies from different chain levels stack), `ResolutionHierarchy` (defines the fixed order operators are applied within a claim), `CheckForConflict`, `ToSlice`, and `OperatorValue`.
- **Operators**, one file + `_test.go` each: `add.go`, `default.go`, `value.go`, `essential.go`, `one_of.go`, `subset_of.go`, `superset_of.go`. Registered/dispatched by key in `policy_operators.go`.
- **`model/helpers.go`** orchestrates: `MergePolicyOperators` (combine two policy sets for a claim, respecting `ResolutionHierarchy`), `ApplyPolicy` (apply a resolved `MetadataPolicy` to an `EntityStatement`).
- **`internal/trust_chain/trust_chain.go`** is the entry point: `BuildTrustChain` walks from leaf up to trust anchor; `ResolveMetadata` has three return paths and verifies the resolved metadata on all of them. Both pass the top of the chain through `verifyTrustAnchor`, which is the only place a chain's anchor is judged: once in `BuildTrustChain` after the links are verified, and once in each of the two branches `ResolveMetadata` has for the last entry. The multi-entry paths first apply the immediate superior's `metadata` claim, then the accumulated policy where the chain carries one; the single-entry path has neither a superior nor a policy. `CalculateChainExpiration` bounds validity to the earliest-expiring statement.

When adding or changing an operator, keep the three concerns aligned: resolution semantics, merge semantics across chain levels, and `ResolutionHierarchy` ordering. `model/metadata_processing_e2e_test.go` checks policy merging and application against the specification's worked examples. It does not cover the superior's `metadata` claim or resolved-metadata verification; `internal/trust_chain/chain_metadata_test.go` covers the pipeline end to end.

### Metadata entity types

Each federation entity type has its own file implementing `EntityTypeIdentifier` (a `VerifyMetadata() error` validator): `federation_metadata.go`, `openid_relying_party_metadata.go`, `openid_provider_metadata.go`, `oauth_authorization_server_metadata.go`, `oauth_client_metadata.go`, `oauth_resource_metadata.go`, `openid_wallet_provider_metadata.go`, `openid_credential_issuer_metadata.go`, `openid_credential_verifier_metadata.go`. The `Metadata` and `MetadataPolicy` structs in `model/model.go` have one field per type. Adding a new entity type touches nine places, each of which fails silently rather than at compile time, because `EntityTypeIdentifier` only requires `VerifyMetadata`: a new file with the struct, `VerifyMetadata` for claim shape and `VerifyResolvedMetadata` for required claims, an `_ EntityTypeIdentifier = X{}` assertion, the identifier in `builtInEntityTypes`, fields on both `Metadata` and `MetadataPolicy`, a case in each of `Metadata.setEntityType`/`byEntityType` and `MetadataPolicy.setEntityType`/`byEntityType`, a block in each of the four hand-written `UnmarshalJSON`/`MarshalJSON` methods, and `verify`/`verifyResolved` entries in `builtInEntityTypeDefinitions`. A new type's body must be `map[string]any`, because `ReMarshalJsonAsEntityMetadata` decodes into it and a struct body would reintroduce the member-name folding described under JSON handling. Leaving the type out of `builtInEntityTypes` routes it into `Extensions` at parse time; leaving out the `setEntityType` case routes it there during resolution, so the typed field a consumer reads stays nil. The tests that guard this are the per-type loops over `builtInEntityTypes` in `model/entity_type_test.go` and `model/chain_policy_test.go`, so adding the identifier there is what makes the rest fail loudly.

### JSON handling

`EntityStatement`, `Metadata`, and `PolicyOperators` have hand-written `UnmarshalJSON` methods that reject malformed/expired statements at parse time. `EntityStatement` validates its own required claims there; `Metadata` validates claim shape only, because a statement's metadata may be completed by a superior, so the required claims of an entity type are judged at the end of resolution instead. When touching these types, preserve the custom (un)marshalling — the JSON shape is spec-defined and validated on the way in.

Spec-defined member names must be read by their exact name. Go's `encoding/json` matches struct fields with Unicode simple folding, so a struct decode reads `keyſ` or `TRUST_MARK` as `keys` or `trust_mark`, which a conforming parser would not: anywhere a raw map check and a struct decode run over the same object, the two can disagree about what the statement says. `model.ParseJWKSet` is the one way to read a key set: it takes the keys from the exact `keys` member and leaves out an entry that is not a usable JWK, which is what RFC 7517 §5 asks, with `model.ValidateJWKShape` as the per-key check it shares with `entity_statement.SelectKey`. `model.ParseFederationEntityKeys` wraps it for the `jwks` **claim** and adds §3.1.1's rule that every key in that set carry a unique, non-empty, string `kid` — refusing the set, because that rule is a Federation MUST about the whole set and would otherwise be escaped by any entry the lenient parse leaves out. Everything else uses the lenient parse: §3.1.1 states that rule inside the definition of the `jwks` claim, and nowhere else, so a metadata `jwks` and a `trust_mark_owners` entry keep RFC 7517 §4.5's optional `kid`. Refusing a whole Entity Configuration over a `trust_mark_owners` entry would also contradict §3.1.1's instruction to ignore that claim on an Entity that is not a Trust Anchor. `model.VerifyJWKSetClaims` is the matching check for the `jwks`, `jwks_uri` and `signed_jwks_uri` metadata parameters, which §5.2.1 defines as OPTIONAL for every Entity Type except `federation_entity`, where they must not appear at all.

Keys the library publishes are held to more than keys it reads. `entity_configuration.New` refuses to publish a key of the operator's own that is not a usable JWK; `subordinate_statement.New` does not, because that set is a registrant's keys relayed by its authority, and one bad registered key must not take down the statement or anything resolved through it.

## Conventions

- `//todo:` comments mark known incomplete areas across the client, server and model packages (the unimplemented `constraints` claim, trust mark delegation, content-type matching, error-type revisits, and handler duplication). They are intentional signposts, not stray notes.
- Logging is optional and nil-safe: `Configuration.LogInfo`/`LogError` no-op when no `*slog.Logger` is set. Use them rather than a package logger.
- Tests live alongside code as `_test.go`; `model_test/` and `server_test/` hold shared test helpers/fixtures (e.g. `server_test/testserver.go`).
- Comments are not to be added by agents. Code is self-documenting and the comments are not welcome
- Commits, if made, must not be co-authored
- When adding a change, tests MUST be written and MUST pass. Data-driven / table-driven tests are much preferred over single-case where possible.

## Standards

- When making any changes, the latest version of any given specification MUST be pulled first
