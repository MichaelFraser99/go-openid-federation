# Copilot instructions

A Go library implementing the [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html) specification. It is a library, not a runnable service.

## Hard rules

- **Tests are mandatory.** Every change must add or update tests, and they must pass. Prefer table-driven tests over single-case.
- **Do not add code comments.** The code is self-documenting; comments are not welcome. Leave existing `//todo:` markers alone — they are intentional signposts.
- **Do not co-author commits.** No `Co-Authored-By` trailers.
- **Spec-first.** Before changing behaviour tied to a specification, pull the latest version of that spec and align to it.
- **Do not hand-roll crypto.** All JWS/JWK/JWT signing and verification goes through `github.com/MichaelFraser99/go-jose`.
- **Preserve custom (un)marshalling.** `EntityStatement`, `Metadata`, and `PolicyOperators` have hand-written `UnmarshalJSON` that validates spec-defined shapes and rejects malformed/expired statements at parse time. Keep that validation intact.

## Verify before opening a PR

Do not open a PR until all of these pass locally:

- Go 1.25.x (see `go.mod`).
- Tests: `go test ./...` — the full suite, not just the package you touched.
- Lint: `golangci-lint run` — match the version pinned in `.github/workflows/golangci-lint.yml`.
- Reproduce the full gate: `pre-commit run --all-files` (end-of-file/whitespace fixers, yaml check, `golangci-lint-full`).

## Review and quality bar

This is a security library: entity statements and trust marks are attacker-controllable signed JWTs, and trust-chain resolution walks untrusted remote endpoints. Hold every change to the same bar a careful human reviewer would.

- **Self-review the full diff** before opening the PR. Read it as a reviewer, not the author. Explain in the PR description what changed, why, and how it was verified.
- **Never weaken existing validation.** The custom `UnmarshalJSON` guards and spec-shape checks are security controls — preserve them, and prefer tightening over loosening.
- **Think adversarially about untrusted input:** malformed/expired/oversized statements, cyclic or hostile trust chains, chain amplification and unbounded traversal (respect `MaxTrustChainDepth` and dead-end tracking), unexpected JSON shapes. Add tests for the abuse case, not just the happy path.
- **Confirm spec compliance.** Cite the relevant clause of the current OpenID Federation spec in the PR when behaviour is spec-driven.
- **Cover behaviour with table-driven tests**, including error and boundary cases. A change without a failing-then-passing test is incomplete.
- **Keep the change scoped** to the issue. Flag anything out-of-scope you notice rather than silently expanding the diff.
- If you are not confident a change is correct and safe, say so in the PR rather than presenting it as done.

## Architecture

Four layered packages:

- **`model/`** — all exported types, JWT/entity-statement structures, and the metadata-policy engine. Most logic lives here; depends on nothing else in the repo.
- **`internal/`** — federation protocol mechanics (`entity_configuration`, `subordinate_statement`, `entity_statement`, `trust_chain`, `trust_marks`): the actual HTTP + signature verification.
- **`server/`** — HTTP handlers for federation endpoints, wired in `server/server.go`. Capabilities turn on by *presence of config* on `model.ServerConfiguration`, not boolean flags.
- **`client/`** — thin wrapper exposing `BuildTrustChain` and `ResolveMetadata`.

### Metadata policy engine (most intricate part)

Policy operators live one-per-file in `model/` (`add.go`, `default.go`, `value.go`, `essential.go`, `one_of.go`, `subset_of.go`, `superset_of.go`), dispatched in `policy_operators.go`. When changing an operator, keep the three concerns aligned: `Resolve` semantics, `Merge` across chain levels, and `ResolutionHierarchy` ordering. `model/metadata_processing_e2e_test.go` is the integration check.

### Adding a metadata entity type

New file with the struct + `VerifyMetadata`, an `_ EntityTypeIdentifier = X{}` assertion, and matching fields on both `Metadata` and `MetadataPolicy` in `model/model.go`.
