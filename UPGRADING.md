# Upgrading go-openid-federation

Each change you may have to act on is marked **Breaking change** in the README section it concerns. The lists below link to those sections.

## From v0.11.1

- [Errors](README.md#errors): `/resolve` builds this server's own statements in process, and a fault in them answers 5xx.
- [Trust chains](README.md#trust-chains): a walk logs once for each entity, and several Info messages are replaced by one summary line.
- [Retriever interfaces](README.md#retriever-interfaces): a temporary outage in `GetSubordinateSigners` or `ListTrustMarkIssuers` answers 503, and `/extended-list` no longer drops a statement silently over it.
- [Query parameters](README.md#query-parameters): one subordinate's unusable record or signer no longer takes down `/extended-list` or `/.well-known/openid-federation`.
- [ServerConfiguration](README.md#serverconfiguration): a redirect from a peer to a URL that does not use `https` is refused, whatever client you supply.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): resolved `openid_credential_issuer` metadata must name the subject as its `credential_issuer`.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): a `nil` member below a metadata parameter is written as `null`, not left out.
- [An intermediate or trust anchor](README.md#an-intermediate-or-trust-anchor): a leaf no longer publishes a `federation_fetch_endpoint` or `federation_list_endpoint` typed into its metadata.
- [Extensions](README.md#extensions): a `SubordinateStatus.ResponseLifetime` under one second answers 500 instead of signing an expired response.
- [Errors](README.md#errors): a transport error that wraps `model.ErrServerError` for one peer no longer ends a trust chain walk that has another route.
- [Retriever interfaces](README.md#retriever-interfaces): a retriever error that wraps `model.ErrServerError` or `model.ErrTemporarilyUnavailable` answers with the endpoint's fixed description, not its own text.
- [Errors](README.md#errors): a failure to fetch the subject's own entity configuration answers with the class your `HttpClient`'s transport error carries, not 404 `not_found`.
- [Retriever interfaces](README.md#retriever-interfaces): a `SubordinateCacheTime` under one second caches nothing.
- [Trust chains](README.md#trust-chains): a subordinate statement that cannot be fetched no longer ends a resolve that another route can complete.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): an `Extensions` entry under a built-in entity type is refused when written.
- [Query parameters](README.md#query-parameters): `/list` and `/extended-list` leave out a store value that is not an entity identifier, and serve a repeated one once.
- [Query parameters](README.md#query-parameters): `/extended-list` removes a `subordinate_statement` from your retriever when `claims` is present without it, or when this server cannot issue one.
- [Query parameters](README.md#query-parameters): `/trust-mark` answers 500 for a value from `IssueTrustMark` that is not a trust mark for the requested subject and type.
- [Limits](README.md#limits): a trust mark of a type the trust anchor does not trust no longer counts against `MaxTrustMarks`, and no longer writes a log line of its own. The summary line counts them as `untrusted_types`.
- [Query parameters](README.md#query-parameters): `/trust-mark-status` answers 404 for a trust mark whose `iss` is not this server, without asking your retriever.
- [Anchoring a chain a caller supplies](README.md#anchoring-a-chain-a-caller-supplies): an entity configuration or subordinate statement that carries a `trust_chain` or `peer_trust_chain` header is refused.
- [Metadata policy](README.md#metadata-policy): an entity type policy or a parameter policy whose value is `null` is refused.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): resolved `oauth_authorization_server` metadata must hold the endpoints and signing algorithm lists that RFC 8414 section 2 makes conditional.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): `openid_credential_verifier_provider` is a built-in entity type with its own field, and its resolved metadata must hold `jwks`.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): `openid_credential_verifier` metadata must follow Wallet Architectures draft 06 section 6.4.1.
- [Retriever interfaces](README.md#retriever-interfaces): `AddSubordinate`, `GetSubordinate` and `GetSubordinates` copy the configuration, so a write to it no longer changes what `/fetch` signs.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): an entity identifier must be an RFC 3986 URI, so a raw space, a raw non-ASCII character or a port above 65535 is refused.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): a credential issuer's `authorization_servers` must be a non-empty array of entity identifiers.
- [Metadata policy](README.md#metadata-policy): a merged policy whose `add` and `superset_of` operators hold more operands in total than `MaxStatementValues` is refused.
- [Metadata policy](README.md#metadata-policy): a `metadata_policy` that repeats a member name at any of its three levels is refused.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): a statement, trust mark or delegation that repeats a name in its header or its claims is refused.
- [Metadata policy](README.md#metadata-policy): `SubordinateConfiguration` has new `Metadata` and `Constraints` fields, so a literal that sets its fields by position no longer compiles.
- [ServerConfiguration](README.md#serverconfiguration): `server.NewServer` returns an error, and refuses a configuration that would fail every request.
- [Metadata policy](README.md#metadata-policy): a `value` operator replaces a parameter of another JSON type, so a resolved parameter can have a type the subject did not publish. Check the types in a custom entity type's `VerifyResolvedMetadata`, and in any `Extensions` type before you use it.
- [Metadata policy](README.md#metadata-policy): `value` and `default` assign their operand as written, repeats included, and refuse to merge with an operand that differs only by a repeat. `add` keeps a repeat the subject published, and initialises an absent parameter with its operand as written.
- [Query parameters](README.md#query-parameters): `/resolve` with `entity_type` judges only the named types, so a broken type that the request does not name no longer refuses the resolution.
- [Metadata policy](README.md#metadata-policy): an element of any operand on `scope` is split into scope values, so `subset_of: ["openid profile"]` permits both, and a `superset_of` or `one_of` element that holds whitespace is no longer refused when the policy is processed. A `one_of` on a `scope` that is present is still a policy error.
- [Metadata policy](README.md#metadata-policy): a resolved `scope` that holds no scope value is refused as `invalid_metadata` for `openid_relying_party` and `oauth_client`.
- [Anchoring a chain a caller supplies](README.md#anchoring-a-chain-a-caller-supplies): a refused entry in a chain you pass to `Client.ResolveMetadata` carries `invalid_metadata` only, and no longer also `ErrInvalidTrustChain`. Its description is fixed text; the parser's reason is the cause, which `errors.Unwrap` returns.
- [Errors](README.md#errors): `Client.BuildTrustChain` and `Client.ResolveMetadata` refuse a malformed leaf, trust anchor or subject with `ErrInvalidRequest`, where they returned an error that matched no sentinel.
- [Errors](README.md#errors): an error that carries two classes answers in the order of the response table, whether or not a transport path reclassified it, and `ErrLimitReached` survives reclassification.
- [Errors](README.md#errors): `page_not_found` from your `HttpClient`'s transport is an unclassified error, so `/resolve` no longer answers 404 `page_not_found`.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): a metadata value that is a `json.Marshaler` or a `[]byte` is written as `encoding/json` writes it, not as an array of numbers, so a published statement can change.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): a trust mark typed `application/trust-mark+jwt` is accepted, and every `typ` header is compared with ASCII-only case folding.
- [Query parameters](README.md#query-parameters): on `/extended-list` with `claims=subordinate_statement`, a store's 4xx answer for one subordinate lists that subordinate without its statement, where the whole page answered 500.
- [Metadata policy](README.md#metadata-policy): a `subset_of` that leaves no value resolves to `[]`, not `null`.
- [Metadata policy](README.md#metadata-policy): a policy this server issues that puts `one_of` on `scope` is logged at Error on each issuance, and still issued.
- [ServerConfiguration](README.md#serverconfiguration): `Server.AddAuthorityHint` returns an `error`, and refuses a hint that is not an entity identifier or that names this server itself.
- [Retriever interfaces](README.md#retriever-interfaces): a `ListTrustMarkIssuers` record with a type that is not valid UTF-8 or an issuer that is not an entity identifier is left out of `trust_mark_issuers`, where it took down `/.well-known/openid-federation`.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): a private key member inside a `jwks` value of any shape, such as a bare JWK or an array, is found. `/.well-known` and `/fetch` refuse the statement, and `/extended-list` removes the key.
- [Query parameters](README.md#query-parameters): `/trust-mark-status` answers 404 for a trust mark with no `iss`, and `/subordinate-status` answers 400 `invalid_request` for this server's own identifier.
- [Retriever interfaces](README.md#retriever-interfaces): the subordinate store holds values in JSON shape, so `GetSubordinate` returns a `josemodel.Jwks` or other Go type you stored as `map[string]any` and `[]any`.
- [How operand values are compared](README.md#how-operand-values-are-compared): an operand built in Go is held in JSON shape, so `OperatorValue` returns `map[string]any` and `[]any`, not the type you passed.
- [ServerConfiguration](README.md#serverconfiguration): `NewServer` refuses a signer whose key cannot sign with its `Algorithm`, an `AuthorityHints` entry that names this server, and a private key member in the metadata or trust mark owners it would publish. It accepts a metadata `jwks` held as a `josemodel.Jwks` again.
- [Metadata policy](README.md#metadata-policy): `subset_of` and `one_of` operands count towards the merged-policy bound, and one statement's `scope` operands may hold at most `MaxStatementValues` scope values.
- [Metadata policy](README.md#metadata-policy): an array element of a `value` or `default` operand on `scope` is split into scope values, as for the other operators.
- [Metadata policy](README.md#metadata-policy): policies merge from the trust anchor down, as section 6.1.4.1 requires, so the values of a merged `add` resolve in a different order.

## From v0.11.0-rc.2

> **Breaking change.** v0.11.0 requires `go-jose` v0.11.0, which requires Go 1.27. Minimal version selection lifts every consumer to v0.11.0, so read its "Upgrading from 0.10.x" notes if your own code imports `go-jose`. The changes that reach a consumer of this library:
>
> - **`kid` values.** `jwk.PublicJwk` now derives a `kid` as the key's RFC 7638 thumbprint. If you compute your signing key's `KeyID` that way at startup, it changes on upgrade, and every superior that registered your old `kid` must be given the new one, or your entity configuration no longer verifies against its subordinate statement.
> - **`josemodel.Jwks`.** It appears in `SubordinateConfiguration.JWKs`, `TrustMarkOwner.JWKs` and `Configuration.TrustAnchors`. An empty set now serialises as `{"keys":[]}` rather than `{"keys":null}`, decoding JSON into one refuses a missing or `null` `keys`, and `RetrieveByKeyID` returns every key carrying the `kid`.
> - **Stricter keys from peers.** An EC key whose `x` or `y` is not the full size of its curve, and an RSA key whose `n` or `e` carries a leading zero octet, are now refused, as RFC 7518 sections 6.2.1.2 and 2 require. A peer publishing one can no longer be verified.
> - **Expiry is exclusive.** A statement, trust mark or delegation has expired once the current time reaches its `exp` plus `model.ClockSkewLeeway`, as RFC 7519 section 4.1.4 requires ("MUST be before"). Earlier releases accepted it for one more second.

- [Installation](README.md#installation): this release requires `go-jose` v0.11.0 and Go 1.27.
- [Query parameters](README.md#query-parameters): a `sub` that spells the server's own identifier differently is refused.
- [Limits](README.md#limits): `MaxRequestPeerBytes`, `MaxPeerResponseTime`, `MaxResolveTime`, `MaxTrustMarks`, `MaxStatementValues` and `MaxAuthorityHints` are new, and `Server.Configure` no longer installs `http.DefaultClient`.
- [Retriever interfaces](README.md#retriever-interfaces): a subordinate added with `AddSubordinate` and no `Retriever` no longer expires.
- [Per-subordinate signing keys](README.md#per-subordinate-signing-keys): a signer whose `KeyID` is already published for a different key is left out, and `/.well-known/openid-federation` no longer answers 500.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): more statements are refused, `PolicyOperators` has an `Unrecognised` field, and `Metadata.VerifyResolved` applies the shape rules and takes the subject's identifier.
- [How operand values are compared](README.md#how-operand-values-are-compared): `essential` takes a boolean only, operator combinations are checked across levels, and the four list operators are held to their element types.
- [Trust chains](README.md#trust-chains): the fetch endpoint is requested as published, and trust mark refusals are logged at Info.
- [Constraints](README.md#constraints): `EntityStatement.Constraints` is typed, and constraints are enforced.
- [Anchoring a chain a caller supplies](README.md#anchoring-a-chain-a-caller-supplies): with no `TrustAnchors`, `Client.ResolveMetadata` fetches the anchor's entity configuration itself.
- [Errors](README.md#errors): signer errors are classified, and `/list` keeps every class a retriever gives.

## From v0.10.0

Every change listed under [From v0.11.0-rc.2](#from-v0110-rc2) applies, and so do these:

- [Limits](README.md#limits): `MaxTrustChainDepth` defaults to 10, and `MaxEntitiesTraversed` and `MaxTrustMarkIssuers` are new.
- [Retriever interfaces](README.md#retriever-interfaces): a bare `error` for an unknown subject answers 500.
- [Entity statements and metadata](README.md#entity-statements-and-metadata): three `EntityStatement` fields changed type or were removed, and the required-claim checks moved out of `VerifyMetadata`.
- [Custom entity types](README.md#custom-entity-types): a subject whose entity type is incomplete after resolution is refused.
- [How operand values are compared](README.md#how-operand-values-are-compared): `ProcessAndExtractPolicy` skips self-issued statements, and the superior's `metadata` claim is applied.
- [Anchoring a chain a caller supplies](README.md#anchoring-a-chain-a-caller-supplies): a chain of one entry resolves only when it is the trust anchor's own entity configuration, `Client.ResolveMetadata` takes a `trustAnchor` argument and never returns nil metadata, and `TrustAnchors` restricts which anchors `/resolve` serves.
