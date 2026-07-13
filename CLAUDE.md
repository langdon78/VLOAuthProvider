# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
swift build
swift test
swift test --filter OAuthProviderTests
swift test --filter testHMACSHA1SignatureGeneration   # single test
swift build -c release
swift package clean
swift package update
```

## What this is

An RFC 5849-compliant OAuth 1.0 **client-side** request-signing library. It signs outgoing `URLRequest`s with OAuth 1.0 credentials/signatures — it is not an OAuth server, and does not manage token storage, refresh, or a full authorization flow end-to-end (that orchestration lives one layer up, in `VLOAuthFlowCoordinator`).

## Architecture

Source is split into `Public/` (the API surface) and `Private/` (encryption implementations, encoding helpers) under `Sources/VLOAuthProvider/`.

- **`AuthenticationProvider`** (protocol, `Public/AuthenticationProvider.swift`) — the abstraction: `createSignedRequest(from:with:as:) async throws -> URLRequest`. Anything conforming to this can be swapped in as the signer.
- **`OAuthProvider`** (`Public/OAuthProvider.swift`) — the concrete, and only, implementation of `AuthenticationProvider`. Signs an arbitrary `URLRequest` — **it is not restricted to any particular host**; the caller supplies the full request. (Any hardcoded-host restriction you see elsewhere in the `VL*` stack, e.g. in `VLDiscogsClient`, is a decision made at that higher layer, not a limitation of this package.)
- **`OAuthParameters`** (`Public/Models/OAuthParameters.swift`) — holds consumer/token credentials, signature method, nonce/timestamp (auto-generated if omitted), callback, and verifier. Uses `OrderedDictionary` (swift-collections) for deterministic parameter ordering, required for correct signature base-string construction per RFC 3986/5849.
- **`TemporaryCredentials`** / **`TokenCredentials`** (`Public/Models/`) — plain structs representing the request-token and access-token pairs from OAuth 1.0's three-legged flow (RFC 5849 §1.1). These are just data holders the caller threads through the flow manually (see below) — there is no built-in flow orchestrator in this package.
- **Encryption handlers** (`Private/Encryption/`) — `HMACEncryptionHandler` (HMAC-SHA1, plus MD5/SHA256/SHA512 support), `RSAEncryptionHandler` (RSA-SHA1 via `Security`), `PlaintextEncryptionHandler`. All conform to `EncryptionHandler` and are selected via `OAuthSignatureMethod` on `OAuthParameters`.

### Three-legged flow is manual, not automated

There is no `OAuthServer`/server-side implementation anywhere in this package, despite what the README's feature checklist claims ("Server Implementation — Complete OAuth 1.0 server-side support") — that line does not correspond to any code here; treat it as stale. What actually exists is three separate `createSignedRequest` calls the caller makes explicitly, one per leg (request temporary credentials → direct user to the authorize URL → exchange verifier for token credentials) — see the README's "OAuth 1.0 Three-Legged Flow" section for the exact call sequence. `VLOAuthFlowCoordinator` is what actually orchestrates this sequence for consumers of this package; don't expect this package to drive the flow itself.

### `.formData` transmission crashes — do not use it

`ParameterTransmissionType.formData` triggers `fatalError("Form data transmission is not yet supported")` in `OAuthProvider.createSignedRequest` (`Public/OAuthProvider.swift`) — **not** a thrown error, an unrecoverable crash. Only `.header` and `.queryString` are safe to use. The type's own doc comments describe `.formData` as merely "not yet implemented," which understates the actual risk — a caller that reaches this path takes the whole process down, not just that request.

## Testing

Swift Testing (`@Test`), not XCTest. Includes RFC 2202 HMAC test vectors and RFC-compliance checks — when changing signature/encoding logic, run the full suite, not just a targeted filter, since these are exactly the kind of regressions test vectors exist to catch.
