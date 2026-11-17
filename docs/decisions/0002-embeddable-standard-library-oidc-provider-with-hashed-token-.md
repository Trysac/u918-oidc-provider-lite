# Embeddable Standard-Library OIDC Provider with Hashed Token Family State

Status: accepted (generated, pending human review)

## Context

Internal applications and integration test suites need a standards-compliant OpenID Connect 1.0 provider without operating an external identity server or pulling heavy third-party runtime dependencies.

## Decision

Implement the OAuth 2.1 authorization code flow and OpenID Connect Core 1.0 endpoints as a zero-runtime-dependency Go http.Handler that delegates user authentication and consent to two host interfaces, signs RS256 JWS tokens using crypto/rsa, stores only SHA-256 digests of codes and tokens in bounded maps, and tracks token families for automatic replay revocation.

## Consequences

The library has zero runtime dependencies outside the Go standard library, prevents plain-text credential leakage from memory or events, and passes independent verification with coreos/go-oidc and golang.org/x/oauth2. Implicit/hybrid flows and dynamic client registration are intentionally omitted.
