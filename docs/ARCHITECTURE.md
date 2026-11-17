# Architecture

`oidcproviderlite` is structured as a single, zero-external-dependency Go package implementing `http.Handler`.

## Components

- **`Provider` (`oidcproviderlite.go`)**: Routes requests for `/.well-known/openid-configuration`, `/jwks.json`, `/authorize`, `/token`, and `/userinfo`. Maintains bounded in-memory maps of hashed authorization codes, access tokens, and refresh tokens protected by a mutex.
- **`KeySet` (`keys.go`)**: Validates 2048–4096 bit RSA private keys, signs ID tokens using RS256 (`crypto/rsa` + `crypto/sha256`), and supports zero-downtime key rotation (`Rotate`), publishing the active and immediately preceding public keys on `/jwks.json`.
- **`Error` (`errors.go`)**: Unified machine-readable error type used for both Go API errors and RFC 6749 JSON error responses.

## Key Design Decisions

1. **Hashed State Only**: Raw authorization codes, access tokens, and refresh tokens (32 random bytes, base64url-encoded) are returned to the client once and stored only as `[32]byte` SHA-256 digests.
2. **Token Family Tracking**: Every authorization code creates a random `familyID` inherited by all access and refresh tokens derived from it. Replaying a used authorization code or a rotated refresh token immediately deletes all tokens sharing that `familyID`.
3. **Bounded Memory**: Pending codes and active tokens are capped by `MaxCodes` (default 10,000) and `MaxTokens` (default 100,000). When a cap is reached, expired/used records are purged first; if still full, the provider returns `temporarily_unavailable`.
