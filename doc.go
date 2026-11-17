// Package oidcproviderlite provides an embeddable OpenID Connect 1.0 and OAuth 2.1
// authorization code flow provider as a standard [net/http.Handler].
//
// It implements OpenID Connect Discovery 1.0, RFC 7517 JSON Web Key Sets (JWKS)
// with zero-downtime key rotation, mandatory S256 PKCE (RFC 7636), RFC 9207
// authorization response issuer parameters, single-use authorization codes with
// replay revocation, and rotating refresh tokens with token family revocation
// (RFC 9700).
//
// # Threat Model
//
// Defended by oidcproviderlite:
//   - Authorization code interception: PKCE with S256 is mandatory on every
//     authorization request; "plain" or missing challenges are rejected.
//   - Open redirector attacks: client_id and redirect_uri are verified by exact
//     string equality before any redirect occurs. Mismatches return a 400 plain
//     error page without a Location header (RFC 6749 Section 4.1.2.1).
//   - Authorization code replay: codes are single-use. A second presentation of
//     a used code is rejected and immediately revokes all tokens issued from it.
//   - Refresh token theft: every refresh grant rotates the refresh token.
//     Replaying a rotated refresh token revokes the entire token family.
//   - Mix-up attacks: authorization responses include the "iss" parameter
//     (RFC 9207) and Discovery advertises authorization_response_iss_parameter_supported.
//   - Token and code leakage at rest: authorization codes, access tokens, and
//     refresh tokens are 32-byte cryptographically random values stored only as
//     SHA-256 hashes in memory.
//   - Client secret timing attacks: client secrets are held as SHA-256 digests
//     and compared in constant time via crypto/subtle.ConstantTimeCompare.
//
// Responsibilities of the host application (not defended by this package):
//   - CSRF protection, session fixation defense, and authentication security on
//     the login and consent interfaces implemented by the host.
//   - TLS termination (HTTPS is required in production by OpenID Connect).
//   - Persistent private key protection and KMS/HSM storage.
//   - Dynamic client registration and rate limiting at the edge.
package oidcproviderlite
