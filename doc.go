// Package oidcproviderlite is a small, dependency-free Go library: Embeddable OpenID Connect provider for the authorization code flow with mandatory PKCE, rotating refresh tokens, JWKS key rotation and discovery
//
// The public API is every exported identifier of this root package. Functions are pure: they do
// no I/O, keep no global mutable state and report invalid input through returned errors.
package oidcproviderlite
