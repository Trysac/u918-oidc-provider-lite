# oidc-provider-lite

Embeddable OpenID Connect provider for the authorization code flow with mandatory PKCE, rotating refresh tokens, JWKS key rotation and discovery.

## The Problem

Internal tools and test environments often require a standards-compliant OpenID Connect provider, but deploying large-scale identity servers like Keycloak or Dex is operationally expensive. Conversely, hand-rolled login implementations often omit critical security mechanisms like PKCE, strict redirect URI validation, or refresh token rotation.

## Installation

```bash
go get github.com/Trysac/u918-oidc-provider-lite
```

## Usage

```go
key, _ := rsa.GenerateKey(rand.Reader, 2048)
keys, _ := oidcproviderlite.NewKeySet("k1", key)
provider, _ := oidcproviderlite.New(oidcproviderlite.Config{
	Issuer:        "https://idp.example.test",
	Clients:       []oidcproviderlite.Client{{ID: "app", RedirectURIs: []string{"https://app.example.test/cb"}, Public: true}},
	Authenticator: myAuthenticator,
	Keys:          keys,
})
http.ListenAndServe(":8080", provider)
```

## Public API Summary

`oidc-provider-lite` exposes a single `http.Handler` via `New(Config)`. 

- **Config**: Defines the `Issuer`, static list of `Clients` (with `SecretSHA256` or marked `Public`), `Authenticator` and `Consent` interfaces, and a `KeySet`.
- **Limits**: The provider enforces bounded memory usage using `MaxCodes` (default 10,000) and `MaxTokens` (default 100,000). Exceeding these limits returns `503 Service Unavailable` with `temporarily_unavailable`.
- **Errors**: Errors are returned as JSON `{"error": "code", "error_description": "text"}`. Invalid client secrets or revoked tokens trigger specific `401 Unauthorized` or `400 Bad Request` responses as defined by RFC 6749.

## Why not Keycloak or Dex

Full identity servers require separate storage, complex configurations, and multiple processes. `oidc-provider-lite` is a library, not a service, implementing only the secure subset of OAuth 2.1 and OIDC Core 1.0, delegating UI to your host app.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model.
