# Testing

## Test Oracles

Tests in `oidcproviderlite_test.go` use `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` as independent client oracles interacting with an `httptest.Server` running the `*oidcproviderlite.Provider`.

## Test Coverage

- **Discovery**: Validates metadata fields in `/.well-known/openid-configuration`.
- **PKCE**: Validates RFC 7636 Appendix B test vectors; negative tests for missing/invalid challenges.
- **Authorization**: Verifies `redirect_uri` exact matching and error handling (no `Location` header on bad requests).
- **Token Exchange**: Validates `authorization_code` exchange, ID token claim generation (nonce, sub, aud, at_hash), and RS256 signature verification across JWKS rotations.
- **Lifecycle**: Tests token revocation on authorization code reuse, refresh token rotation, and family revocation.
- **Rate/Memory Limits**: Verifies the `MaxCodes` limit returns `temporarily_unavailable`.

Run the test suite with:

```bash
go test -race -cover .
```
