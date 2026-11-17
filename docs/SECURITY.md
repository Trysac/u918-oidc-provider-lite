# Security Policy and Threat Model

## Threat Model

### Defended

1. **Authorization Code Interception**: Mandatory `S256` PKCE (RFC 7636). Requests omitting PKCE or using `plain` are rejected.
2. **Open Redirector Attacks**: `client_id` and `redirect_uri` are validated via exact string match on `/authorize`. If validation fails, the provider returns `400 Bad Request` and does not set a `Location` header.
3. **Authorization Code Replay**: Codes are single-use. Replay returns `invalid_grant` and triggers revocation of all tokens derived from the same family.
4. **Refresh Token Theft**: Each refresh grant rotates the token. Reuse of a refresh token revokes the entire token family.
5. **IdP Mix-Up**: All authorization responses include the `iss` parameter (RFC 9207).
6. **Token Leakage**: Secrets, codes, and tokens are stored in memory only as SHA-256 hashes.
7. **Side Channels**: Client secret and PKCE comparisons utilize `crypto/subtle.ConstantTimeCompare`.

### Not Defended

1. **Host Session Security**: The library does not manage the login or consent sessions; CSRF protection and session binding on the host's `Authenticator` and `Consent` implementations are the host's responsibility.
2. **TLS Termination**: The provider assumes secure transport; TLS termination must be handled by the host application.
3. **Key Persistence**: RSA keys are stored in process memory. HSM/KMS-backed storage must be implemented by the host.
4. **Dynamic Registration**: Clients are strictly configured at initialization; dynamic registration is not supported.
