# Project Record

## Objective

Provide an embeddable, secure-by-default OpenID Connect and OAuth 2.1 provider library for Go applications, specifically implementing the authorization code flow with PKCE, rotating refresh tokens, and JWKS key rotation.

## Scope

- **In scope**: Implementation of OIDC Discovery 1.0, RFC 7636 (PKCE), RFC 6749 (Authorization Code Flow), RFC 9207 (Mix-up protection), and OAuth 2.0 Security BCP (Refresh token rotation).
- **Out of scope**: Implicit/Hybrid flows, client credentials flow, dynamic client registration, token introspection/revocation endpoints, logout functionality, request objects, and token encryption.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort Metrics

| Metric | Value |
|---|---|
| Tokens (input / output) | 11886723 / 53410 |
| Hours (human) | pending measurement |
| Cost (USD) | 2.9412 |

## Factory run u918 (measured from API usage)

| Date (UTC) | Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|---|
| 2026-11-10 | generation | google/gemini-4-argon | yes | 5976 | 31292 | 0 | 0 | 0.6497 |
| 2026-11-10 | fix-1 | google/gemini-3.8-flash | no | 197573 | 800 | 0 | 164911 | 0.1635 |
| 2026-11-10 | fix-2 | google/gemini-3.8-flash | no | 112628 | 248 | 0 | 151787 | 0.0968 |
| 2026-11-10 | fix-3 | google/gemini-3.8-flash | no | 101841 | 3158 | 0 | 269184 | 0.1084 |
| 2026-11-10 | fix-4 | google/gemini-3.8-flash | no | 144197 | 505 | 0 | 399938 | 0.1400 |
| 2026-11-17 | fix-1 | google/gemini-3.8-flash | no | 256042 | 1214 | 0 | 1004250 | 0.2719 |
| 2026-11-17 | fix-2 | google/gemini-3.8-flash | no | 252643 | 1246 | 0 | 1966467 | 0.3416 |
| 2026-11-17 | fix-3 | google/gemini-3.8-flash | no | 475581 | 10683 | 0 | 4281386 | 0.7178 |
| 2026-11-17 | fix-4 | google/gemini-3.8-flash | no | 74671 | 480 | 0 | 226917 | 0.0748 |
| 2026-11-17 | fix-1 | google/gemini-3.8-flash | no | 37713 | 209 | 0 | 73063 | 0.0345 |
| 2026-11-17 | audit | google/gemini-3.8-flash | no | 204442 | 1387 | 0 | 1202235 | 0.2487 |
| 2026-11-17 | threat-model | google/gemini-3.8-flash | no | 99730 | 548 | 0 | 177556 | 0.0902 |
| 2026-11-17 | docs | google/gemini-3.1-flash-lite | no | 1991 | 1640 | 0 | 4001 | 0.0031 |

Total: $2.9412. Prices: vertex line, as measured by its adapter. Providers serve the current version of each model id, so the date tells which version answered; versions, launch stages and price sources per line are in the factory's model register (docs/MODELS.md).
