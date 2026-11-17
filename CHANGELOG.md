# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added embeddable OpenID Connect 1.0 provider (`Provider`, `Config`, `KeySet`) with mandatory S256 PKCE, rotating refresh tokens with family revocation, RS256 JWKS key rotation, and discovery.
- Initial project structure from the factory utility template.
