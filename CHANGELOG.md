# Changelog

## [0.2.0](https://github.com/BP602/ntfy-hermes-jev-bridge/compare/v0.1.0...v0.2.0) (2026-09-25)


### Features

* accept validated JSON configuration from environment ([98c05be](https://github.com/BP602/ntfy-hermes-jev-bridge/commit/98c05bebd7e0d5a4a15a84c4deebff78aa2aa4fc))
* publish GHCR images with release-please and structured logs ([69fcc37](https://github.com/BP602/ntfy-hermes-jev-bridge/commit/69fcc37669edfa0afdc2d75a0abe62cef560929b))
* route notification sources through Hermes profiles ([f7fe536](https://github.com/BP602/ntfy-hermes-jev-bridge/commit/f7fe536d309b1b88a5920ee1a394f1f7c372bffe))


### Bug Fixes

* harden bridge validation and reliability ([03acda7](https://github.com/BP602/ntfy-hermes-jev-bridge/commit/03acda786266b67f92a0ef7f58206a6b100414a6))
* publish latest image on every main build ([ec6894a](https://github.com/BP602/ntfy-hermes-jev-bridge/commit/ec6894a130ec8ce5bf6588f9926eeb5980b7af1e))
* require actionable Hermes review replies ([ab66079](https://github.com/BP602/ntfy-hermes-jev-bridge/commit/ab66079e1a5f601d354a7c623713b3066972bd58))
* suppress opted-in price-only watch diffs ([35f8729](https://github.com/BP602/ntfy-hermes-jev-bridge/commit/35f8729a93d4707ae4f34837a6f573219c6ba697))
* update uv lock version in release PR ([73e5020](https://github.com/BP602/ntfy-hermes-jev-bridge/commit/73e502062ea9d5444d3f9efe19d687ff96ae764f))

## 0.1.0 (unreleased baseline)

- Initial local-first ntfy → Jev → Hermes bridge with SQLite inbox, guarded rollout, signed outbox, and scheduled digests.

Release Please updates this file when a Conventional Commit release PR is merged.
