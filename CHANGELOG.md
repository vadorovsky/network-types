# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.6](https://github.com/vadorovsky/network-types/compare/v0.0.5...v0.0.6) - 2024-03-23

### Fixed
- follow rename of aya-bpf to aya-ebpf ([#15](https://github.com/vadorovsky/network-types/pull/15))

### Other
- use new core::net instead of std::net, dropping the std feature ([#17](https://github.com/vadorovsky/network-types/pull/17))

## [0.0.5](https://github.com/vadorovsky/network-types/compare/v0.0.4...v0.0.5) - 2023-11-30

### Added
- add std feature flag that exposes std types ([#7](https://github.com/vadorovsky/network-types/pull/7))

### Fixed
- Convert addresses from/to big-endian ([#8](https://github.com/vadorovsky/network-types/pull/8))

### Other
- Add release-plz action
- Add serde support to structs
