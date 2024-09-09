# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.7](https://github.com/vadorovsky/network-types/compare/v0.0.6...v0.0.7) - 2024-09-09

### Other

- Add ARP header ([#23](https://github.com/vadorovsky/network-types/pull/23))

## [0.0.6](https://github.com/vadorovsky/network-types/compare/v0.0.5...v0.0.6) - 2024-06-04

### Fixed
- fix serializing UDP header struct and add test
- Drop usage of `u128` in `Ipv6Hdr`
- follow rename of aya-bpf to aya-ebpf ([#15](https://github.com/vadorovsky/network-types/pull/15))

### Other
- Handle IPv6 in the code example
- fix cfg_attr test ([#13](https://github.com/vadorovsky/network-types/pull/13))
- use new core::net instead of std::net, dropping the std feature ([#17](https://github.com/vadorovsky/network-types/pull/17))

## [0.0.5](https://github.com/vadorovsky/network-types/compare/v0.0.4...v0.0.5) - 2023-11-30

### Added
- add std feature flag that exposes std types ([#7](https://github.com/vadorovsky/network-types/pull/7))

### Fixed
- Convert addresses from/to big-endian ([#8](https://github.com/vadorovsky/network-types/pull/8))

### Other
- Add release-plz action
- Add serde support to structs
