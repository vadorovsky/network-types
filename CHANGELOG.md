# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/vadorovsky/network-types/compare/v0.1.0...v0.1.1) - 2026-02-05

### Added

- Add IGMPv1 and IGMPv3 headers
- add `Ipv4::options_len` ([#75](https://github.com/vadorovsky/network-types/pull/75))
- Add support IGMPv2

### Fixed

- use the correct size for the unused field in IGMPv3MembershipReportHdr struct ([#81](https://github.com/vadorovsky/network-types/pull/81))

### Other

- Derive Hash trait for IpProto ([#82](https://github.com/vadorovsky/network-types/pull/82))
- add `feature-powerset`
- unbreak
- Extract ICMPv6 redirect payload
- rename `{Hdr,Data}Un`
- add nightly CI
- Remove excessive qualification
- appease deprecation warnings
- remove useless transmutes
- Remove integer-to-pointer cast
- Remove dependency on memoffset
- add miri
- use taiki-e/setup-cross-toolchain-action
- `fail-fast: false`
- remove `--verbose`
- Bump edition to 2024
- Derive Clone and Copy for Icmp enum ([#72](https://github.com/vadorovsky/network-types/pull/72))

## [0.0.8](https://github.com/vadorovsky/network-types/compare/v0.0.7...v0.0.8) - 2025-04-07

### Added

- Add MacHdr ([#20](https://github.com/vadorovsky/network-types/pull/20))

### Other

- *(ipv6)* store addresses and length as byte-arrays
- *(udp)* store fields as byte-arrays
- Embed readme in doc
- *(ipv4)* Use byte-arrays to store addresses and u16s
- Use `src_addr` methods from IP header structs
- Add mac to lib.rs

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
