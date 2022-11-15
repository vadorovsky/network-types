//! Rust structs representing network-related types (on Layer 2, 3 and 4) in
//! Linux.
//!
//! The crate is [no_std](https://docs.rust-embedded.org/book/intro/no-std.html)
//! and the structures are fully compatible with the ones provided by the Linux
//! kernel, which makes it a great fit for [eBPF](https://ebpf.io/) programs
//! written with [Aya](https://aya-rs.dev/).

#![no_std]

pub mod bitfield;
pub mod l2;
pub mod l3;
pub mod l4;
pub mod macros;
