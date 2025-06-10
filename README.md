# network-types

Rust structs representing network protocol headers (on Layer 2, 3 and 4).

The crate is [no_std](https://docs.rust-embedded.org/book/intro/no-std.html),
which makes it a great fit for [eBPF](https://ebpf.io/) programs written
with [Aya](https://aya-rs.dev/).

## Examples

An example of an [XDP program](https://aya-rs.dev/book/start/) logging
information about addresses and ports for incoming packets:

```rust
use core::mem;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source_addr = unsafe { (*ipv4hdr).src_addr() };

            let source_port = match unsafe { (*ipv4hdr).proto } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    u16::from_be_bytes(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    unsafe { (*udphdr).src_port() }
                }
                _ => return Ok(xdp_action::XDP_PASS),
            };

            info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source_addr = unsafe { (*ipv6hdr).src_addr() };

            let source_port = match unsafe { (*ipv6hdr).next_hdr } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN  + Ipv6Hdr::LEN) }?;
                    u16::from_be_bytes(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
                    unsafe { (*udphdr).src_port() }
                }
                _ => return Ok(xdp_action::XDP_PASS),
            };

            info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);
        }
        _ => {},
    }

    Ok(xdp_action::XDP_PASS)
}
```

## Naming conventions

When naming stucts and fields, we are trying to stick to the following
principles:

- Use `CamelCase`, even for names which normally would be all uppercase
  (e.g. `Icmp` instead of `ICMP`). This is the convention used by the
  [std::net](https://doc.rust-lang.org/std/net/index.html) module.
- Where field names (specified by RFCs or other standards) contain spaces,
  replace them with `_`. In general, use `snake_case` for field names.
- Shorten the following verbose names:
  - `source` -> `src`
  - `destination` -> `dst`
  - `address` -> `addr`
  - `checksum` -> `check`

## Feature flags

[Serde](https://serde.rs) support can be enabled through the `serde`
feature flag. It is intended to be used with binary serialization libraries
like [`bincode`](https://crates.io/crates/bincode) that leverage Serde's
infrastructure.

Note that `no_std` support is lost when enabling Serde.

License: MIT
