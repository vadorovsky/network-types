# network-types
Rust structs representing network-related types (on Layer 2, 3 and 4) in Linux.

The crate is [no_std](https://docs.rust-embedded.org/book/intro/no-std.html)
and the structures are fully compatible with the ones provided by the Linux
kernel, which makes it a great fit for [eBPF](https://ebpf.io/) programs written
with [Aya](https://aya-rs.dev/).

## Example with Aya

This crate can be used for parsing packet headers in
[TC classifier](https://aya-rs.dev/book/programs/classifiers/) and
[XDP](https://aya-rs.dev/book/start/).

A small example of an XDP program logging information about addresses and ports
for incoming packets:

```rust
#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    l2::ethernet::{EthHdr, ETH_HDR_LEN},
    l3::{
        ip::{Ipv4Hdr, IPV4_HDR_LEN},
        L3Protocol,
    },
    l4::{tcp::TcpHdr, udp::UdpHdr, L4Protocol},
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
    match unsafe { *ethhdr }.protocol()? {
        L3Protocol::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, ETH_HDR_LEN)? };
    let saddr = unsafe { *ipv4hdr }.saddr_from_be();

    let sport = match unsafe { *ipv4hdr }.protocol()? {
        L4Protocol::Tcp => {
            let tcphdr: *const TcpHdr =
                unsafe { ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN) }?;
            u16::from_be(unsafe { *tcphdr }.source)
        }
        L4Protocol::Udp => {
            let udphdr: *const UdpHdr =
                unsafe { ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN) }?;
            u16::from_be(unsafe { *udphdr }.source)
        }
        _ => return Err(()),
    };

    info!(&ctx, "SRC IP: {}, SRC PORT: {}", saddr, sport);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```
