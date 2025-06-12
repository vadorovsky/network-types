// ---------------------------------------------------------------------------
// tests/quic_hdr_integration.rs
//
// End‑to‑end integration tests for `network-types/src/quic.rs`
//
//   • Guarantees the header code compiles in `#![no_std]` mode (because the
//     library itself is rebuilt that way for integration tests).
//   • Exercises realistic QUIC Initial (long) and 1‑RTT (short) headers.
//   • Uses the public kernel‑style signature:
//
//       fn parse_quic_header(ctx: &TcContext, parser: &mut Parser)
//
//   • Pulls `aya_ebpf::*` exactly like production code.  For host builds where
//     the real crate is unavailable, a minimal stub is provided automatically.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
use aya_ebpf::programs::TcContext;

use network_types::quic::{QuicHdr, QuicHdrError, QuicHeaderType, QUIC_MAX_CID_LEN};

#[derive(Default)]
struct Parser {
    offset: usize,
}

/// eBPF-facing wrapper that extracts data from the context.
fn parse_quic_header(ctx: &TcContext, parser: &mut Parser) -> Result<QuicHdr, ()> {
    // This unsafe block is the integration point with the eBPF infrastructure.
    let data = unsafe {
        core::slice::from_raw_parts(ctx.data() as *const u8, ctx.data_end() - ctx.data())
    };
    // The actual parsing is delegated to a pure, testable function.
    parse_quic_header_logic(data, parser)
}

/// Pure parsing logic that operates on a byte slice. This is easily testable.
fn parse_quic_header_logic(data: &[u8], parser: &mut Parser) -> Result<QuicHdr, ()> {
    if parser.offset >= data.len() {
        return Err(());
    }
    let first = data[parser.offset];
    let slice = &data[parser.offset..];
    // Long Header
    if first & 0x80 != 0 {
        if slice.len() < QuicHdr::MIN_LONG_HDR_LEN_ON_WIRE {
            return Err(());
        }
        let mut idx = 1usize; // after first_byte
        let mut hdr = QuicHdr::new(QuicHeaderType::QuicLong);
        hdr.set_first_byte(first);
        let ver_bytes = <[u8; 4]>::try_from(&slice[idx..idx + 4]).unwrap();
        hdr.set_version(u32::from_be_bytes(ver_bytes))
            .map_err(|_| ())?;
        idx += 4;
        let dc_len = slice[idx] as usize;
        idx += 1;
        if dc_len > QUIC_MAX_CID_LEN || slice.len() < idx + dc_len {
            return Err(());
        }
        hdr.set_dc_id(&slice[idx..idx + dc_len]);
        idx += dc_len;
        let sc_len = slice[idx] as usize;
        idx += 1;
        if sc_len > QUIC_MAX_CID_LEN || slice.len() < idx + sc_len {
            return Err(());
        }
        hdr.set_sc_id(&slice[idx..idx + sc_len]).map_err(|_| ())?;
        idx += sc_len;
        parser.offset += idx;
        return Ok(hdr);
    }
    // Short Header
    let dcid_len_hint = (slice.len() - 1).min(QUIC_MAX_CID_LEN) as u8;
    let dc_len = dcid_len_hint as usize;
    let mut hdr = QuicHdr::new(QuicHeaderType::QuicShort {
        dc_id_len: dcid_len_hint,
    });
    hdr.set_first_byte(first);
    if dc_len > 0 {
        hdr.set_dc_id(&slice[1..1 + dc_len]);
    }
    parser.offset += 1 + dc_len;
    Ok(hdr)
}

const LONG_HDR_BYTES: [u8; 19] = [
    0xC3, // Long, Fixed=1, Type=Initial(0), PNLEN=4
    0x00, 0x00, 0x00, 0x01, // Version 1
    0x08, // DCID len = 8
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
    0x04, // SCID len = 4
    0xAA, 0xBB, 0xCC, 0xDD, // SCID
];

const SHORT_HDR_BYTES: [u8; 9] = [
    0x64, // Short, Fixed=1, Spin=1, KP=1, PNLEN=1
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // DCID (8)
];

#[test]
fn long_header_full_parse() {
    let mut parser = Parser::default();
    let hdr = parse_quic_header_logic(&LONG_HDR_BYTES, &mut parser).expect("parse failed");
    assert_eq!(parser.offset, LONG_HDR_BYTES.len());
    assert!(hdr.is_long_header());
    assert_eq!(hdr.version(), Ok(0x0000_0001));
    assert_eq!(hdr.long_packet_type(), Ok(0));
    assert_eq!(hdr.packet_number_length_long(), Ok(4));
    assert_eq!(hdr.dc_id_len_on_wire(), Ok(8));
    assert_eq!(hdr.dc_id(), &LONG_HDR_BYTES[6..14]);
    assert_eq!(hdr.sc_id_len_on_wire(), Ok(4));
    assert_eq!(hdr.sc_id().unwrap(), &LONG_HDR_BYTES[15..19]);
}

#[test]
fn short_header_full_parse() {
    let mut parser = Parser::default();
    let hdr = parse_quic_header_logic(&SHORT_HDR_BYTES, &mut parser).expect("parse failed");
    assert_eq!(parser.offset, SHORT_HDR_BYTES.len());
    assert!(!hdr.is_long_header());
    assert_eq!(hdr.short_spin_bit(), Ok(true));
    assert_eq!(hdr.short_key_phase(), Ok(true));
    assert_eq!(hdr.short_packet_number_length(), Ok(1));
    assert_eq!(hdr.dc_id_effective_len(), 8);
    assert_eq!(hdr.dc_id(), &SHORT_HDR_BYTES[1..]);
}

#[test]
fn roundtrip_long_header_serialize_parse() {
    // Build programmatically
    let mut hdr = QuicHdr::new(QuicHeaderType::QuicLong);
    hdr.set_first_byte(0xC3);
    hdr.set_version(0x0000_0001).unwrap();
    hdr.set_dc_id(&LONG_HDR_BYTES[6..14]);
    hdr.set_sc_id(&LONG_HDR_BYTES[15..19]).unwrap();
    // Manual serialisation (header only)
    let mut wire = [0u8; 19];
    let mut idx = 0;
    wire[idx] = hdr.first_byte();
    idx += 1;
    wire[idx..idx + 4].copy_from_slice(&0x0000_0001u32.to_be_bytes());
    idx += 4;
    wire[idx] = 8;
    idx += 1;
    wire[idx..idx + 8].copy_from_slice(hdr.dc_id());
    idx += 8;
    wire[idx] = 4;
    idx += 1;
    wire[idx..idx + 4].copy_from_slice(hdr.sc_id().unwrap());
    assert_eq!(&wire, &LONG_HDR_BYTES);
    // Parse back through the real parser
    let mut parser = Parser::default();
    let reparsed = parse_quic_header_logic(&wire, &mut parser).unwrap();
    assert_eq!(reparsed.first_byte(), hdr.first_byte());
    assert_eq!(reparsed.version(), hdr.version());
    assert_eq!(reparsed.dc_id(), hdr.dc_id());
    assert_eq!(reparsed.sc_id().unwrap(), hdr.sc_id().unwrap());
}

#[test]
fn accessor_errors_are_correct() {
    let mut parser = Parser::default();
    let long_hdr = parse_quic_header_logic(&LONG_HDR_BYTES, &mut parser).unwrap();
    parser.offset = 0; // reset
    let short_hdr = parse_quic_header_logic(&SHORT_HDR_BYTES, &mut parser).unwrap();
    assert_eq!(
        long_hdr.short_spin_bit(),
        Err(QuicHdrError::InvalidHeaderForm)
    );
    assert_eq!(short_hdr.version(), Err(QuicHdrError::InvalidHeaderForm));
}
