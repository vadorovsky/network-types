#![allow(dead_code)] // Allow dead code for elements that are part of the setup

use network_types::quic::{
    QuicHdr, QuicPacketType, QuicHeaderType,
    QUIC_MAX_CID_LEN, // Used in parse_quic_header
};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::udp::UdpHdr;

use aya_ebpf::{
    programs::TcContext,
    EbpfContext, // Trait for ctx.load(), used by parser functions
    bindings::__sk_buff // For creating TcContext
};
// core::ptr was removed as it's not used.

// Constants for QUIC parsing logic, mirrored from src/quic.rs as they are private there.
const HDR_FORM_BIT_TEST: u8 = 0x80; // Not used directly in this file after changes, but kept for reference
const LONG_PACKET_TYPE_MASK_TEST: u8 = 0x30;
const LONG_PACKET_TYPE_SHIFT_TEST: u8 = 4;
const PN_LENGTH_BITS_MASK_TEST: u8 = 0x03;


// --- Parser Struct and HeaderType Enum (remains the same) ---
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum HeaderType {
    Ethernet,
    Ipv4,
    // Ipv6, // Not used in current tests, can be re-added if needed
    Udp,
    Quic,
    StopProcessing,
    ErrorOccurred,
}

struct Parser {
    offset: usize,
    next_hdr: HeaderType,
}

impl Parser {
    fn new() -> Self {
        Parser {
            offset: 0,
            next_hdr: HeaderType::Ethernet,
        }
    }
}

fn read_quic_varint(ctx: &TcContext, offset: usize) -> Result<(u64, usize), ()> {
    // Ensure we can read the first byte to determine the length of the varint.
    let read_end = offset + 1;
    if read_end > ctx.data_end() {
        return Err(());
    }
    let first_byte: u8 = unsafe { ctx.load(offset).map_err(|_| ())? };

    // The length of the varint (1, 2, 4, or 8 bytes) is encoded in the first two bits.
    let len = 1 << (first_byte >> 6);

    // Ensure the full varint is within packet bounds before reading it.
    let read_end = offset + len;
    if read_end > ctx.data_end() {
        return Err(());
    }

    // Read the varint value based on its determined length.
    let val = match len {
        1 => (first_byte & 0x3F) as u64,
        2 => {
            let raw: u16 = unsafe { ctx.load(offset).map_err(|_| ())? };
            (u16::from_be(raw) & 0x3FFF) as u64
        }
        4 => {
            let raw: u32 = unsafe { ctx.load(offset).map_err(|_| ())? };
            (u32::from_be(raw) & 0x3FFFFFFF) as u64
        }
        8 => {
            let raw: u64 = unsafe { ctx.load(offset).map_err(|_| ())? };
            u64::from_be(raw) & 0x3FFFFFFFFFFFFFFF
        }
        _ => return Err(()), // Should be unreachable
    };

    Ok((val, len))
}

fn parse_quic_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let mut current_offset = parser.offset;

    // Boundary check for the first byte of the QUIC header.
    if current_offset + 1 > ctx.data_end() {
        return Err(());
    }
    let first_byte: u8 = unsafe { ctx.load(current_offset).map_err(|_| ())? };
    current_offset += 1;

    let is_long_header = (first_byte & HDR_FORM_BIT_TEST) != 0;

    if is_long_header {
        // --- Long Header Parsing ---

        // Boundary check for Version (4 bytes).
        if current_offset + 4 > ctx.data_end() {
            return Err(());
        }
        current_offset += 4; // Skip Version

        // Boundary check for DCID Len (1 byte) and DCID.
        if current_offset + 1 > ctx.data_end() {
            return Err(());
        }
        let dcid_len: u8 = unsafe { ctx.load(current_offset).map_err(|_| ())? };
        current_offset += 1;
        if current_offset + (dcid_len as usize) > ctx.data_end() {
            return Err(());
        }
        current_offset += dcid_len as usize; // Skip DCID

        // Boundary check for SCID Len (1 byte) and SCID.
        if current_offset + 1 > ctx.data_end() {
            return Err(());
        }
        let scid_len: u8 = unsafe { ctx.load(current_offset).map_err(|_| ())? };
        current_offset += 1;
        if current_offset + (scid_len as usize) > ctx.data_end() {
            return Err(());
        }
        current_offset += scid_len as usize; // Skip SCID

        // For Initial packets, parse Token Length and Token.
        let long_packet_type = (first_byte & LONG_PACKET_TYPE_MASK_TEST) >> LONG_PACKET_TYPE_SHIFT_TEST;
        if long_packet_type == 0 { // Type 0 -> Initial Packet
            let (token_len_val, token_len_bytes) = read_quic_varint(ctx, current_offset)?;
            current_offset += token_len_bytes;
            if current_offset + (token_len_val as usize) > ctx.data_end() {
                return Err(());
            }
            current_offset += token_len_val as usize; // Skip Token
        }

        // Read payload length using our safe varint reader.
        let (_payload_len, len_bytes) = read_quic_varint(ctx, current_offset)?;
        current_offset += len_bytes;

        // Boundary check for the Packet Number. Its length is in the first byte.
        let pn_len = (first_byte & PN_LENGTH_BITS_MASK_TEST) as usize + 1;
        if current_offset + pn_len > ctx.data_end() {
            return Err(());
        }
        current_offset += pn_len; // Skip Packet Number
    } else {
        // --- Short Header Parsing ---
        // For short headers, the DCID length is implicit from the connection context.
        // For a stateless parser, we must assume a fixed length. 8 bytes is a common choice.
        const SHORT_HEADER_DCID_LEN: usize = 8;
        if current_offset + SHORT_HEADER_DCID_LEN > ctx.data_end() {
            return Err(());
        }
        current_offset += SHORT_HEADER_DCID_LEN; // Skip DCID

        // Packet Number length is also implicit and protected. We assume a max length of 4 bytes.
        const SHORT_HEADER_PN_LEN: usize = 4;
        if current_offset + SHORT_HEADER_PN_LEN > ctx.data_end() {
            return Err(());
        }
        current_offset += SHORT_HEADER_PN_LEN; // Skip Packet Number
    }

    parser.offset = current_offset;
    parser.next_hdr = HeaderType::StopProcessing;
    Ok(())
}

// --- Simplified Layer Parsers for Test Orchestration (using TcContext) ---
fn parse_ethernet_header_dummy(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let _eth_hdr: EthHdr = ctx.load(parser.offset).map_err(|_| ())?;
    parser.offset += EthHdr::LEN;
    parser.next_hdr = HeaderType::Ipv4;
    Ok(())
}

fn parse_ipv4_header_dummy(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let ipv4_hdr: Ipv4Hdr = ctx.load(parser.offset).map_err(|_| ())?;
    let ip_hdr_len = (ipv4_hdr.vihl & 0x0F) as usize * 4;
    if ip_hdr_len < Ipv4Hdr::LEN { return Err(()); }
    parser.offset += ip_hdr_len;
    parser.next_hdr = HeaderType::Udp; // Assuming UDP next for QUIC
    Ok(())
}

fn parse_udp_header_dummy(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let _udp_hdr: UdpHdr = ctx.load(parser.offset).map_err(|_| ())?;
    parser.offset += UdpHdr::LEN;
    parser.next_hdr = HeaderType::Quic;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    // --- Packet Building Helper ---
    fn build_quic_packet(quic_payload_and_header: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let eth = EthHdr {
            dst_addr: [0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
            src_addr: [0x22, 0x22, 0x22, 0x22, 0x22, 0x22],
            ether_type: EtherType::Ipv4.into(), // Use .into() for u16 conversion
        };
        // Manual serialization for EthHdr as it might not be Pod
        buf.extend_from_slice(&eth.dst_addr); // Corrected: was ð.dst_addr
        buf.extend_from_slice(&eth.src_addr); // Corrected: was ð.src_addr
        buf.extend_from_slice(&u16::from(eth.ether_type).to_be_bytes());


        let l3_offset = buf.len();
        let mut ipv4 = Ipv4Hdr {
            vihl: (4 << 4) | 5, // IPv4, 5 * 32-bit words header length
            tos: 0,
            tot_len: 0u16.to_be_bytes(), // Placeholder, will be updated
            id: 0x1234u16.to_be_bytes(),
            frags: 0u16.to_be_bytes(),
            ttl: 64,
            proto: IpProto::Udp,
            check: 0u16.to_be_bytes(), // Checksum placeholder
            src_addr: [192, 168, 1, 1].into(),
            dst_addr: [192, 168, 1, 2].into(),
        };
        let ipv4_hdr_len = (ipv4.vihl & 0x0F) as usize * 4;
        // Directly extend with a known-size struct
        let ipv4_bytes_slice = unsafe {
            core::slice::from_raw_parts(&ipv4 as *const _ as *const u8, ipv4_hdr_len)
        };
        buf.extend_from_slice(ipv4_bytes_slice);


        let l4_offset = buf.len();
        let mut udp = UdpHdr {
            src: 12345u16.to_be_bytes(), // Corrected: was source
            dst: 443u16.to_be_bytes(),   // Corrected: was dest
            len: 0u16.to_be_bytes(), // Placeholder
            check: 0u16.to_be_bytes(), // Checksum placeholder
        };
        let udp_bytes_slice = unsafe {
            core::slice::from_raw_parts(&udp as *const _ as *const u8, UdpHdr::LEN)
        };
        buf.extend_from_slice(udp_bytes_slice);
        buf.extend_from_slice(quic_payload_and_header);

        // Update IPv4 total length
        let ipv4_total_len = (buf.len() - l3_offset) as u16;
        ipv4.tot_len = ipv4_total_len.to_be_bytes();
        let updated_ipv4_bytes = unsafe {
            core::slice::from_raw_parts(&ipv4 as *const _ as *const u8, ipv4_hdr_len)
        };
        buf[l3_offset..l3_offset + ipv4_hdr_len].copy_from_slice(updated_ipv4_bytes);

        // Update UDP total length
        let udp_total_len = (buf.len() - l4_offset) as u16;
        udp.len = udp_total_len.to_be_bytes();
        let updated_udp_bytes = unsafe {
            core::slice::from_raw_parts(&udp as *const _ as *const u8, UdpHdr::LEN)
        };
        buf[l4_offset..l4_offset + UdpHdr::LEN].copy_from_slice(updated_udp_bytes);
        buf
    }

    // --- Test Orchestration Function (using TcContext) ---
    fn run_parser_on_packet(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
        // Increased loop count to handle more headers if necessary, 4 is Eth+IP+UDP+QUIC
        for _ in 0..4 {
            match parser.next_hdr {
                HeaderType::Ethernet => parse_ethernet_header_dummy(ctx, parser)?,
                HeaderType::Ipv4 => parse_ipv4_header_dummy(ctx, parser)?,
                HeaderType::Udp => parse_udp_header_dummy(ctx, parser)?,
                HeaderType::Quic => parse_quic_header(ctx, parser)?,
                HeaderType::StopProcessing => break,
                HeaderType::ErrorOccurred => return Err(()),
                // _ => return Err(()), // Catch-all for unexpected HeaderTypes
            }
        }
        if parser.next_hdr != HeaderType::StopProcessing {
            // If it didn't stop, but also didn't error, it might be an issue if we expected it to fully parse.
            Err(())
        } else {
            Ok(())
        }
    }

    // Helper to create __sk_buff and TcContext for tests
    // This function is unsafe because TcContext::new is unsafe.
    // It returns the skb_metadata so it can be kept alive by the caller.
    unsafe fn create_tc_context_with_skb(
        packet_slice: &mut [u8]
    ) -> (TcContext, __sk_buff) {
        let mut skb_metadata = MaybeUninit::<__sk_buff>::uninit();
        let skb_ptr = skb_metadata.as_mut_ptr();

        // Zero out the struct
        core::ptr::write_bytes(skb_ptr, 0, 1);
        let mut skb_metadata = skb_metadata.assume_init();

        skb_metadata.data = packet_slice.as_mut_ptr() as usize as u32; // Corrected: was `as *mut _ as u32`
        skb_metadata.data_end = (packet_slice.as_mut_ptr() as usize + packet_slice.len()) as u32; // Corrected: removed `as *mut _`
        skb_metadata.len = packet_slice.len() as u32;
        // NOTE: For TcContext, skb.data usually points to the network header.
        // Here, our parser expects offset 0 to be the start of Ethernet.
        // So, skb.data pointing to the start of packet_slice is correct for these tests.

        let ctx = TcContext::new(&mut skb_metadata as *mut _);
        (ctx, skb_metadata)
    }


    // --- New Integration Tests ---
    #[test]
    fn test_parse_full_packet_valid_quic_initial() {
        let quic_data = vec![
            // Initial Packet (Long Header)
            0xC0, // Type: Initial, Fixed Bit: 1, Packet Number Length: 1
            0x00, 0x00, 0x00, 0x01, // Version: 1
            0x00, // DCID Len: 0 
            0x00, // SCID Len: 0
            0x00, // Token Length: 0
            0x01, // Length (payload + PN): 1 (for PN)
            0xAB, // Packet Number (dummy)
        ];
        let mut packet_bytes_vec = build_quic_packet(&quic_data);

        let (ctx, mut _skb_metadata_guard) = unsafe { create_tc_context_with_skb(&mut packet_bytes_vec) };
        let mut parser = Parser::new();

        let result = run_parser_on_packet(&ctx, &mut parser);
        assert!(result.is_ok(), "Full packet parsing failed for QUIC Initial: {:?}", result.err());

        // Expected offset: Eth (14) + IPv4 (20, default) + UDP (8) + QUIC data len
        let expected_offset = EthHdr::LEN + (5 * 4) + UdpHdr::LEN + quic_data.len();
        assert_eq!(parser.offset, expected_offset);
        assert_eq!(parser.next_hdr, HeaderType::StopProcessing);
    }
    
    #[test]
    fn test_parse_full_packet_valid_quic_short_header() {
        let quic_data = vec![
            // Short Header Packet
            0x40, // Type: Short, Fixed Bit: 1, Spin Bit: 0, Key Phase: 0, PN Len: 1
            // (No DCID included in this minimal example, assumes 0 length for parser)
            0xBC, // Packet Number (dummy)
        ];
        let mut packet_bytes_vec = build_quic_packet(&quic_data);
        let (ctx, mut _skb_metadata_guard) = unsafe { create_tc_context_with_skb(&mut packet_bytes_vec) };
        let mut parser = Parser::new();

        let result = run_parser_on_packet(&ctx, &mut parser);
        assert!(result.is_ok(), "Full packet parsing failed for QUIC Short: {:?}", result.err());
        let expected_offset = EthHdr::LEN + (5 * 4) + UdpHdr::LEN + quic_data.len();
        assert_eq!(parser.offset, expected_offset);
        assert_eq!(parser.next_hdr, HeaderType::StopProcessing);
    }

    #[test]
    fn test_parse_full_packet_quic_too_short_for_header() {
        let quic_data = vec![0xC0]; // Valid first byte for Initial, but not enough data for rest of header
        let mut packet_bytes_vec = build_quic_packet(&quic_data);
        let (ctx, mut _skb_metadata_guard) = unsafe { create_tc_context_with_skb(&mut packet_bytes_vec) };
        let mut parser = Parser::new();

        let result = run_parser_on_packet(&ctx, &mut parser);
        assert!(result.is_err(), "Full packet parsing should fail if QUIC part is malformed/too short");
        // Parser should stop at QUIC header parsing, offset remains at start of QUIC
        assert_eq!(parser.offset, EthHdr::LEN + (5*4) + UdpHdr::LEN);
        assert_eq!(parser.next_hdr, HeaderType::Quic); // Still expecting QUIC, but failed
    }

    // This function returns __sk_buff to ensure its lifetime is tied to the caller's scope,
    // preventing the TcContext from holding a dangling pointer.
    fn setup_direct_quic_test(packet_slice: &mut [u8], initial_offset: usize) -> (TcContext, Parser, __sk_buff) {
        let (ctx, skb_metadata) = unsafe { create_tc_context_with_skb(packet_slice) };

        let mut parser = Parser::new();
        parser.offset = initial_offset;
        parser.next_hdr = HeaderType::Quic;
        (ctx, parser, skb_metadata)
    }


    #[test]
    fn test_parse_quic_header_short_minimal_direct() {
        let mut packet_bytes = vec![0x40, 0x01]; // Short header, PN Len 1, PN 0x01
        let (ctx, mut parser, _skb_guard) = setup_direct_quic_test(&mut packet_bytes, 0);
        let result = parse_quic_header(&ctx, &mut parser);
        assert!(result.is_ok(), "QUIC short minimal direct parse failed: {:?}", result.err());
        assert_eq!(parser.offset, 2); // 1 byte header flags + 1 byte PN
    }

    #[test]
    fn test_parse_quic_header_initial_basic_direct() {
        let mut packet_bytes = vec![
            // Initial Packet (Long Header)
            0xC0, // Type: Initial (00), Fixed Bit: 1, Packet Number Length: 1 (00)
            0x00, 0x00, 0x00, 0x01, // Version: 1
            0x00,       // DCID Len: 0
            0x00,       // SCID Len: 0
            0x00,       // Token Length (VarInt): 0
            0x01,       // Length (VarInt): 1 (covers 1 byte PN)
            0xAB,       // Packet Number: 0xAB (1 byte)
        ];
        let (ctx, mut parser, _skb_guard) = setup_direct_quic_test(&mut packet_bytes, 0);
        let result = parse_quic_header(&ctx, &mut parser);
        assert!(result.is_ok(), "QUIC initial basic direct parse failed: {:?}", result.err());
        // Expected: 1 (type) + 4 (ver) + 1 (dcidlen) + 1 (scidlen) + 1 (tokenlen) + 1 (len) + 1 (pn) = 10
        assert_eq!(parser.offset, 10);
    }

    #[test]
    fn test_parse_quic_initial_with_cids_token_longer_length_direct() {
        // Long header initial packet: Type (Initial) + PN Len (2 bytes from 0b01)
        let mut packet_bytes = vec![
            0xC0 | 0b01, // First byte: Long Header (1), Fixed Bit (1), Type (Initial 00), Reserved (0), PN Len (2 -> 01)
            // Version (4 bytes)
            0x00, 0x00, 0x00, 0x01,
            // DCID Len (1 byte) + DCID (4 bytes)
            0x04, // DCID Len = 4
            0x01, 0x02, 0x03, 0x04, // DCID
            // SCID Len (1 byte) + SCID (4 bytes)
            0x04, // SCID Len = 4
            0x05, 0x06, 0x07, 0x08, // SCID
            // Token Length (varint, 1 byte for value 2) + Token (2 bytes)
            0x02, // Token Length = 2
            0xAB, 0xCD, // Token
            // Length (varint, 1 byte for value 5 -> payload 3 + PN 2) + Payload (variable) + PN (2 bytes)
            // The problem statement defines Length as "Length (varint): 1 (covers 1 byte PN)" for basic initial
            // This test case's Length is 0x05. If PN Len is 2 (from 0xC0 | 0b01), this means payload part is 3.
            // The previous PN was 0xAB. Here it's 0x12, 0x34
            0x05, // Length = 5 (meaning 3 bytes of "payload" if PN takes 2)
            0x12, 0x34, // Packet Number (2 bytes due to PN Len 0b01)
        ];
        // Total expected length:
        // 1 (Flags) + 4 (Version) + 1 (DCID Len) + 4 (DCID) + 1 (SCID Len) + 4 (SCID)
        // + 1 (Token Varint Len for value 2) + 2 (Token actual bytes)
        // + 1 (Length Varint Len for value 5) + 2 (PN actual bytes)
        // = 1+4+1+4+1+4+1+2+1+2 = 21 bytes
        let (ctx, mut parser, _skb_guard) = setup_direct_quic_test(&mut packet_bytes, 0);
        let result = parse_quic_header(&ctx, &mut parser);
        assert!(result.is_ok(), "Parsing QUIC Initial with CIDs/Token failed: {:?}", result.err());
        assert_eq!(parser.offset, 21);
    }

    #[test]
    fn test_packet_too_short_for_long_header_version_direct() {
        let mut packet_bytes = vec![0xC0, 0x00, 0x00]; // Not enough for version
        let (ctx, mut parser, _skb_guard) = setup_direct_quic_test(&mut packet_bytes, 0);
        assert!(parse_quic_header(&ctx, &mut parser).is_err());
    }

    #[test]
    fn test_packet_too_short_for_short_header_pkt_num_direct() {
        let mut packet_bytes = vec![0x41]; // Short header, PN len 2 (0b01), but no PN bytes
        let (ctx, mut parser, _skb_guard) = setup_direct_quic_test(&mut packet_bytes, 0);
        assert!(parse_quic_header(&ctx, &mut parser).is_err());
    }

    #[test]
    fn test_quic_hdr_struct_methods_basic() {
        let first_byte = 0xc0; // Long header, Initial, PN Len 1
        let mut hdr_for_test = QuicHdr::new(QuicHeaderType::QuicLong); // Type is for context
        hdr_for_test.set_first_byte(first_byte);
        assert!(hdr_for_test.is_long_header());
        assert_eq!(hdr_for_test.long_packet_type().unwrap(), QuicPacketType::Initial);
        // Corrected method name:
        assert_eq!(hdr_for_test.packet_number_length_long().unwrap(), 1);
    }
}