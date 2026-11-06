//! Split frames larger than the replay link's MTU into what the wire carried.
//!
//! Captures taken on a host with segmentation/receive offload (TSO/GSO/GRO/LRO) record
//! coalesced frames of up to 64 KiB that never existed on the wire; the sender saw (or
//! sent) MSS-sized segments. Such a frame cannot be injected over a 1500-byte link: the
//! injector's send fails and the packet is lost (E036, 2026-11-06: the whole send
//! shortfall of three captures was exactly their frames over 1514 bytes).
//!
//! * IPv4/TCP: re-segmented at the MSS the link allows, as TSO would (sequence numbers
//!   advance by the payload carried, IP identification increments per segment, FIN/PSH
//!   only on the last segment, CWR only on the first).
//! * Other IPv4: fragmented per RFC 791 (offsets in 8-byte units, MF on all but the last,
//!   DF cleared). The transport checksum is left as is: it covers the whole datagram.
//! * Anything else (non-IPv4, VLAN-tagged, malformed): returned unchanged and counted as
//!   unsendable by the caller.

use super::{fold_checksum, set_transport_checksum_ipv4, sum_be_words_fast};
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::Ipv4Addr;

const ETH_HDR: usize = 14;
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Segmented {
    /// The frame fits the link (or splitting is disabled).
    Fits,
    /// TCP re-segmentation: the frames that replace the input.
    Tcp(Vec<Vec<u8>>),
    /// IPv4 fragmentation: the fragments that replace the input.
    Fragmented(Vec<Vec<u8>>),
    /// Too large and not splittable; the caller writes it unchanged and counts it.
    Unsendable,
}

fn set_ipv4_header_checksum(ip_hdr: &mut [u8]) {
    ip_hdr[10] = 0;
    ip_hdr[11] = 0;
    let c = fold_checksum(sum_be_words_fast(ip_hdr));
    ip_hdr[10..12].copy_from_slice(&c.to_be_bytes());
}

/// Split `frame` (Ethernet II) when it is longer than `max_frame` bytes. `max_frame == 0`
/// disables splitting.
pub(super) fn split_oversized(frame: &[u8], max_frame: usize) -> Segmented {
    if max_frame == 0 || frame.len() <= max_frame {
        return Segmented::Fits;
    }
    if frame.len() < ETH_HDR + 20 || frame[12..14] != ETHERTYPE_IPV4 || max_frame < ETH_HDR + 68 {
        return Segmented::Unsendable;
    }
    let ip = &frame[ETH_HDR..];
    if ip[0] >> 4 != 4 {
        return Segmented::Unsendable;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return Segmented::Unsendable;
    }
    // A frame captured before segmentation offload often carries IP total length 0 or a
    // value larger than what was captured; the bytes present are the datagram.
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let ip_len = if total == 0 || total > ip.len() { ip.len() } else { total };
    if ip_len <= ihl {
        return Segmented::Unsendable;
    }
    let max_ip = max_frame - ETH_HDR;
    let frag_field = u16::from_be_bytes([ip[6], ip[7]]);
    let already_fragment = frag_field & 0x3fff != 0; // MF set or offset != 0
    if ip[9] == IpNextHeaderProtocols::Tcp.0
        && !already_fragment
        && let Some(segs) = split_tcp(frame, ihl, ip_len, max_ip)
    {
        return Segmented::Tcp(segs);
    }
    match fragment_ipv4(frame, ihl, ip_len, max_ip) {
        Some(frags) => Segmented::Fragmented(frags),
        None => Segmented::Unsendable,
    }
}

fn split_tcp(frame: &[u8], ihl: usize, ip_len: usize, max_ip: usize) -> Option<Vec<Vec<u8>>> {
    let ip = &frame[ETH_HDR..ETH_HDR + ip_len];
    let tcp = &ip[ihl..];
    if tcp.len() < 20 {
        return None;
    }
    let thl = ((tcp[12] >> 4) as usize) * 4;
    if thl < 20 || tcp.len() < thl || ihl + thl >= max_ip {
        return None;
    }
    let payload = &tcp[thl..];
    let mss = max_ip - ihl - thl;
    if payload.len() <= mss {
        return None; // headers alone overflow; let fragmentation handle it
    }
    let seq0 = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let id0 = u16::from_be_bytes([ip[4], ip[5]]);
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let flags0 = tcp[13];
    let n = payload.len().div_ceil(mss);
    let mut out = Vec::with_capacity(n);
    for (i, chunk) in payload.chunks(mss).enumerate() {
        let mut f = Vec::with_capacity(ETH_HDR + ihl + thl + chunk.len());
        f.extend_from_slice(&frame[..ETH_HDR]);
        f.extend_from_slice(&ip[..ihl]);
        f.extend_from_slice(&tcp[..thl]);
        f.extend_from_slice(chunk);
        let seg_ip_len = (ihl + thl + chunk.len()) as u16;
        let ipb = &mut f[ETH_HDR..];
        ipb[2..4].copy_from_slice(&seg_ip_len.to_be_bytes());
        ipb[4..6].copy_from_slice(&id0.wrapping_add(i as u16).to_be_bytes());
        set_ipv4_header_checksum(&mut ipb[..ihl]);
        let t = &mut ipb[ihl..];
        let seq = seq0.wrapping_add((i * mss) as u32);
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        let mut flags = flags0;
        if i + 1 < n {
            flags &= !(0x01 | 0x08); // FIN, PSH only on the last segment
        }
        if i > 0 {
            flags &= !(0x02 | 0x80); // SYN, CWR only on the first segment
        }
        t[13] = flags;
        set_transport_checksum_ipv4(t, IpNextHeaderProtocols::Tcp, &src, &dst);
        out.push(f);
    }
    Some(out)
}

fn fragment_ipv4(frame: &[u8], ihl: usize, ip_len: usize, max_ip: usize) -> Option<Vec<Vec<u8>>> {
    let ip = &frame[ETH_HDR..ETH_HDR + ip_len];
    let data = &ip[ihl..];
    let per = ((max_ip.checked_sub(ihl)?) / 8) * 8;
    if per == 0 {
        return None;
    }
    let frag_field = u16::from_be_bytes([ip[6], ip[7]]);
    let base_units = (frag_field & 0x1fff) as usize;
    let more_after = frag_field & 0x2000 != 0;
    let n = data.len().div_ceil(per);
    let mut out = Vec::with_capacity(n);
    for (i, chunk) in data.chunks(per).enumerate() {
        let mut f = Vec::with_capacity(ETH_HDR + ihl + chunk.len());
        f.extend_from_slice(&frame[..ETH_HDR]);
        f.extend_from_slice(&ip[..ihl]);
        f.extend_from_slice(chunk);
        let ipb = &mut f[ETH_HDR..];
        ipb[2..4].copy_from_slice(&((ihl + chunk.len()) as u16).to_be_bytes());
        let off_units = base_units + i * per / 8;
        if off_units > 0x1fff {
            return None;
        }
        let mf = i + 1 < n || more_after;
        let field = (off_units as u16) | if mf { 0x2000 } else { 0 };
        ipb[6..8].copy_from_slice(&field.to_be_bytes());
        set_ipv4_header_checksum(&mut ipb[..ihl]);
        out.push(f);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_frame(proto: u8, l4: &[u8], id: u16, frag: u16, total_override: Option<u16>) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR];
        f[12] = 0x08;
        let total = total_override.unwrap_or((20 + l4.len()) as u16);
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[4..6].copy_from_slice(&id.to_be_bytes());
        ip[6..8].copy_from_slice(&frag.to_be_bytes());
        set_ipv4_header_checksum(&mut ip);
        f.extend_from_slice(&ip);
        f.extend_from_slice(l4);
        f
    }

    fn tcp(seq: u32, flags: u8, payload_len: usize) -> Vec<u8> {
        let mut t = vec![0u8; 32]; // 20 + 12 bytes of options
        t[0..2].copy_from_slice(&443u16.to_be_bytes());
        t[2..4].copy_from_slice(&50000u16.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[12] = 8 << 4;
        t[13] = flags;
        t.extend((0..payload_len).map(|i| (i % 251) as u8));
        t
    }

    fn ip_checksum_ok(f: &[u8]) -> bool {
        let ihl = ((f[ETH_HDR] & 0x0f) as usize) * 4;
        fold_checksum(sum_be_words_fast(&f[ETH_HDR..ETH_HDR + ihl])) == 0
    }

    #[test]
    fn small_frames_and_disabled_splitting_pass_through() {
        let f = ipv4_frame(6, &tcp(1, 0x18, 100), 7, 0x4000, None);
        assert_eq!(split_oversized(&f, 1514), Segmented::Fits);
        let big = ipv4_frame(6, &tcp(1, 0x18, 5000), 7, 0x4000, None);
        assert_eq!(split_oversized(&big, 0), Segmented::Fits);
    }

    #[test]
    fn tcp_is_resegmented_like_tso() {
        let payload = 4000;
        let f = ipv4_frame(6, &tcp(1_000, 0x19, payload), 100, 0x4000, None); // FIN|PSH|ACK
        let Segmented::Tcp(segs) = split_oversized(&f, 1514) else { panic!("not split") };
        let mss = 1500 - 20 - 32;
        assert_eq!(segs.len(), payload.div_ceil(mss));
        let mut carried = Vec::new();
        for (i, s) in segs.iter().enumerate() {
            assert!(s.len() <= 1514);
            assert!(ip_checksum_ok(s));
            let ip = &s[ETH_HDR..];
            assert_eq!(u16::from_be_bytes([ip[2], ip[3]]) as usize, s.len() - ETH_HDR);
            assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 100 + i as u16);
            let t = &ip[20..];
            assert_eq!(u32::from_be_bytes([t[4], t[5], t[6], t[7]]), 1_000 + (i * mss) as u32);
            let last = i + 1 == segs.len();
            assert_eq!(t[13] & 0x09 != 0, last, "FIN/PSH only on the last segment");
            assert_eq!(&t[20..32], &[0u8; 12][..], "options copied");
            // TCP checksum verifies over the pseudo-header.
            let src = Ipv4Addr::new(10, 0, 0, 1);
            let dst = Ipv4Addr::new(10, 0, 0, 2);
            let mut copy = t.to_vec();
            let want = u16::from_be_bytes([copy[16], copy[17]]);
            set_transport_checksum_ipv4(&mut copy, IpNextHeaderProtocols::Tcp, &src, &dst);
            assert_eq!(u16::from_be_bytes([copy[16], copy[17]]), want);
            carried.extend_from_slice(&t[32..]);
        }
        assert_eq!(carried, tcp(0, 0, payload)[32..].to_vec(), "payload preserved in order");
    }

    #[test]
    fn offload_frames_with_zero_ip_length_use_the_captured_bytes() {
        let f = ipv4_frame(6, &tcp(5, 0x10, 3000), 1, 0x4000, Some(0));
        let Segmented::Tcp(segs) = split_oversized(&f, 1514) else { panic!("not split") };
        let carried: usize = segs.iter().map(|s| s.len() - ETH_HDR - 20 - 32).sum();
        assert_eq!(carried, 3000);
    }

    #[test]
    fn udp_is_fragmented_per_rfc791() {
        let mut udp = vec![0u8; 8];
        udp.extend(std::iter::repeat_n(0xab, 3992));
        let f = ipv4_frame(17, &udp, 9, 0x4000, None);
        let Segmented::Fragmented(frags) = split_oversized(&f, 1514) else { panic!("not fragmented") };
        assert_eq!(frags.len(), 3);
        let mut joined = Vec::new();
        for (i, fr) in frags.iter().enumerate() {
            assert!(fr.len() <= 1514);
            assert!(ip_checksum_ok(fr));
            let ip = &fr[ETH_HDR..];
            let field = u16::from_be_bytes([ip[6], ip[7]]);
            assert_eq!(field & 0x4000, 0, "DF cleared");
            assert_eq!(field & 0x2000 != 0, i + 1 < frags.len(), "MF on all but the last");
            assert_eq!((field & 0x1fff) as usize * 8, joined.len(), "offset in 8-byte units");
            joined.extend_from_slice(&ip[20..]);
        }
        assert_eq!(joined, udp);
    }

    #[test]
    fn non_ipv4_oversized_frames_are_unsendable() {
        let mut f = vec![0u8; 3000];
        f[12] = 0x86;
        f[13] = 0xdd;
        assert_eq!(split_oversized(&f, 1514), Segmented::Unsendable);
    }
}
