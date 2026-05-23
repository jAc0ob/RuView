//! ADR-110 §A0.12 sync packet decoder (firmware v0.6.9+).
//!
//! Emitted by the firmware on the same UDP socket as ADR-018 CSI frames,
//! distinguished by leading magic `0xC511A110`. Pairs `(node_id, sequence)`
//! across the two UDP streams so a host aggregator can recover mesh-aligned
//! timestamps for every CSI frame — see `WITNESS-LOG-110 §A0.12` for live
//! verification, `archive/v1/src/hardware/csi_extractor.py:SyncPacketParser`
//! for the matching Python decoder.
//!
//! Wire format (32 bytes, little-endian):
//! ```text
//! [0..3]   magic 0xC511A110 (LE u32)
//! [4]      node_id
//! [5]      proto_ver (currently 0x01)
//! [6]      flags: bit 0 = is_leader
//!                 bit 1 = is_valid (fresh sync within VALID_WINDOW_MS)
//!                 bit 2 = smoothed_used (EMA filter active)
//! [7]      reserved
//! [8..15]  local esp_timer_get_time() (u64)
//! [16..23] mesh-aligned epoch = local + smoothed offset (u64)
//! [24..27] high-water CSI sequence (u32) — pairing key against ADR-018 frames
//! [28..31] reserved
//! ```
//!
//! Recover the per-board offset for a given sync packet as
//! `local_us - epoch_us` (signed). Follower nodes report the EMA-smoothed
//! offset measured in §A0.10; leader nodes report `~0` modulo call-stack
//! elapsed time (`leader_epoch_us = now_us` by definition).

use serde::{Deserialize, Serialize};

use crate::error::ParseError;

/// Magic constant in the first 4 little-endian bytes of every sync packet.
pub const SYNC_PACKET_MAGIC: u32 = 0xC511_A110;
/// Total wire size of a v0.6.9+ sync packet.
pub const SYNC_PACKET_SIZE: usize = 32;
/// Wire protocol version currently emitted by firmware.
pub const SYNC_PACKET_PROTO_VER: u8 = 0x01;

/// Decoded ADR-110 §A0.12 sync packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPacket {
    pub node_id: u8,
    pub proto_ver: u8,
    pub flags: SyncPacketFlags,
    /// Node-local `esp_timer_get_time()` snapshot at emission time.
    pub local_us: u64,
    /// Mesh-aligned epoch — `local_us + smoothed_offset`.
    pub epoch_us: u64,
    /// High-water ADR-018 CSI sequence number at emission time. Host
    /// aggregator pairs (`node_id`, `sequence`) across the two UDP streams
    /// to apply the recovered offset back to in-flight CSI frames.
    pub sequence: u32,
}

/// Flag bits packed into byte 6 of the sync packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SyncPacketFlags {
    pub is_leader: bool,
    pub is_valid: bool,
    pub smoothed_used: bool,
}

impl SyncPacketFlags {
    pub fn from_byte(b: u8) -> Self {
        Self {
            is_leader: (b & 0x01) != 0,
            is_valid: (b & 0x02) != 0,
            smoothed_used: (b & 0x04) != 0,
        }
    }

    pub fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.is_leader { b |= 0x01; }
        if self.is_valid { b |= 0x02; }
        if self.smoothed_used { b |= 0x04; }
        b
    }
}

impl SyncPacket {
    /// Decode a 32-byte sync packet. Returns `ParseError::InvalidMagic` if
    /// the leading u32 doesn't match `SYNC_PACKET_MAGIC` (host should
    /// dispatch on the magic before calling this — see crate-level docs).
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < SYNC_PACKET_SIZE {
            return Err(ParseError::InsufficientData {
                needed: SYNC_PACKET_SIZE,
                got: buf.len(),
            });
        }
        let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if magic != SYNC_PACKET_MAGIC {
            return Err(ParseError::InvalidMagic { expected: SYNC_PACKET_MAGIC, got: magic });
        }
        let node_id = buf[4];
        let proto_ver = buf[5];
        let flags = SyncPacketFlags::from_byte(buf[6]);
        // buf[7] reserved
        let local_us = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let epoch_us = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let sequence = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        // buf[28..32] reserved
        Ok(Self {
            node_id,
            proto_ver,
            flags,
            local_us,
            epoch_us,
            sequence,
        })
    }

    /// Recover the signed offset between this node's local monotonic clock
    /// and the mesh epoch (`local_us - epoch_us`). For followers this is
    /// the EMA-smoothed offset; for leaders this is approximately 0 (a few
    /// µs of call-stack elapsed only).
    pub fn local_minus_epoch_us(&self) -> i64 {
        (self.local_us as i64) - (self.epoch_us as i64)
    }

    /// Serialize back to wire bytes (32 bytes, little-endian).
    pub fn to_bytes(&self) -> [u8; SYNC_PACKET_SIZE] {
        let mut out = [0u8; SYNC_PACKET_SIZE];
        out[0..4].copy_from_slice(&SYNC_PACKET_MAGIC.to_le_bytes());
        out[4] = self.node_id;
        out[5] = self.proto_ver;
        out[6] = self.flags.to_byte();
        // out[7] reserved zero
        out[8..16].copy_from_slice(&self.local_us.to_le_bytes());
        out[16..24].copy_from_slice(&self.epoch_us.to_le_bytes());
        out[24..28].copy_from_slice(&self.sequence.to_le_bytes());
        // out[28..32] reserved zero
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces the COM9 follower sync-pkt #1 captured in WITNESS-LOG-110 §A0.12.
    #[test]
    fn follower_typical_packet_roundtrips() {
        let pkt = SyncPacket {
            node_id: 9,
            proto_ver: 1,
            flags: SyncPacketFlags { is_leader: false, is_valid: true, smoothed_used: true },
            local_us: 28_798_450,
            epoch_us: 27_634_885,
            sequence: 20,
        };
        let wire = pkt.to_bytes();
        let decoded = SyncPacket::from_bytes(&wire).unwrap();
        assert_eq!(decoded, pkt);
        // The 1.16-second boot delta §A0.10 measured between COM9 and COM12.
        assert_eq!(decoded.local_minus_epoch_us(), 1_163_565);
        assert_eq!(decoded.flags.to_byte(), 0x06);
    }

    /// COM12 leader case from WITNESS-LOG-110 §A0.12: flags=0x03, epoch ≈ local.
    #[test]
    fn leader_packet_has_local_close_to_epoch() {
        let pkt = SyncPacket {
            node_id: 12,
            proto_ver: 1,
            flags: SyncPacketFlags { is_leader: true, is_valid: true, smoothed_used: false },
            local_us: 28_864_932,
            epoch_us: 28_864_939,
            sequence: 20,
        };
        let wire = pkt.to_bytes();
        let decoded = SyncPacket::from_bytes(&wire).unwrap();
        assert_eq!(decoded.flags.to_byte(), 0x03);
        assert_eq!(decoded.local_minus_epoch_us(), -7);  // leader has zero offset modulo call-stack
        assert!(decoded.flags.is_leader);
        assert!(decoded.flags.is_valid);
        assert!(!decoded.flags.smoothed_used);
    }

    #[test]
    fn magic_mismatch_is_typed_error() {
        let mut wire = SyncPacket {
            node_id: 1, proto_ver: 1, flags: SyncPacketFlags::default(),
            local_us: 0, epoch_us: 0, sequence: 0,
        }.to_bytes();
        wire[0] = 0x01;  // corrupt magic low byte
        let err = SyncPacket::from_bytes(&wire).unwrap_err();
        match err {
            ParseError::InvalidMagic { got, .. } => assert_ne!(got, SYNC_PACKET_MAGIC),
            other => panic!("expected InvalidMagic, got {other:?}"),
        }
    }

    #[test]
    fn short_packet_is_typed_error() {
        let wire = [0u8; 16];  // half a packet
        let err = SyncPacket::from_bytes(&wire).unwrap_err();
        match err {
            ParseError::InsufficientData { needed, got } => {
                assert_eq!(needed, SYNC_PACKET_SIZE);
                assert_eq!(got, 16);
            }
            other => panic!("expected InsufficientData, got {other:?}"),
        }
    }

    /// Every (leader, valid, smoothed_used) triple round-trips independently.
    #[test]
    fn all_flag_combinations_roundtrip() {
        for &is_leader in &[false, true] {
            for &is_valid in &[false, true] {
                for &smoothed_used in &[false, true] {
                    let flags = SyncPacketFlags { is_leader, is_valid, smoothed_used };
                    let pkt = SyncPacket {
                        node_id: 1, proto_ver: 1, flags,
                        local_us: 1234, epoch_us: 5678, sequence: 99,
                    };
                    let wire = pkt.to_bytes();
                    let decoded = SyncPacket::from_bytes(&wire).unwrap();
                    assert_eq!(decoded.flags, flags);
                    assert_eq!(decoded.flags.to_byte(), flags.to_byte());
                }
            }
        }
    }

    /// A host dispatches CSI vs sync purely on the leading u32. The two
    /// magics must therefore never collide.
    #[test]
    fn sync_and_csi_magics_differ() {
        assert_ne!(SYNC_PACKET_MAGIC, crate::esp32_parser::ESP32_CSI_MAGIC);
    }

    #[test]
    fn wire_size_constant_is_correct() {
        let pkt = SyncPacket {
            node_id: 0, proto_ver: 1, flags: SyncPacketFlags::default(),
            local_us: 0, epoch_us: 0, sequence: 0,
        };
        assert_eq!(pkt.to_bytes().len(), SYNC_PACKET_SIZE);
        assert_eq!(SYNC_PACKET_SIZE, 32);
    }
}
