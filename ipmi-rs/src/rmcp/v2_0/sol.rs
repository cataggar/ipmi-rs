//! SOL framing and per-authenticated-session flow control.

use std::collections::VecDeque;

/// Local cap on a single SOL character payload, independent of advertised limits.
pub(super) const MAX_SOL_DATA: usize = 255;
/// Maximum amount of console output waiting to be read.
pub(super) const MAX_OUTPUT_QUEUE: usize = 4096;

/// SOL payload framing errors (no console contents in diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolFrameError {
    /// Header truncated or character payload exceeded the local limit.
    InvalidLength,
    /// Reserved header bits, sequence, or accepted count invalid.
    InvalidHeader,
    /// Data changed while retransmitting the same SOL sequence number.
    ConflictingRetransmission,
    /// SOL data was skipped or arrived out of order.
    OutputGap,
    /// Acknowledgment claims more characters than were sent.
    InvalidAck,
    /// Negotiated outbound payload limit exceeded.
    ExceedsNegotiatedLimit,
    /// Remote SOL payload was deactivated.
    RemoteInactive,
    /// Remote transmit buffer overran; output has been lost.
    OutputOverrun,
}

/// Status bits in SOL's fourth header byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SolFlags {
    /// Negative acknowledgment.
    pub nack: bool,
    /// BMC cannot currently accept data.
    pub transfer_unavailable: bool,
    /// BMC deactivated SOL.
    pub inactive: bool,
    /// BMC lost characters due to a transmit overrun.
    pub overrun: bool,
    /// Serial break detected.
    pub break_detected: bool,
    /// Request a serial break; interactive mode only.
    pub generate_break: bool,
    /// Discard buffered BMC-to-console data; interactive mode only.
    pub flush_inbound: bool,
    /// Discard buffered console-to-BMC data; interactive mode only.
    pub flush_outbound: bool,
}

impl SolFlags {
    fn decode(value: u8) -> Result<Self, SolFrameError> {
        if value & 0x83 != 0 {
            return Err(SolFrameError::InvalidHeader);
        }
        Ok(Self {
            nack: value & 0x40 != 0,
            transfer_unavailable: value & 0x20 != 0,
            inactive: value & 0x10 != 0,
            overrun: value & 0x08 != 0,
            break_detected: value & 0x04 != 0,
            ..Self::default()
        })
    }

    fn encode(self) -> u8 {
        u8::from(self.nack) << 6
            | u8::from(self.transfer_unavailable) << 5
            | u8::from(self.inactive) << 4
            | u8::from(self.overrun) << 3
            | u8::from(self.break_detected) << 2
            | u8::from(self.generate_break) << 4
            | u8::from(self.flush_inbound) << 1
            | u8::from(self.flush_outbound)
    }
}

/// A decrypted SOL packet; 4 header bytes followed by console characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolFrame {
    /// Data sequence (1..15); zero means no data.
    pub sequence: u8,
    /// Sequence being acknowledged (zero means no ACK).
    pub ack: u8,
    /// Number of characters accepted from the acknowledged sequence.
    pub accepted: u8,
    /// SOL status or interactive control flags.
    pub flags: SolFlags,
    /// Characters sent with this frame.
    pub data: Vec<u8>,
}

impl SolFrame {
    /// Decode an authenticated, decrypted SOL payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, SolFrameError> {
        if !(4..=MAX_SOL_DATA + 4).contains(&bytes.len()) {
            return Err(SolFrameError::InvalidLength);
        }
        if bytes[0] & 0xf0 != 0 || bytes[1] & 0xf0 != 0 {
            return Err(SolFrameError::InvalidHeader);
        }
        let frame = Self {
            sequence: bytes[0],
            ack: bytes[1],
            accepted: bytes[2],
            flags: SolFlags::decode(bytes[3])?,
            data: bytes[4..].to_vec(),
        };
        if (frame.ack == 0 && frame.accepted != 0)
            || (frame.sequence == 0 && !frame.data.is_empty())
        {
            return Err(SolFrameError::InvalidHeader);
        }
        Ok(frame)
    }

    /// Encode a SOL header and bounded character payload.
    pub fn encode(&self) -> Result<Vec<u8>, SolFrameError> {
        if self.sequence > 15
            || self.ack > 15
            || self.data.len() > MAX_SOL_DATA
            || (self.sequence == 0 && !self.data.is_empty())
            || (self.ack == 0 && self.accepted != 0)
        {
            return Err(SolFrameError::InvalidHeader);
        }
        let mut bytes = Vec::with_capacity(self.data.len() + 4);
        bytes.extend([self.sequence, self.ack, self.accepted, self.flags.encode()]);
        bytes.extend(&self.data);
        Ok(bytes)
    }

    pub(super) fn ack(sequence: u8, accepted: usize, nack: bool) -> Self {
        Self {
            sequence: 0,
            ack: sequence,
            accepted: accepted as u8,
            flags: SolFlags {
                nack,
                ..SolFlags::default()
            },
            data: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(in crate::rmcp) struct InputAck {
    pub accepted: u8,
    pub nack: bool,
    pub unavailable: bool,
}

#[derive(Debug)]
pub(in crate::rmcp) struct SolFlow {
    output: VecDeque<u8>,
    previous_sequence: Option<u8>,
    previous_data: Vec<u8>,
    previous_accepted: usize,
    pub next_input_sequence: u8,
    pub waiting_for_ack: Option<u8>,
    pub input_ack: Option<InputAck>,
    pub max_input: usize,
    pub max_output: usize,
}

impl SolFlow {
    pub fn new(max_input: usize, max_output: usize) -> Self {
        Self {
            output: VecDeque::with_capacity(MAX_OUTPUT_QUEUE),
            previous_sequence: None,
            previous_data: Vec::new(),
            previous_accepted: 0,
            next_input_sequence: 1,
            waiting_for_ack: None,
            input_ack: None,
            max_input: max_input.min(MAX_SOL_DATA + 4),
            max_output: max_output.min(MAX_SOL_DATA + 4),
        }
    }

    pub fn read(&mut self, bytes: &mut [u8]) -> usize {
        let count = bytes.len().min(self.output.len());
        for slot in &mut bytes[..count] {
            *slot = self.output.pop_front().expect("queue length checked");
        }
        count
    }

    pub fn has_output(&self) -> bool {
        !self.output.is_empty()
    }

    pub fn next_sequence(&mut self) -> u8 {
        let current = self.next_input_sequence;
        self.next_input_sequence = if current == 15 { 1 } else { current + 1 };
        current
    }

    /// Apply an authenticated frame and produce the protocol ACK if it has a
    /// nonzero data sequence. ACK-only frames never cause an ACK-of-an-ACK.
    pub fn accept(&mut self, frame: &SolFrame) -> Result<Option<SolFrame>, SolFrameError> {
        if frame.data.len() + 4 > self.max_output {
            return Err(SolFrameError::ExceedsNegotiatedLimit);
        }
        if let Some(waiting) = self.waiting_for_ack {
            if frame.ack == waiting {
                // Validation of count relative to the outstanding payload is
                // performed by the sender, before any suffix is retransmitted.
                self.input_ack = Some(InputAck {
                    accepted: frame.accepted,
                    nack: frame.flags.nack,
                    unavailable: frame.flags.transfer_unavailable,
                });
            }
        }
        if frame.sequence == 0 {
            return Ok(None);
        }

        if let Some(previous) = self.previous_sequence {
            if frame.sequence == previous {
                let common = self.previous_accepted.min(frame.data.len());
                if frame.data[..common] != self.previous_data[..common] {
                    return Err(SolFrameError::ConflictingRetransmission);
                }
                if frame.data.len() < self.previous_accepted {
                    return Ok(Some(SolFrame::ack(frame.sequence, frame.data.len(), false)));
                }
            } else if frame.sequence != if previous == 15 { 1 } else { previous + 1 }
                || (self.previous_accepted < self.previous_data.len()
                    && !frame
                        .data
                        .starts_with(&self.previous_data[self.previous_accepted..]))
            {
                return Err(SolFrameError::OutputGap);
            } else {
                self.previous_accepted = 0;
            }
        }
        let newly_available = frame.data.len().saturating_sub(self.previous_accepted);
        let accepted = newly_available
            .min(MAX_OUTPUT_QUEUE - self.output.len())
            .min(u8::MAX as usize - self.previous_accepted);
        let end = self.previous_accepted + accepted;
        self.output
            .extend(frame.data[self.previous_accepted..end].iter().copied());
        self.previous_sequence = Some(frame.sequence);
        self.previous_data.clone_from(&frame.data);
        self.previous_accepted = end;
        Ok(Some(SolFrame::ack(
            frame.sequence,
            self.previous_accepted,
            self.previous_accepted < frame.data.len(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(seq: u8, bytes: &[u8]) -> SolFrame {
        SolFrame::decode(&[&[seq, 0, 0, 0][..], bytes].concat()).unwrap()
    }

    #[test]
    fn exact_framing_ack_and_resend_suffix() {
        let mut flow = SolFlow::new(128, 128);
        assert_eq!(data(1, b"ab").encode().unwrap(), [1, 0, 0, 0, b'a', b'b']);
        assert_eq!(
            flow.accept(&data(1, b"ab"))
                .unwrap()
                .unwrap()
                .encode()
                .unwrap(),
            [0, 1, 2, 0]
        );
        flow.accept(&data(1, b"ab")).unwrap();
        flow.accept(&data(1, b"abcd")).unwrap();
        let mut output = [0; 8];
        assert_eq!(flow.read(&mut output), 4);
        assert_eq!(&output[..4], b"abcd");
        assert_eq!(flow.next_sequence(), 1);
        flow.next_input_sequence = 15;
        assert_eq!(flow.next_sequence(), 15);
        assert_eq!(flow.next_sequence(), 1);
        flow.previous_sequence = Some(15);
        flow.previous_data = b"abcd".to_vec();
        flow.previous_accepted = 4;
        assert!(flow.accept(&data(1, b"e")).is_ok());
    }

    #[test]
    fn reordered_conflicting_and_full_queue() {
        let mut flow = SolFlow::new(128, 128);
        flow.accept(&data(1, b"a")).unwrap();
        assert_eq!(
            flow.accept(&data(3, b"b")).unwrap_err(),
            SolFrameError::OutputGap
        );
        assert_eq!(
            flow.accept(&data(1, b"b")).unwrap_err(),
            SolFrameError::ConflictingRetransmission
        );
        flow.output
            .extend(std::iter::repeat_n(0, MAX_OUTPUT_QUEUE - 2));
        let ack = flow.accept(&data(2, b"xy")).unwrap().unwrap();
        assert_eq!(ack.accepted, 1);
        assert!(ack.flags.nack);
        assert_eq!(
            flow.accept(&data(3, b"z")).unwrap_err(),
            SolFrameError::OutputGap
        );
        let mut out = vec![0; MAX_OUTPUT_QUEUE];
        assert_eq!(flow.read(&mut out), MAX_OUTPUT_QUEUE);
        assert_eq!(flow.accept(&data(2, b"xy")).unwrap().unwrap().accepted, 2);
    }

    #[test]
    fn malformed_and_ack_only_are_bounded() {
        for bytes in [
            &[0, 0, 0][..],
            &[0, 0, 1, 0],
            &[0, 0, 0, 0, 1],
            &[0x10, 0, 0, 0],
            &[0, 0x10, 0, 0],
            &[0, 0, 0, 0x80],
        ] {
            assert!(SolFrame::decode(bytes).is_err());
        }
        assert!(matches!(
            SolFrame::decode(&vec![0; MAX_SOL_DATA + 5]),
            Err(SolFrameError::InvalidLength)
        ));
        let mut flow = SolFlow::new(128, 128);
        assert!(flow
            .accept(&SolFrame::decode(&[0, 1, 0, 0]).unwrap())
            .unwrap()
            .is_none());
    }
}
