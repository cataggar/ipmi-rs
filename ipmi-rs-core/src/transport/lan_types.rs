//! Shared, checked representations of LAN configuration wire values.

use super::{Ipv4Address, Ipv6Address, MacAddress};

/// Invalid LAN parameter or wire response. A failed write may still have taken effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanConfigError {
    /// The response did not include the parameter revision.
    MissingRevision,
    /// The parameter revision is not IPMI 2.0 revision 1.1.
    UnsupportedRevision(u8),
    /// An exact-length value (or a bounded block) had the wrong length.
    InvalidLength { expected: usize, actual: usize },
    /// A value contained an invalid bit field.
    InvalidValue(u8),
    /// The IPv6 prefix length was greater than 128.
    InvalidPrefix(u8),
    /// The selected parameter and typed request do not match.
    MismatchedParameter,
    /// A multi-block value was missing, out of order, or inconsistent.
    InvalidBlockSequence,
    /// A selector-addressed response belongs to a different set or block.
    SelectorMismatch,
    /// An existing legacy address parser found too few bytes.
    Truncated,
}

impl From<crate::connection::NotEnoughData> for LanConfigError {
    fn from(_: crate::connection::NotEnoughData) -> Self {
        Self::Truncated
    }
}

pub(super) fn length(data: &[u8], expected: usize) -> Result<(), LanConfigError> {
    if data.len() == expected {
        Ok(())
    } else {
        Err(LanConfigError::InvalidLength {
            expected,
            actual: data.len(),
        })
    }
}

pub(super) fn prefix(value: u8) -> Result<(), LanConfigError> {
    if value <= 128 {
        Ok(())
    } else {
        Err(LanConfigError::InvalidPrefix(value))
    }
}

/// Set-in-progress protocol states (LAN parameter 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanSetInProgress {
    Complete,
    InProgress,
    CommitWrite,
}

impl LanSetInProgress {
    pub(crate) fn byte(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::InProgress => 1,
            Self::CommitWrite => 2,
        }
    }

    pub(crate) fn parse(value: u8) -> Result<Self, LanConfigError> {
        match value & 3 {
            0 => Ok(Self::Complete),
            1 => Ok(Self::InProgress),
            2 => Ok(Self::CommitWrite),
            _ => Err(LanConfigError::InvalidValue(value)),
        }
    }
}

/// IPv4 header settings (TTL, flags, precedence/TOS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanIpv4Header(pub [u8; 3]);

/// BMC ARP replies and gratuitous ARP settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanArpControl {
    pub arp_responses: bool,
    pub gratuitous_arp: bool,
}

impl LanArpControl {
    pub(crate) fn byte(self) -> u8 {
        u8::from(self.arp_responses) << 1 | u8::from(self.gratuitous_arp)
    }
}

/// An optional 802.1q VLAN tag. Enabled IDs must be in 1..=4094;
/// disabled ID 0 is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanVlanId {
    pub enabled: bool,
    pub id: u16,
}

impl LanVlanId {
    pub(crate) fn bytes(self) -> Result<[u8; 2], LanConfigError> {
        if (self.enabled && self.id == 0) || self.id > 4094 {
            return Err(LanConfigError::InvalidValue((self.id & 0xff) as u8));
        }
        let id = self.id.to_le_bytes();
        Ok([id[0], id[1] | if self.enabled { 0x80 } else { 0 }])
    }

    pub(crate) fn parse(data: &[u8]) -> Result<Self, LanConfigError> {
        length(data, 2)?;
        let enabled = data[1] & 0x80 != 0;
        let id = u16::from_le_bytes([data[0], data[1] & 0x0f]);
        // Some BMCs use zero when the VLAN is disabled.
        if (enabled && !(1..=4094).contains(&id)) || id > 4094 {
            return Err(LanConfigError::InvalidValue(data[1]));
        }
        Ok(Self { enabled, id })
    }
}

/// Invalid-password policy. Intervals are expressed in tens of seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanBadPasswordThreshold {
    pub generate_audit_event: bool,
    pub threshold: u8,
    pub reset_interval: u16,
    pub lockout_interval: u16,
}

impl LanBadPasswordThreshold {
    pub(crate) fn bytes(self) -> [u8; 6] {
        let reset = self.reset_interval.to_le_bytes();
        let lockout = self.lockout_interval.to_le_bytes();
        [
            u8::from(self.generate_audit_event),
            self.threshold,
            reset[0],
            reset[1],
            lockout[0],
            lockout[1],
        ]
    }

    pub(crate) fn parse(data: &[u8]) -> Result<Self, LanConfigError> {
        length(data, 6)?;
        Ok(Self {
            generate_audit_event: data[0] & 1 != 0,
            threshold: data[1],
            reset_interval: u16::from_le_bytes([data[2], data[3]]),
            lockout_interval: u16::from_le_bytes([data[4], data[5]]),
        })
    }
}

/// LAN alert destination type, parameter 18. The set selector is part of the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanAlertDestinationType {
    pub set_selector: u8,
    pub acknowledged: bool,
    /// 0=PET, 6=OEM1, 7=OEM2; other 3-bit values are retained.
    pub destination_type: u8,
    pub timeout: u8,
    pub retries: u8,
}

impl LanAlertDestinationType {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, LanConfigError> {
        length(data, 4)?;
        if data[0] > 15 {
            return Err(LanConfigError::InvalidValue(data[0]));
        }
        Ok(Self {
            set_selector: data[0],
            acknowledged: data[1] & 0x80 != 0,
            destination_type: data[1] & 7,
            timeout: data[2],
            retries: data[3] & 7,
        })
    }

    pub(crate) fn bytes(self) -> Result<[u8; 4], LanConfigError> {
        if self.set_selector > 15 || self.destination_type > 7 || self.retries > 7 {
            return Err(LanConfigError::InvalidValue(
                self.set_selector
                    .max(self.destination_type)
                    .max(self.retries),
            ));
        }
        Ok([
            self.set_selector,
            u8::from(self.acknowledged) << 7 | self.destination_type,
            self.timeout,
            self.retries,
        ])
    }
}

/// LAN alert destination address, parameter 19. Unknown formats remain opaque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LanAlertDestinationAddress {
    Ipv4 {
        set_selector: u8,
        backup_gateway: bool,
        address: Ipv4Address,
        mac: MacAddress,
    },
    /// Preserve the full variable-length payload for an unrecognized address format.
    Other(Vec<u8>),
}

impl LanAlertDestinationAddress {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, LanConfigError> {
        if data.len() < 2 {
            return Err(LanConfigError::InvalidLength {
                expected: 2,
                actual: data.len(),
            });
        }
        if data[1] & 0xf0 != 0 {
            return Ok(Self::Other(data.to_vec()));
        }
        length(data, 13)?;
        let bytes: [u8; 13] = data.try_into().expect("checked length");
        if bytes[0] > 15 {
            return Err(LanConfigError::InvalidValue(bytes[0]));
        }
        Ok(Self::Ipv4 {
            set_selector: bytes[0],
            backup_gateway: bytes[2] & 1 != 0,
            address: Ipv4Address(bytes[3..7].try_into().expect("checked length")),
            mac: MacAddress(bytes[7..13].try_into().expect("checked length")),
        })
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Other(bytes) => bytes.clone(),
            Self::Ipv4 {
                set_selector,
                backup_gateway,
                address,
                mac,
            } => {
                let mut bytes = [0; 13];
                bytes[0] = *set_selector;
                bytes[2] = u8::from(*backup_gateway);
                bytes[3..7].copy_from_slice(&address.0);
                bytes[7..13].copy_from_slice(&mac.0);
                bytes.to_vec()
            }
        }
    }
}

/// IPv6 static/dynamic router enablement (parameter 64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6RouterControl {
    pub static_routers: bool,
    pub dynamic_routers: bool,
}

/// DHCPv6/ND-SLAAC timing configuration support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6TimingSupport {
    NotSupported,
    Global,
    PerInterface,
}

impl TryFrom<u8> for Ipv6TimingSupport {
    type Error = LanConfigError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NotSupported),
            1 => Ok(Self::Global),
            2 => Ok(Self::PerInterface),
            other => Err(LanConfigError::InvalidValue(other)),
        }
    }
}

impl Ipv6RouterControl {
    pub(crate) fn byte(self) -> u8 {
        u8::from(self.static_routers) | u8::from(self.dynamic_routers) << 1
    }
}

/// A single selector-addressed, possibly short, 16-byte IPv6 LAN block.
///
/// Both selectors are explicit. A DUID uses consecutive blocks, with its
/// total length in the first byte of block zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6LanBlock {
    pub set_selector: u8,
    pub block_selector: u8,
    pub bytes: Vec<u8>,
}

impl Ipv6LanBlock {
    /// Validate a block before sending it (or decoding a response).
    pub fn new(
        set_selector: u8,
        block_selector: u8,
        bytes: Vec<u8>,
    ) -> Result<Self, LanConfigError> {
        if bytes.len() > 16 {
            return Err(LanConfigError::InvalidLength {
                expected: 16,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            set_selector,
            block_selector,
            bytes,
        })
    }

    pub(crate) fn parse(data: &[u8]) -> Result<Self, LanConfigError> {
        if data.len() < 2 || data.len() > 18 {
            return Err(LanConfigError::InvalidLength {
                expected: 18,
                actual: data.len(),
            });
        }
        Self::new(data[0], data[1], data[2..].to_vec())
    }

    pub(crate) fn wire(&self) -> Vec<u8> {
        let mut bytes = vec![self.set_selector, self.block_selector];
        bytes.extend_from_slice(&self.bytes);
        bytes
    }
}

/// An assembled DHCPv6 DUID, with the advertised byte count checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Duid {
    pub set_selector: u8,
    pub bytes: Vec<u8>,
}

impl Ipv6Duid {
    /// Assemble ordered blocks. The first block starts with the DUID length.
    pub fn from_blocks(blocks: &[Ipv6LanBlock]) -> Result<Self, LanConfigError> {
        let Some(first) = blocks.first() else {
            return Err(LanConfigError::InvalidBlockSequence);
        };
        if first.block_selector != 0 || first.bytes.is_empty() {
            return Err(LanConfigError::InvalidBlockSequence);
        }
        let len = first.bytes[0] as usize;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first.bytes[1..]);
        for (index, block) in blocks.iter().enumerate().skip(1) {
            if block.set_selector != first.set_selector
                || block.block_selector as usize != index
                || block.bytes.len() > 16
                || (index + 1 < blocks.len() && block.bytes.len() != 16)
            {
                return Err(LanConfigError::InvalidBlockSequence);
            }
            bytes.extend_from_slice(&block.bytes);
        }
        if blocks.len() > 1 && first.bytes.len() != 16 {
            return Err(LanConfigError::InvalidBlockSequence);
        }
        if bytes.len() < len || bytes.len() > len + 15 || blocks.len() > 16 {
            return Err(LanConfigError::InvalidBlockSequence);
        }
        bytes.truncate(len);
        Ok(Self {
            set_selector: first.set_selector,
            bytes,
        })
    }

    /// Split a DUID into consecutive set/block-addressed writes.
    pub fn blocks(&self) -> Result<Vec<Ipv6LanBlock>, LanConfigError> {
        let len: u8 = self
            .bytes
            .len()
            .try_into()
            .map_err(|_| LanConfigError::InvalidLength {
                expected: 255,
                actual: self.bytes.len(),
            })?;
        let mut payload = vec![len];
        payload.extend_from_slice(&self.bytes);
        payload
            .chunks(16)
            .enumerate()
            .map(|(block, bytes)| Ipv6LanBlock::new(self.set_selector, block as u8, bytes.to_vec()))
            .collect()
    }
}

/// DHCPv6 timing configuration (parameter 63), split across blocks 0 and 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6DhcpTiming {
    pub set_selector: u8,
    /// 16 bytes in block 0 and 6 bytes in block 1.
    pub values: [u8; 22],
}

impl Ipv6DhcpTiming {
    /// Combine two matching, ordered blocks.
    pub fn from_blocks(
        first: &Ipv6LanBlock,
        second: &Ipv6LanBlock,
    ) -> Result<Self, LanConfigError> {
        if first.set_selector != second.set_selector
            || first.block_selector != 0
            || second.block_selector != 1
        {
            return Err(LanConfigError::InvalidBlockSequence);
        }
        length(&first.bytes, 16)?;
        length(&second.bytes, 6)?;
        let mut values = [0; 22];
        values[..16].copy_from_slice(&first.bytes);
        values[16..].copy_from_slice(&second.bytes);
        Ok(Self {
            set_selector: first.set_selector,
            values,
        })
    }

    /// Return the two individually addressable wire blocks.
    pub fn blocks(self) -> [Ipv6LanBlock; 2] {
        [
            Ipv6LanBlock {
                set_selector: self.set_selector,
                block_selector: 0,
                bytes: self.values[..16].to_vec(),
            },
            Ipv6LanBlock {
                set_selector: self.set_selector,
                block_selector: 1,
                bytes: self.values[16..].to_vec(),
            },
        ]
    }
}

/// A selector-addressed IPv6 dynamic router component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6DynamicRouter<T> {
    pub set_selector: u8,
    pub value: T,
}

/// Four independently addressable IPv6 router components.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Router {
    pub address: Ipv6Address,
    pub mac: MacAddress,
    pub prefix_length: u8,
    pub prefix: Ipv6Address,
}

impl Ipv6Router {
    /// Check the prefix length before using a router for configuration.
    pub fn validate(self) -> Result<Self, LanConfigError> {
        prefix(self.prefix_length)?;
        Ok(self)
    }
}
