use crate::connection::{Channel, IpmiCommand, Message, NetFn, NotEnoughData};

use super::lan_types::{length, prefix};
use super::{
    Ipv6DynamicRouter, Ipv6LanBlock, Ipv6RouterControl, Ipv6TimingSupport,
    LanAlertDestinationAddress, LanAlertDestinationType, LanArpControl, LanBadPasswordThreshold,
    LanConfigError, LanIpv4Header, LanSetInProgress, LanVlanId,
};

/// Get LAN Configuration Parameters command.
///
/// Reference: IPMI 2.0 Specification, Table 23-3.
#[derive(Clone, Debug)]
pub struct GetLanConfigParameters {
    channel: Channel,
    parameter: LanConfigParameter,
    set_selector: u8,
    block_selector: u8,
    revision_only: bool,
}

impl GetLanConfigParameters {
    /// Create a new Get LAN Configuration Parameters command.
    pub fn new(channel: Channel, parameter: LanConfigParameter) -> Self {
        Self {
            channel,
            parameter,
            set_selector: 0,
            block_selector: 0,
            revision_only: false,
        }
    }

    /// Set the set selector used for parameters that have multiple entries.
    pub fn with_set_selector(mut self, set_selector: u8) -> Self {
        self.set_selector = set_selector;
        self
    }

    /// Set the block selector used for parameters that are paged.
    pub fn with_block_selector(mut self, block_selector: u8) -> Self {
        self.block_selector = block_selector;
        self
    }

    /// Return only the parameter revision when set to `true`.
    pub fn revision_only(mut self, revision_only: bool) -> Self {
        self.revision_only = revision_only;
        self
    }
}

impl From<GetLanConfigParameters> for Message {
    fn from(value: GetLanConfigParameters) -> Self {
        let channel = value.channel.value() & 0x0F;
        let channel = if value.revision_only {
            channel | 0x80
        } else {
            channel
        };
        Message::new_request(
            NetFn::Transport,
            0x02,
            vec![
                channel,
                value.parameter.value(),
                value.set_selector,
                value.block_selector,
            ],
        )
    }
}

impl IpmiCommand for GetLanConfigParameters {
    type Output = LanConfigParameterResponse;
    type Error = LanConfigError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() {
            return Err(LanConfigError::MissingRevision);
        }

        Ok(LanConfigParameterResponse {
            parameter_revision: data[0],
            data: data[1..].to_vec(),
        })
    }
}

/// LAN configuration parameters.
///
/// Reference: IPMI 2.0 Specification, Table 23-4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanConfigParameter {
    SetInProgress,
    AuthTypeSupport,
    AuthTypeEnables,
    IpAddress,
    IpAddressSource,
    MacAddress,
    SubnetMask,
    IpHeader,
    PrimaryRmcpPort,
    SecondaryRmcpPort,
    BmcArpControl,
    GratuitousArpInterval,
    DefaultGatewayAddress,
    DefaultGatewayMacAddress,
    BackupGatewayAddress,
    BackupGatewayMacAddress,
    SnmpCommunity,
    NumberOfAlertDestinations,
    AlertDestinationType,
    AlertDestinationAddress,
    VlanId,
    VlanPriority,
    CipherSuiteCount,
    CipherSuites,
    CipherSuitePrivilegeLevels,
    BadPasswordThreshold,
    Ipv6Ipv4Support,
    Ipv6Ipv4AddressingEnables,
    Ipv6HeaderStaticTrafficClass,
    Ipv6HeaderStaticHopLimit,
    Ipv6HeaderFlowLabel,
    Ipv6Status,
    Ipv6StaticAddresses,
    Ipv6StaticDuidStorageLength,
    Ipv6StaticDuid,
    Ipv6DynamicAddress,
    Ipv6DynamicDuidStorageLength,
    Ipv6DynamicDuid,
    Ipv6DhcpTimingSupport,
    Ipv6DhcpTiming,
    Ipv6RouterControl,
    Ipv6StaticRouter1Address,
    Ipv6StaticRouter1Mac,
    Ipv6StaticRouter1PrefixLength,
    Ipv6StaticRouter1Prefix,
    Ipv6StaticRouter2Address,
    Ipv6StaticRouter2Mac,
    Ipv6StaticRouter2PrefixLength,
    Ipv6StaticRouter2Prefix,
    Ipv6DynamicRouterCount,
    Ipv6DynamicRouterAddress,
    Ipv6DynamicRouterMac,
    Ipv6DynamicRouterPrefixLength,
    Ipv6DynamicRouterPrefix,
    Ipv6DynamicHopLimit,
    Ipv6NeighborDiscoverySlaacTimingSupport,
    Ipv6NeighborDiscoverySlaacTiming,
    /// Unrecognized/OEM parameter, returned as raw bytes.
    Other(u8),
}

impl LanConfigParameter {
    /// Get the raw parameter selector value.
    pub fn value(&self) -> u8 {
        match self {
            LanConfigParameter::SetInProgress => 0,
            LanConfigParameter::AuthTypeSupport => 1,
            LanConfigParameter::AuthTypeEnables => 2,
            LanConfigParameter::IpAddress => 3,
            LanConfigParameter::IpAddressSource => 4,
            LanConfigParameter::MacAddress => 5,
            LanConfigParameter::SubnetMask => 6,
            LanConfigParameter::IpHeader => 7,
            LanConfigParameter::PrimaryRmcpPort => 8,
            LanConfigParameter::SecondaryRmcpPort => 9,
            LanConfigParameter::BmcArpControl => 10,
            LanConfigParameter::GratuitousArpInterval => 11,
            LanConfigParameter::DefaultGatewayAddress => 12,
            LanConfigParameter::DefaultGatewayMacAddress => 13,
            LanConfigParameter::BackupGatewayAddress => 14,
            LanConfigParameter::BackupGatewayMacAddress => 15,
            LanConfigParameter::SnmpCommunity => 16,
            LanConfigParameter::NumberOfAlertDestinations => 17,
            LanConfigParameter::AlertDestinationType => 18,
            LanConfigParameter::AlertDestinationAddress => 19,
            LanConfigParameter::VlanId => 20,
            LanConfigParameter::VlanPriority => 21,
            LanConfigParameter::CipherSuiteCount => 22,
            LanConfigParameter::CipherSuites => 23,
            LanConfigParameter::CipherSuitePrivilegeLevels => 24,
            LanConfigParameter::BadPasswordThreshold => 26,
            LanConfigParameter::Ipv6Ipv4Support => 50,
            LanConfigParameter::Ipv6Ipv4AddressingEnables => 51,
            LanConfigParameter::Ipv6HeaderStaticTrafficClass => 52,
            LanConfigParameter::Ipv6HeaderStaticHopLimit => 53,
            LanConfigParameter::Ipv6HeaderFlowLabel => 54,
            LanConfigParameter::Ipv6Status => 55,
            LanConfigParameter::Ipv6StaticAddresses => 56,
            LanConfigParameter::Ipv6StaticDuidStorageLength => 57,
            LanConfigParameter::Ipv6StaticDuid => 58,
            LanConfigParameter::Ipv6DynamicAddress => 59,
            LanConfigParameter::Ipv6DynamicDuidStorageLength => 60,
            LanConfigParameter::Ipv6DynamicDuid => 61,
            LanConfigParameter::Ipv6DhcpTimingSupport => 62,
            LanConfigParameter::Ipv6DhcpTiming => 63,
            LanConfigParameter::Ipv6RouterControl => 64,
            LanConfigParameter::Ipv6StaticRouter1Address => 65,
            LanConfigParameter::Ipv6StaticRouter1Mac => 66,
            LanConfigParameter::Ipv6StaticRouter1PrefixLength => 67,
            LanConfigParameter::Ipv6StaticRouter1Prefix => 68,
            LanConfigParameter::Ipv6StaticRouter2Address => 69,
            LanConfigParameter::Ipv6StaticRouter2Mac => 70,
            LanConfigParameter::Ipv6StaticRouter2PrefixLength => 71,
            LanConfigParameter::Ipv6StaticRouter2Prefix => 72,
            LanConfigParameter::Ipv6DynamicRouterCount => 73,
            LanConfigParameter::Ipv6DynamicRouterAddress => 74,
            LanConfigParameter::Ipv6DynamicRouterMac => 75,
            LanConfigParameter::Ipv6DynamicRouterPrefixLength => 76,
            LanConfigParameter::Ipv6DynamicRouterPrefix => 77,
            LanConfigParameter::Ipv6DynamicHopLimit => 78,
            LanConfigParameter::Ipv6NeighborDiscoverySlaacTimingSupport => 79,
            LanConfigParameter::Ipv6NeighborDiscoverySlaacTiming => 80,
            LanConfigParameter::Other(value) => *value,
        }
    }

    /// Parse known LAN configuration parameter data.
    pub fn parse(&self, data: &[u8]) -> Result<LanConfigParameterData, LanConfigError> {
        use LanConfigParameterData::*;

        if matches!(self, LanConfigParameter::Other(_)) {
            return Ok(Raw(data.to_vec()));
        }

        let expected = match self {
            Self::AuthTypeEnables => 5,
            Self::IpAddress
            | Self::SubnetMask
            | Self::DefaultGatewayAddress
            | Self::BackupGatewayAddress
            | Self::AlertDestinationType => 4,
            Self::MacAddress
            | Self::DefaultGatewayMacAddress
            | Self::BackupGatewayMacAddress
            | Self::BadPasswordThreshold => 6,
            Self::IpHeader | Self::Ipv6HeaderFlowLabel | Self::Ipv6Status => 3,
            Self::PrimaryRmcpPort | Self::SecondaryRmcpPort | Self::VlanId => 2,
            Self::SnmpCommunity => 18,
            Self::AlertDestinationAddress => 0,
            Self::CipherSuites => 0,
            Self::CipherSuitePrivilegeLevels => 9,
            Self::Ipv6StaticAddresses | Self::Ipv6DynamicAddress => 20,
            Self::Ipv6StaticRouter1Address
            | Self::Ipv6StaticRouter1Prefix
            | Self::Ipv6StaticRouter2Address
            | Self::Ipv6StaticRouter2Prefix => 16,
            Self::Ipv6StaticRouter1Mac | Self::Ipv6StaticRouter2Mac => 6,
            Self::Ipv6DynamicRouterAddress | Self::Ipv6DynamicRouterPrefix => 17,
            Self::Ipv6DynamicRouterMac => 7,
            Self::Ipv6DynamicRouterPrefixLength => 2,
            Self::Ipv6StaticDuid
            | Self::Ipv6DynamicDuid
            | Self::Ipv6DhcpTiming
            | Self::Ipv6NeighborDiscoverySlaacTiming => 0,
            _ => 1,
        };
        if expected != 0 {
            length(data, expected)?;
        }
        let value = match self {
            Self::SetInProgress => SetInProgress(LanSetInProgress::parse(data[0])?),
            Self::AuthTypeSupport => AuthTypeSupport(data[0]),
            Self::AuthTypeEnables => AuthTypeEnables(data.try_into().expect("checked length")),
            LanConfigParameter::IpAddress => IpAddress(Ipv4Address::from_slice(data)?),
            LanConfigParameter::IpAddressSource => {
                if data[0] & 0xf0 != 0 {
                    return Err(LanConfigError::InvalidValue(data[0]));
                }
                IpAddressSource(self::IpAddressSource::from(data[0]))
            }
            LanConfigParameter::MacAddress => MacAddress(self::MacAddress::from_slice(data)?),
            LanConfigParameter::SubnetMask => SubnetMask(Ipv4Address::from_slice(data)?),
            Self::IpHeader => IpHeader(LanIpv4Header(data.try_into().expect("checked length"))),
            Self::PrimaryRmcpPort => PrimaryRmcpPort(u16::from_be_bytes([data[0], data[1]])),
            Self::SecondaryRmcpPort => SecondaryRmcpPort(u16::from_be_bytes([data[0], data[1]])),
            Self::BmcArpControl => BmcArpControl(LanArpControl {
                arp_responses: data[0] & 2 != 0,
                gratuitous_arp: data[0] & 1 != 0,
            }),
            Self::GratuitousArpInterval => GratuitousArpInterval(data[0]),
            LanConfigParameter::DefaultGatewayAddress => {
                DefaultGatewayAddress(Ipv4Address::from_slice(data)?)
            }
            LanConfigParameter::DefaultGatewayMacAddress => {
                DefaultGatewayMacAddress(self::MacAddress::from_slice(data)?)
            }
            LanConfigParameter::BackupGatewayAddress => {
                BackupGatewayAddress(Ipv4Address::from_slice(data)?)
            }
            LanConfigParameter::BackupGatewayMacAddress => {
                BackupGatewayMacAddress(self::MacAddress::from_slice(data)?)
            }
            Self::SnmpCommunity => SnmpCommunity(data.try_into().expect("checked length")),
            Self::NumberOfAlertDestinations => NumberOfAlertDestinations(data[0] & 0x0f),
            Self::AlertDestinationType => {
                AlertDestinationType(LanAlertDestinationType::parse(data)?)
            }
            Self::AlertDestinationAddress => {
                AlertDestinationAddress(LanAlertDestinationAddress::parse(data)?)
            }
            Self::VlanId => VlanId(LanVlanId::parse(data)?),
            Self::VlanPriority => VlanPriority(data[0] & 7),
            Self::CipherSuiteCount => CipherSuiteCount(data[0]),
            Self::CipherSuites => {
                if data.is_empty() || data.len() > 17 {
                    return Err(LanConfigError::InvalidLength {
                        expected: 17,
                        actual: data.len(),
                    });
                }
                CipherSuites(data.to_vec())
            }
            Self::CipherSuitePrivilegeLevels => {
                CipherSuitePrivilegeLevels(data.try_into().expect("checked length"))
            }
            Self::BadPasswordThreshold => {
                BadPasswordThreshold(LanBadPasswordThreshold::parse(data)?)
            }
            LanConfigParameter::Ipv6Ipv4Support => {
                Ipv6Ipv4Support(self::Ipv6Ipv4Support::from(data[0]))
            }
            LanConfigParameter::Ipv6Ipv4AddressingEnables => {
                Ipv6Ipv4AddressingEnables(Ipv6Ipv4Enables::from(data[0]))
            }
            LanConfigParameter::Ipv6HeaderStaticTrafficClass => {
                Ipv6HeaderStaticTrafficClass(data[0])
            }
            LanConfigParameter::Ipv6HeaderStaticHopLimit => Ipv6HeaderStaticHopLimit(data[0]),
            LanConfigParameter::Ipv6HeaderFlowLabel => {
                let raw = self::Ipv6HeaderFlowLabel::from_slice(data)?;
                if data[0] & 0xf0 != 0 {
                    return Err(LanConfigError::InvalidValue(data[0]));
                }
                Ipv6HeaderFlowLabel(raw)
            }
            LanConfigParameter::Ipv6Status => Ipv6Status(self::Ipv6Status::from_slice(data)?),
            LanConfigParameter::Ipv6StaticAddresses => {
                Ipv6StaticAddresses(Ipv6StaticAddress::from_slice(data)?)
            }
            LanConfigParameter::Ipv6DynamicAddress => {
                Ipv6DynamicAddress(self::Ipv6DynamicAddress::from_slice(data)?)
            }
            Self::Ipv6StaticDuidStorageLength => Ipv6StaticDuidStorageLength(data[0]),
            Self::Ipv6DynamicDuidStorageLength => Ipv6DynamicDuidStorageLength(data[0]),
            Self::Ipv6DhcpTimingSupport => Ipv6DhcpTimingSupport(data[0].try_into()?),
            Self::Ipv6NeighborDiscoverySlaacTimingSupport => {
                Ipv6NeighborDiscoverySlaacTimingSupport(data[0].try_into()?)
            }
            Self::Ipv6StaticDuid => Ipv6StaticDuid(Ipv6LanBlock::parse(data)?),
            Self::Ipv6DynamicDuid => Ipv6DynamicDuid(Ipv6LanBlock::parse(data)?),
            Self::Ipv6DhcpTiming => Ipv6DhcpTiming(Ipv6LanBlock::parse(data)?),
            Self::Ipv6NeighborDiscoverySlaacTiming => {
                Ipv6NeighborDiscoverySlaacTiming(Ipv6LanBlock::parse(data)?)
            }
            Self::Ipv6RouterControl => {
                if data[0] & !3 != 0 {
                    return Err(LanConfigError::InvalidValue(data[0]));
                }
                Ipv6RouterControl(self::Ipv6RouterControl {
                    static_routers: data[0] & 1 != 0,
                    dynamic_routers: data[0] & 2 != 0,
                })
            }
            Self::Ipv6StaticRouter1Address => {
                Ipv6StaticRouter1Address(Ipv6Address::from_slice(data)?)
            }
            Self::Ipv6StaticRouter2Address => {
                Ipv6StaticRouter2Address(Ipv6Address::from_slice(data)?)
            }
            Self::Ipv6StaticRouter1Mac => Ipv6StaticRouter1Mac(self::MacAddress::from_slice(data)?),
            Self::Ipv6StaticRouter2Mac => Ipv6StaticRouter2Mac(self::MacAddress::from_slice(data)?),
            Self::Ipv6StaticRouter1PrefixLength => {
                prefix(data[0])?;
                Ipv6StaticRouter1PrefixLength(data[0])
            }
            Self::Ipv6StaticRouter2PrefixLength => {
                prefix(data[0])?;
                Ipv6StaticRouter2PrefixLength(data[0])
            }
            Self::Ipv6StaticRouter1Prefix => {
                Ipv6StaticRouter1Prefix(Ipv6Address::from_slice(data)?)
            }
            Self::Ipv6StaticRouter2Prefix => {
                Ipv6StaticRouter2Prefix(Ipv6Address::from_slice(data)?)
            }
            Self::Ipv6DynamicRouterCount => Ipv6DynamicRouterCount(data[0]),
            Self::Ipv6DynamicRouterAddress => Ipv6DynamicRouterAddress(Ipv6DynamicRouter {
                set_selector: data[0],
                value: Ipv6Address::from_slice(&data[1..])?,
            }),
            Self::Ipv6DynamicRouterMac => Ipv6DynamicRouterMac(Ipv6DynamicRouter {
                set_selector: data[0],
                value: self::MacAddress::from_slice(&data[1..])?,
            }),
            Self::Ipv6DynamicRouterPrefixLength => {
                prefix(data[1])?;
                Ipv6DynamicRouterPrefixLength(Ipv6DynamicRouter {
                    set_selector: data[0],
                    value: data[1],
                })
            }
            Self::Ipv6DynamicRouterPrefix => Ipv6DynamicRouterPrefix(Ipv6DynamicRouter {
                set_selector: data[0],
                value: Ipv6Address::from_slice(&data[1..])?,
            }),
            Self::Ipv6DynamicHopLimit => Ipv6DynamicHopLimit(data[0]),
            _ => Raw(data.to_vec()),
        };

        Ok(value)
    }
}

/// LAN configuration response data.
#[derive(Clone, Debug, PartialEq)]
pub struct LanConfigParameterResponse {
    pub parameter_revision: u8,
    pub data: Vec<u8>,
}

impl LanConfigParameterResponse {
    /// Parse LAN parameter data using a known parameter selector.
    pub fn parse(
        &self,
        parameter: LanConfigParameter,
    ) -> Result<LanConfigParameterData, LanConfigError> {
        if !matches!(parameter, LanConfigParameter::Other(_)) && self.parameter_revision != 0x11 {
            return Err(LanConfigError::UnsupportedRevision(self.parameter_revision));
        }
        parameter.parse(&self.data)
    }

    /// Decode an entry and check its returned set/block selectors against the request.
    /// Unlike [`Self::parse`], this prevents silently accepting a different entry.
    pub fn parse_selected(
        &self,
        parameter: LanConfigParameter,
        set_selector: u8,
        block_selector: u8,
    ) -> Result<LanConfigParameterData, LanConfigError> {
        use LanConfigParameterData as D;
        let value = self.parse(parameter)?;
        let selected = match &value {
            D::AlertDestinationType(v) => Some((v.set_selector, None)),
            D::AlertDestinationAddress(LanAlertDestinationAddress::Ipv4 {
                set_selector, ..
            }) => Some((*set_selector, None)),
            D::AlertDestinationAddress(LanAlertDestinationAddress::Other(v)) => Some((v[0], None)),
            D::Ipv6StaticAddresses(v) => Some((v.set_selector, None)),
            D::Ipv6DynamicAddress(v) => Some((v.set_selector, None)),
            D::Ipv6StaticDuid(v)
            | D::Ipv6DynamicDuid(v)
            | D::Ipv6DhcpTiming(v)
            | D::Ipv6NeighborDiscoverySlaacTiming(v) => {
                Some((v.set_selector, Some(v.block_selector)))
            }
            D::Ipv6DynamicRouterAddress(v) | D::Ipv6DynamicRouterPrefix(v) => {
                Some((v.set_selector, None))
            }
            D::Ipv6DynamicRouterMac(v) => Some((v.set_selector, None)),
            D::Ipv6DynamicRouterPrefixLength(v) => Some((v.set_selector, None)),
            _ => None,
        };
        if let Some((set, block)) = selected {
            if set != set_selector || block.is_some_and(|b| b != block_selector) {
                return Err(LanConfigError::SelectorMismatch);
            }
        }
        Ok(value)
    }
}

/// LAN configuration parameter data variants.
#[derive(Clone, Debug, PartialEq)]
pub enum LanConfigParameterData {
    None,
    SetInProgress(LanSetInProgress),
    AuthTypeSupport(u8),
    AuthTypeEnables([u8; 5]),
    IpAddress(Ipv4Address),
    IpAddressSource(IpAddressSource),
    MacAddress(MacAddress),
    SubnetMask(Ipv4Address),
    IpHeader(LanIpv4Header),
    PrimaryRmcpPort(u16),
    SecondaryRmcpPort(u16),
    BmcArpControl(LanArpControl),
    GratuitousArpInterval(u8),
    DefaultGatewayAddress(Ipv4Address),
    DefaultGatewayMacAddress(MacAddress),
    BackupGatewayAddress(Ipv4Address),
    BackupGatewayMacAddress(MacAddress),
    SnmpCommunity([u8; 18]),
    NumberOfAlertDestinations(u8),
    AlertDestinationType(LanAlertDestinationType),
    AlertDestinationAddress(LanAlertDestinationAddress),
    VlanId(LanVlanId),
    VlanPriority(u8),
    CipherSuiteCount(u8),
    CipherSuites(Vec<u8>),
    CipherSuitePrivilegeLevels([u8; 9]),
    BadPasswordThreshold(LanBadPasswordThreshold),
    Ipv6Ipv4Support(Ipv6Ipv4Support),
    Ipv6Ipv4AddressingEnables(Ipv6Ipv4Enables),
    Ipv6HeaderStaticTrafficClass(u8),
    Ipv6HeaderStaticHopLimit(u8),
    Ipv6HeaderFlowLabel(Ipv6HeaderFlowLabel),
    Ipv6Status(Ipv6Status),
    Ipv6StaticAddresses(Ipv6StaticAddress),
    Ipv6StaticDuidStorageLength(u8),
    Ipv6StaticDuid(Ipv6LanBlock),
    Ipv6DynamicAddress(Ipv6DynamicAddress),
    Ipv6DynamicDuidStorageLength(u8),
    Ipv6DynamicDuid(Ipv6LanBlock),
    Ipv6DhcpTimingSupport(Ipv6TimingSupport),
    Ipv6DhcpTiming(Ipv6LanBlock),
    Ipv6RouterControl(Ipv6RouterControl),
    Ipv6StaticRouter1Address(Ipv6Address),
    Ipv6StaticRouter1Mac(MacAddress),
    Ipv6StaticRouter1PrefixLength(u8),
    Ipv6StaticRouter1Prefix(Ipv6Address),
    Ipv6StaticRouter2Address(Ipv6Address),
    Ipv6StaticRouter2Mac(MacAddress),
    Ipv6StaticRouter2PrefixLength(u8),
    Ipv6StaticRouter2Prefix(Ipv6Address),
    Ipv6DynamicRouterCount(u8),
    Ipv6DynamicRouterAddress(Ipv6DynamicRouter<Ipv6Address>),
    Ipv6DynamicRouterMac(Ipv6DynamicRouter<MacAddress>),
    Ipv6DynamicRouterPrefixLength(Ipv6DynamicRouter<u8>),
    Ipv6DynamicRouterPrefix(Ipv6DynamicRouter<Ipv6Address>),
    Ipv6DynamicHopLimit(u8),
    Ipv6NeighborDiscoverySlaacTimingSupport(Ipv6TimingSupport),
    Ipv6NeighborDiscoverySlaacTiming(Ipv6LanBlock),
    Raw(Vec<u8>),
}

/// IPv4 address representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Address(pub [u8; 4]);

impl Ipv4Address {
    fn from_slice(data: &[u8]) -> Result<Self, NotEnoughData> {
        if data.len() < 4 {
            return Err(NotEnoughData);
        }
        Ok(Ipv4Address([data[0], data[1], data[2], data[3]]))
    }
}

impl core::fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// MAC address representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    fn from_slice(data: &[u8]) -> Result<Self, NotEnoughData> {
        if data.len() < 6 {
            return Err(NotEnoughData);
        }
        Ok(MacAddress([
            data[0], data[1], data[2], data[3], data[4], data[5],
        ]))
    }
}

impl core::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// IPv6 address representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Address(pub [u8; 16]);

impl Ipv6Address {
    fn from_slice(data: &[u8]) -> Result<Self, NotEnoughData> {
        if data.len() < 16 {
            return Err(NotEnoughData);
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&data[..16]);
        Ok(Ipv6Address(buf))
    }
}

impl core::fmt::Display for Ipv6Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let addr = std::net::Ipv6Addr::from(self.0);
        write!(f, "{addr}")
    }
}

/// IP address source values.
///
/// Reference: IPMI 2.0 Specification, Table 23-4, parameter #4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpAddressSource {
    Unspecified,
    Static,
    Dhcp,
    BiosOrSystemSoftware,
    Other,
    Reserved(u8),
}

impl From<u8> for IpAddressSource {
    fn from(value: u8) -> Self {
        match value & 0x0F {
            0x00 => Self::Unspecified,
            0x01 => Self::Static,
            0x02 => Self::Dhcp,
            0x03 => Self::BiosOrSystemSoftware,
            0x04 => Self::Other,
            v => Self::Reserved(v),
        }
    }
}

impl From<IpAddressSource> for u8 {
    fn from(value: IpAddressSource) -> Self {
        match value {
            IpAddressSource::Unspecified => 0x00,
            IpAddressSource::Static => 0x01,
            IpAddressSource::Dhcp => 0x02,
            IpAddressSource::BiosOrSystemSoftware => 0x03,
            IpAddressSource::Other => 0x04,
            IpAddressSource::Reserved(v) => v & 0x0F,
        }
    }
}

/// IPv6/IPv4 support capabilities.
///
/// Reference: IPMI 2.0 Specification, Table 23-4, parameter #50.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Ipv4Support {
    pub ipv6_alerting_supported: bool,
    pub dual_stack_supported: bool,
    pub ipv6_only_supported: bool,
}

impl From<u8> for Ipv6Ipv4Support {
    fn from(value: u8) -> Self {
        Self {
            ipv6_alerting_supported: (value & 0x04) == 0x04,
            dual_stack_supported: (value & 0x02) == 0x02,
            ipv6_only_supported: (value & 0x01) == 0x01,
        }
    }
}

/// IPv6/IPv4 addressing enables.
///
/// Reference: IPMI 2.0 Specification, Table 23-4, parameter #51.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6Ipv4Enables {
    Ipv6Disabled,
    Ipv6Only,
    Ipv6Ipv4Simultaneous,
    Reserved(u8),
}

impl From<u8> for Ipv6Ipv4Enables {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Ipv6Disabled,
            0x01 => Self::Ipv6Only,
            0x02 => Self::Ipv6Ipv4Simultaneous,
            v => Self::Reserved(v),
        }
    }
}

impl From<Ipv6Ipv4Enables> for u8 {
    fn from(value: Ipv6Ipv4Enables) -> Self {
        match value {
            Ipv6Ipv4Enables::Ipv6Disabled => 0x00,
            Ipv6Ipv4Enables::Ipv6Only => 0x01,
            Ipv6Ipv4Enables::Ipv6Ipv4Simultaneous => 0x02,
            Ipv6Ipv4Enables::Reserved(v) => v,
        }
    }
}

impl core::fmt::Display for IpAddressSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IpAddressSource::Unspecified => write!(f, "Unspecified"),
            IpAddressSource::Static => write!(f, "Static"),
            IpAddressSource::Dhcp => write!(f, "DHCP"),
            IpAddressSource::BiosOrSystemSoftware => write!(f, "BIOS/System software"),
            IpAddressSource::Other => write!(f, "Other"),
            IpAddressSource::Reserved(v) => write!(f, "Reserved (0x{v:02X})"),
        }
    }
}

impl core::fmt::Display for Ipv6Ipv4Enables {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Ipv6Ipv4Enables::Ipv6Disabled => write!(f, "IPv6 disabled"),
            Ipv6Ipv4Enables::Ipv6Only => write!(f, "IPv6 only"),
            Ipv6Ipv4Enables::Ipv6Ipv4Simultaneous => write!(f, "IPv6/IPv4 simultaneous"),
            Ipv6Ipv4Enables::Reserved(v) => write!(f, "Reserved (0x{v:02X})"),
        }
    }
}

/// IPv6 header flow label (20-bit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6HeaderFlowLabel(pub u32);

impl Ipv6HeaderFlowLabel {
    fn from_slice(data: &[u8]) -> Result<Self, NotEnoughData> {
        if data.len() < 3 {
            return Err(NotEnoughData);
        }
        let raw = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
        Ok(Ipv6HeaderFlowLabel(raw & 0x000F_FFFF))
    }
}

/// IPv6 status capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Status {
    pub static_address_max: u8,
    pub dynamic_address_max: u8,
    pub slaac_supported: bool,
    pub dhcpv6_supported: bool,
}

impl Ipv6Status {
    fn from_slice(data: &[u8]) -> Result<Self, NotEnoughData> {
        if data.len() < 3 {
            return Err(NotEnoughData);
        }
        Ok(Ipv6Status {
            static_address_max: data[0],
            dynamic_address_max: data[1],
            slaac_supported: (data[2] & 0x02) == 0x02,
            dhcpv6_supported: (data[2] & 0x01) == 0x01,
        })
    }
}

/// IPv6 static address entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6StaticAddress {
    pub set_selector: u8,
    pub enabled: bool,
    pub source_type: u8,
    pub address: Ipv6Address,
    pub prefix_length: u8,
    pub status: u8,
}

impl Ipv6StaticAddress {
    fn from_slice(data: &[u8]) -> Result<Self, LanConfigError> {
        length(data, 20)?;

        let set_selector = data[0];
        let source_raw = data[1];
        let enabled = (source_raw & 0x80) == 0x80;
        let source_type = source_raw & 0x0F;

        let address = Ipv6Address::from_slice(&data[2..18])?;
        let prefix_length = data[18];
        prefix(prefix_length)?;
        let status = data[19];

        Ok(Ipv6StaticAddress {
            set_selector,
            enabled,
            source_type,
            address,
            prefix_length,
            status,
        })
    }
}

/// IPv6 dynamic address entry (SLAAC/DHCPv6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6DynamicAddress {
    pub set_selector: u8,
    pub source_type: u8,
    pub address: Ipv6Address,
    pub prefix_length: u8,
    pub status: u8,
}

impl Ipv6DynamicAddress {
    fn from_slice(data: &[u8]) -> Result<Self, LanConfigError> {
        length(data, 20)?;

        let set_selector = data[0];
        let source_type = data[1] & 0x0F;
        let address = Ipv6Address::from_slice(&data[2..18])?;
        let prefix_length = data[18];
        prefix(prefix_length)?;
        let status = data[19];

        Ok(Ipv6DynamicAddress {
            set_selector,
            source_type,
            address,
            prefix_length,
            status,
        })
    }
}
