use crate::connection::{Channel, IpmiCommand, Message, NetFn};

use super::lan_types::prefix;
use super::{
    IpAddressSource, Ipv4Address, Ipv6Address, Ipv6Ipv4Enables, Ipv6LanBlock, Ipv6RouterControl,
    LanAlertDestinationAddress, LanAlertDestinationType, LanArpControl, LanBadPasswordThreshold,
    LanConfigError, LanConfigParameter, LanIpv4Header, LanSetInProgress, LanVlanId, MacAddress,
};

/// Set LAN Configuration Parameters command.
///
/// Reference: IPMI 2.0 Specification, Table 23-2.
#[derive(Clone, Debug)]
pub struct SetLanConfigParameters {
    channel: Channel,
    parameter: LanConfigParameter,
    data: Vec<u8>,
}

impl SetLanConfigParameters {
    /// Create a new Set LAN Configuration Parameters command.
    pub fn new(channel: Channel, parameter: LanConfigParameter, data: Vec<u8>) -> Self {
        Self {
            channel,
            parameter,
            data,
        }
    }

    /// Create a Set LAN Configuration Parameters command from a typed request.
    pub fn from_request(
        channel: Channel,
        parameter: LanConfigParameter,
        request: LanConfigParameterRequest,
    ) -> Self {
        Self::new(channel, parameter, request.to_bytes())
    }

    /// Build a validated typed write, inferring its parameter from the value.
    /// For an unrecognized parameter use [`Self::new`] explicitly.
    pub fn checked(
        channel: Channel,
        request: LanConfigParameterRequest,
    ) -> Result<Self, LanConfigError> {
        let parameter = request
            .parameter()
            .ok_or(LanConfigError::MismatchedParameter)?;
        let data = request.try_to_bytes()?;
        Ok(Self::new(channel, parameter, data))
    }
}

impl From<SetLanConfigParameters> for Message {
    fn from(value: SetLanConfigParameters) -> Self {
        let channel = value.channel.value() & 0x0F;
        let mut payload = Vec::with_capacity(2 + value.data.len());
        payload.push(channel);
        payload.push(value.parameter.value());
        payload.extend_from_slice(&value.data);
        Message::new_request(NetFn::Transport, 0x01, payload)
    }
}

impl IpmiCommand for SetLanConfigParameters {
    type Output = ();
    type Error = LanConfigError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        super::lan_types::length(data, 0)
    }
}

/// LAN configuration parameter request payloads.
#[derive(Clone, Debug, PartialEq)]
pub enum LanConfigParameterRequest {
    /// Legacy byte-valued state; checked writes only accept values 0, 1, and 2.
    SetInProgress(u8),
    SetState(LanSetInProgress),
    AuthTypeEnables([u8; 5]),
    IpAddress(Ipv4Address),
    IpAddressSource(u8),
    AddressSource(IpAddressSource),
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
    AlertDestinationType(LanAlertDestinationType),
    AlertDestinationAddress(LanAlertDestinationAddress),
    VlanId(LanVlanId),
    VlanPriority(u8),
    CipherSuitePrivilegeLevels([u8; 9]),
    BadPasswordThreshold(LanBadPasswordThreshold),
    Ipv6Ipv4AddressingEnables(Ipv6Ipv4Enables),
    Ipv6HeaderStaticTrafficClass(u8),
    Ipv6HeaderStaticHopLimit(u8),
    Ipv6HeaderFlowLabel(super::Ipv6HeaderFlowLabel),
    Ipv6StaticAddress {
        set_selector: u8,
        enabled: bool,
        source_type: u8,
        address: Ipv6Address,
        prefix_length: u8,
        status: u8,
    },
    Ipv6StaticDuid(Ipv6LanBlock),
    Ipv6DynamicDuid(Ipv6LanBlock),
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
    Ipv6NdSlaacTiming(Ipv6LanBlock),
    /// Raw escape hatch, used with an explicit selector through `from_request`.
    Raw(Vec<u8>),
}

impl LanConfigParameterRequest {
    /// Parameter associated with a typed value. Raw writes require an explicit parameter.
    pub fn parameter(&self) -> Option<LanConfigParameter> {
        use LanConfigParameter as P;
        Some(match self {
            Self::SetInProgress(_) | Self::SetState(_) => P::SetInProgress,
            Self::AuthTypeEnables(_) => P::AuthTypeEnables,
            Self::IpAddress(_) => P::IpAddress,
            Self::IpAddressSource(_) | Self::AddressSource(_) => P::IpAddressSource,
            Self::MacAddress(_) => P::MacAddress,
            Self::SubnetMask(_) => P::SubnetMask,
            Self::IpHeader(_) => P::IpHeader,
            Self::PrimaryRmcpPort(_) => P::PrimaryRmcpPort,
            Self::SecondaryRmcpPort(_) => P::SecondaryRmcpPort,
            Self::BmcArpControl(_) => P::BmcArpControl,
            Self::GratuitousArpInterval(_) => P::GratuitousArpInterval,
            Self::DefaultGatewayAddress(_) => P::DefaultGatewayAddress,
            Self::DefaultGatewayMacAddress(_) => P::DefaultGatewayMacAddress,
            Self::BackupGatewayAddress(_) => P::BackupGatewayAddress,
            Self::BackupGatewayMacAddress(_) => P::BackupGatewayMacAddress,
            Self::SnmpCommunity(_) => P::SnmpCommunity,
            Self::AlertDestinationType(_) => P::AlertDestinationType,
            Self::AlertDestinationAddress(_) => P::AlertDestinationAddress,
            Self::VlanId(_) => P::VlanId,
            Self::VlanPriority(_) => P::VlanPriority,
            Self::CipherSuitePrivilegeLevels(_) => P::CipherSuitePrivilegeLevels,
            Self::BadPasswordThreshold(_) => P::BadPasswordThreshold,
            Self::Ipv6Ipv4AddressingEnables(_) => P::Ipv6Ipv4AddressingEnables,
            Self::Ipv6HeaderStaticTrafficClass(_) => P::Ipv6HeaderStaticTrafficClass,
            Self::Ipv6HeaderStaticHopLimit(_) => P::Ipv6HeaderStaticHopLimit,
            Self::Ipv6HeaderFlowLabel(_) => P::Ipv6HeaderFlowLabel,
            Self::Ipv6StaticAddress { .. } => P::Ipv6StaticAddresses,
            Self::Ipv6StaticDuid(_) => P::Ipv6StaticDuid,
            Self::Ipv6DynamicDuid(_) => P::Ipv6DynamicDuid,
            Self::Ipv6DhcpTiming(_) => P::Ipv6DhcpTiming,
            Self::Ipv6RouterControl(_) => P::Ipv6RouterControl,
            Self::Ipv6StaticRouter1Address(_) => P::Ipv6StaticRouter1Address,
            Self::Ipv6StaticRouter1Mac(_) => P::Ipv6StaticRouter1Mac,
            Self::Ipv6StaticRouter1PrefixLength(_) => P::Ipv6StaticRouter1PrefixLength,
            Self::Ipv6StaticRouter1Prefix(_) => P::Ipv6StaticRouter1Prefix,
            Self::Ipv6StaticRouter2Address(_) => P::Ipv6StaticRouter2Address,
            Self::Ipv6StaticRouter2Mac(_) => P::Ipv6StaticRouter2Mac,
            Self::Ipv6StaticRouter2PrefixLength(_) => P::Ipv6StaticRouter2PrefixLength,
            Self::Ipv6StaticRouter2Prefix(_) => P::Ipv6StaticRouter2Prefix,
            Self::Ipv6NdSlaacTiming(_) => P::Ipv6NdSlaacTiming,
            Self::Raw(_) => return None,
        })
    }

    /// Validate a typed value and serialize it. `Raw` bypasses type validation.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, LanConfigError> {
        use LanConfigParameterRequest as R;
        Ok(match self {
            R::SetInProgress(value) => {
                LanSetInProgress::parse(*value)?;
                if *value > 2 {
                    return Err(LanConfigError::InvalidValue(*value));
                }
                vec![*value]
            }
            R::SetState(value) => vec![value.byte()],
            R::AuthTypeEnables(value) => value.to_vec(),
            R::IpAddress(value)
            | R::SubnetMask(value)
            | R::DefaultGatewayAddress(value)
            | R::BackupGatewayAddress(value) => value.0.to_vec(),
            R::IpAddressSource(value) => {
                if *value > 4 {
                    return Err(LanConfigError::InvalidValue(*value));
                }
                vec![*value]
            }
            R::AddressSource(value) => {
                if let IpAddressSource::Reserved(v) = value {
                    return Err(LanConfigError::InvalidValue(*v));
                }
                vec![(*value).into()]
            }
            R::MacAddress(value)
            | R::DefaultGatewayMacAddress(value)
            | R::BackupGatewayMacAddress(value)
            | R::Ipv6StaticRouter1Mac(value)
            | R::Ipv6StaticRouter2Mac(value) => value.0.to_vec(),
            R::IpHeader(value) => value.0.to_vec(),
            R::PrimaryRmcpPort(value) | R::SecondaryRmcpPort(value) => value.to_be_bytes().to_vec(),
            R::BmcArpControl(value) => vec![value.byte()],
            R::GratuitousArpInterval(value) => vec![*value],
            R::SnmpCommunity(value) => value.to_vec(),
            R::AlertDestinationType(value) => value.bytes()?.to_vec(),
            R::AlertDestinationAddress(value) => {
                match value {
                    LanAlertDestinationAddress::Ipv4 { set_selector, .. } => {
                        if *set_selector > 15 {
                            return Err(LanConfigError::InvalidValue(*set_selector));
                        }
                    }
                    LanAlertDestinationAddress::Other(bytes) => {
                        if bytes.len() < 2 {
                            return Err(LanConfigError::InvalidLength {
                                expected: 2,
                                actual: bytes.len(),
                            });
                        }
                        if bytes[1] & 0xf0 == 0 {
                            return Err(LanConfigError::InvalidValue(bytes[1]));
                        }
                    }
                }
                value.bytes().to_vec()
            }
            R::VlanId(value) => value.bytes()?.to_vec(),
            R::VlanPriority(value) => {
                if *value > 7 {
                    return Err(LanConfigError::InvalidValue(*value));
                }
                vec![*value]
            }
            R::CipherSuitePrivilegeLevels(value) => value.to_vec(),
            R::BadPasswordThreshold(value) => value.bytes().to_vec(),
            R::Ipv6Ipv4AddressingEnables(value) => match value {
                Ipv6Ipv4Enables::Reserved(v) => return Err(LanConfigError::InvalidValue(*v)),
                _ => vec![(*value).into()],
            },
            R::Ipv6HeaderStaticTrafficClass(value) | R::Ipv6HeaderStaticHopLimit(value) => {
                vec![*value]
            }
            R::Ipv6HeaderFlowLabel(value) => {
                if value.0 > 0x0f_ffff {
                    return Err(LanConfigError::InvalidValue((value.0 >> 16) as u8));
                }
                vec![(value.0 >> 16) as u8, (value.0 >> 8) as u8, value.0 as u8]
            }
            R::Ipv6StaticAddress {
                set_selector,
                enabled,
                source_type,
                address,
                prefix_length,
                status,
            } => {
                prefix(*prefix_length)?;
                if *source_type > 0x0f || *status != 0 {
                    return Err(LanConfigError::InvalidValue((*source_type).max(*status)));
                }
                let mut bytes = vec![*set_selector, (u8::from(*enabled) << 7) | *source_type];
                bytes.extend_from_slice(&address.0);
                bytes.extend_from_slice(&[*prefix_length, *status]);
                bytes
            }
            R::Ipv6StaticDuid(value)
            | R::Ipv6DynamicDuid(value)
            | R::Ipv6DhcpTiming(value)
            | R::Ipv6NdSlaacTiming(value) => {
                Ipv6LanBlock::new(
                    value.set_selector,
                    value.block_selector,
                    value.bytes.clone(),
                )?;
                if matches!(self, R::Ipv6StaticDuid(_) | R::Ipv6DynamicDuid(_))
                    && (value.bytes.is_empty() || value.block_selector > 15)
                {
                    return Err(LanConfigError::InvalidBlockSequence);
                }
                if matches!(self, R::Ipv6DhcpTiming(_))
                    && ((value.block_selector == 0 && value.bytes.len() != 16)
                        || (value.block_selector == 1 && value.bytes.len() != 6)
                        || value.block_selector > 1)
                {
                    return Err(LanConfigError::InvalidBlockSequence);
                }
                if matches!(self, R::Ipv6NdSlaacTiming(_))
                    && (value.block_selector != 0 || value.bytes.len() != 16)
                {
                    return Err(LanConfigError::InvalidBlockSequence);
                }
                value.wire()
            }
            R::Ipv6RouterControl(value) => vec![value.byte()],
            R::Ipv6StaticRouter1Address(value)
            | R::Ipv6StaticRouter1Prefix(value)
            | R::Ipv6StaticRouter2Address(value)
            | R::Ipv6StaticRouter2Prefix(value) => value.0.to_vec(),
            R::Ipv6StaticRouter1PrefixLength(value) | R::Ipv6StaticRouter2PrefixLength(value) => {
                prefix(*value)?;
                vec![*value]
            }
            R::Raw(value) => value.clone(),
        })
    }

    /// Serialize a parameter request without validation (legacy API).
    /// For safe writes prefer [`Self::try_to_bytes`] and [`SetLanConfigParameters::checked`].
    pub fn to_bytes(&self) -> Vec<u8> {
        // Preserve the legacy unchecked path. Never use it for guarded writes.
        self.try_to_bytes().unwrap_or_else(|_| match self {
            Self::SetInProgress(v) | Self::IpAddressSource(v) => vec![*v],
            Self::Ipv6Ipv4AddressingEnables(v) => vec![(*v).into()],
            Self::Ipv6StaticAddress {
                set_selector,
                enabled,
                source_type,
                address,
                prefix_length,
                status,
            } => {
                let mut bytes = vec![
                    *set_selector,
                    (u8::from(*enabled) << 7) | (*source_type & 0xf),
                ];
                bytes.extend_from_slice(&address.0);
                bytes.extend_from_slice(&[*prefix_length, *status]);
                bytes
            }
            Self::Ipv6HeaderFlowLabel(v) => vec![(v.0 >> 16) as u8, (v.0 >> 8) as u8, v.0 as u8],
            Self::VlanId(v) => {
                let [lo, hi] = v.id.to_le_bytes();
                vec![lo, hi | (u8::from(v.enabled) << 7)]
            }
            Self::VlanPriority(v) => vec![*v],
            Self::AlertDestinationType(v) => vec![
                v.set_selector,
                (u8::from(v.acknowledged) << 7) | v.destination_type,
                v.timeout,
                v.retries,
            ],
            Self::AlertDestinationAddress(v) => v.bytes().to_vec(),
            Self::AddressSource(v) => vec![(*v).into()],
            Self::Ipv6StaticRouter1PrefixLength(v) | Self::Ipv6StaticRouter2PrefixLength(v) => {
                vec![*v]
            }
            Self::Ipv6StaticDuid(v)
            | Self::Ipv6DynamicDuid(v)
            | Self::Ipv6DhcpTiming(v)
            | Self::Ipv6NdSlaacTiming(v) => v.wire(),
            _ => unreachable!("all remaining variants are always valid"),
        })
    }
}
