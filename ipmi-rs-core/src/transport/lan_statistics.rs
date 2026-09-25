//! Get/Clear LAN Statistics (IPMI Transport command 0x04).

use crate::connection::{Channel, IpmiCommand, Message, NetFn};

use super::LanConfigError;

/// Get LAN Statistics without changing the counters.
#[derive(Clone, Copy, Debug)]
pub struct GetLanStatistics {
    pub channel: Channel,
}

impl From<GetLanStatistics> for Message {
    fn from(value: GetLanStatistics) -> Self {
        Message::new_request(NetFn::Transport, 0x04, vec![value.channel.value(), 0])
    }
}

/// The nine 16-bit, network-byte-order LAN counters (IPMI 2.0, table 23-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanStatistics {
    pub ip_rx_packets: u16,
    pub ip_rx_header_errors: u16,
    pub ip_rx_address_errors: u16,
    pub ip_rx_fragmented_packets: u16,
    pub ip_tx_packets: u16,
    pub udp_rx_packets: u16,
    pub rmcp_rx_valid_packets: u16,
    pub udp_proxy_rx_packets: u16,
    pub udp_proxy_dropped_packets: u16,
}

impl IpmiCommand for GetLanStatistics {
    type Output = LanStatistics;
    type Error = LanConfigError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        super::lan_types::length(data, 18)?;
        let read = |index| u16::from_be_bytes([data[index], data[index + 1]]);
        Ok(LanStatistics {
            ip_rx_packets: read(0),
            ip_rx_header_errors: read(2),
            ip_rx_address_errors: read(4),
            ip_rx_fragmented_packets: read(6),
            ip_tx_packets: read(8),
            udp_rx_packets: read(10),
            rmcp_rx_valid_packets: read(12),
            udp_proxy_rx_packets: read(14),
            udp_proxy_dropped_packets: read(16),
        })
    }
}

/// Clear LAN Statistics. This is a mutation: never automatically retry it.
/// Some controllers return the previous counters, others an empty response.
#[derive(Clone, Copy, Debug)]
pub struct ClearLanStatistics {
    pub channel: Channel,
}

impl From<ClearLanStatistics> for Message {
    fn from(value: ClearLanStatistics) -> Self {
        Message::new_request(NetFn::Transport, 0x04, vec![value.channel.value(), 1])
    }
}

impl IpmiCommand for ClearLanStatistics {
    type Output = Option<LanStatistics>;
    type Error = LanConfigError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() {
            Ok(None)
        } else {
            GetLanStatistics::parse_success_response(data).map(Some)
        }
    }
}
