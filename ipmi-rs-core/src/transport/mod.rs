//! Definitions for IPMI transport commands.

mod get_lan_configuration_parameters;
mod lan_statistics;
mod lan_types;
mod lan_write;
mod set_lan_configuration_parameters;
mod sol;

#[cfg(test)]
mod lan_tests;

pub use get_lan_configuration_parameters::{
    GetLanConfigParameters, IpAddressSource, Ipv4Address, Ipv6Address, Ipv6DynamicAddress,
    Ipv6HeaderFlowLabel, Ipv6Ipv4Enables, Ipv6Ipv4Support, Ipv6StaticAddress, Ipv6Status,
    LanConfigParameter, LanConfigParameterData, LanConfigParameterResponse, MacAddress,
};
pub use lan_statistics::{ClearLanStatistics, GetLanStatistics, LanStatistics};
pub use lan_types::{
    Ipv6DhcpTiming, Ipv6Duid, Ipv6DynamicRouter, Ipv6LanBlock, Ipv6Router, Ipv6RouterControl,
    Ipv6TimingSupport, LanAlertDestinationAddress, LanAlertDestinationType, LanArpControl,
    LanBadPasswordThreshold, LanConfigError, LanIpv4Header, LanSetInProgress, LanVlanId,
};
pub use lan_write::{ipv6_static_router_writes, lan_write_guarded, LanBeginFailure, LanWriteError};
pub use set_lan_configuration_parameters::{LanConfigParameterRequest, SetLanConfigParameters};
pub use sol::{
    sol_write_guarded, GetSolConfig, SetSolConfig, SolBitRate, SolConfigError, SolConfigRaw,
    SolConfigResponse, SolParameter, SolParameterValue, SolRetryCount, SolSetInProgress,
    SolWriteError,
};
