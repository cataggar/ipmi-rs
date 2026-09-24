//! Definitions for IPMI transport commands.

mod get_lan_configuration_parameters;
mod set_lan_configuration_parameters;
mod sol;

pub use get_lan_configuration_parameters::{
    GetLanConfigParameters, IpAddressSource, Ipv4Address, Ipv6Address, Ipv6DynamicAddress,
    Ipv6HeaderFlowLabel, Ipv6Ipv4Enables, Ipv6Ipv4Support, Ipv6StaticAddress, Ipv6Status,
    LanConfigParameter, LanConfigParameterData, LanConfigParameterResponse, MacAddress,
};
pub use set_lan_configuration_parameters::{LanConfigParameterRequest, SetLanConfigParameters};
pub use sol::{
    sol_write_guarded, GetSolConfig, SetSolConfig, SolBitRate, SolConfigError, SolConfigRaw,
    SolConfigResponse, SolParameter, SolParameterValue, SolRetryCount, SolSetInProgress,
    SolWriteError,
};
