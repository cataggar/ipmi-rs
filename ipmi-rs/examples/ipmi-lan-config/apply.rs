use crate::common;
use crate::parse::{
    parse_ip_source, parse_ipv4, parse_ipv6, parse_ipv6_ipv4_enables, parse_mac, parse_u24,
    parse_u8,
};
use crate::types::{ConfigInput, LanConfigInput};

use ipmi_rs::{
    connection::{Channel, CompletionErrorCode},
    transport::{
        lan_write_guarded, Ipv6HeaderFlowLabel, LanBeginFailure, LanConfigParameter,
        LanConfigParameterRequest, LanWriteError,
    },
    IpmiError,
};

type Write = (LanConfigParameter, LanConfigParameterRequest);

pub fn apply_config_file(
    ipmi: &mut common::IpmiConnectionEnum,
    path: &str,
    force_write_all: bool,
) -> std::io::Result<()> {
    let contents = std::fs::read_to_string(path)?;
    let config: ConfigInput = serde_json::from_str(&contents)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

    let planned: Vec<_> = config
        .channels
        .iter()
        .map(|entry| {
            let channel = Channel::new(entry.channel_number).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid channel 0x{:02X}", entry.channel_number),
                )
            })?;
            let writes = prepare_writes(&entry.lan_config, force_write_all)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
            for (_, request) in &writes {
                request.try_to_bytes().map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid channel {} LAN value: {error:?}", channel.value()),
                    )
                })?;
            }
            Ok((channel, writes))
        })
        .collect::<std::io::Result<_>>()?;

    for (channel, writes) in planned {
        lan_write_guarded(
            |command| ipmi.send_recv(command),
            channel,
            &writes,
            classify_begin_error,
        )
        .map_err(|err| {
            let outcome = if matches!(&err, LanWriteError::BeginRejected { .. }) {
                "transaction rejected without taking the lock"
            } else {
                "write outcome may be uncertain; do not retry automatically"
            };
            std::io::Error::other(format!(
                "LAN channel {} {outcome}: {err:?}",
                channel.value(),
            ))
        })?;
    }
    Ok(())
}

fn classify_begin_error<C, P>(err: &IpmiError<C, P>) -> LanBeginFailure {
    match err {
        IpmiError::Failed {
            completion_code: CompletionErrorCode::CommandSpecific(0x80..=0x83),
            ..
        }
        | IpmiError::Command {
            completion_code: Some(CompletionErrorCode::CommandSpecific(0x80..=0x83)),
            ..
        } => LanBeginFailure::Rejected,
        _ => LanBeginFailure::Uncertain,
    }
}

fn required<T>(value: Option<T>, name: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("invalid {name}"))
}

fn prepare_writes(config: &LanConfigInput, force_write_all: bool) -> Result<Vec<Write>, String> {
    use LanConfigParameterRequest as R;
    let mut writes = Vec::new();
    let mut add = |request: R| {
        writes.push((request.parameter().expect("typed LAN request"), request));
    };

    if let Some(value) = config.ip_address.as_deref() {
        add(R::IpAddress(required(parse_ipv4(value), "IPv4 address")?));
    }
    if let Some(value) = config.subnet_mask.as_deref() {
        add(R::SubnetMask(required(parse_ipv4(value), "subnet mask")?));
    }
    if let Some(value) = config.gateway.as_deref() {
        add(R::DefaultGatewayAddress(required(
            parse_ipv4(value),
            "gateway",
        )?));
    }
    if let Some(value) = config.mac_address.as_deref() {
        if force_write_all {
            add(R::MacAddress(required(parse_mac(value), "MAC address")?));
        } else {
            log::warn!("Skipping MAC address write; this parameter is often read-only (use --force-write-all to override)");
        }
    }
    if let Some(value) = config.ip_source.as_deref() {
        add(R::AddressSource(required(
            parse_ip_source(value),
            "IP source",
        )?));
    }
    if let Some(value) = config.ipv6_ipv4_addressing_enables.as_deref() {
        add(R::Ipv6Ipv4AddressingEnables(required(
            parse_ipv6_ipv4_enables(value),
            "IPv6/IPv4 enables",
        )?));
    }
    if let Some(value) = config.ipv6_header_static_traffic_class.as_deref() {
        add(R::Ipv6HeaderStaticTrafficClass(required(
            parse_u8(value),
            "IPv6 traffic class",
        )?));
    }
    if let Some(value) = config.ipv6_header_static_hop_limit.as_deref() {
        add(R::Ipv6HeaderStaticHopLimit(required(
            parse_u8(value),
            "IPv6 hop limit",
        )?));
    }
    if let Some(value) = config.ipv6_header_flow_label.as_deref() {
        let bytes = required(parse_u24(value), "IPv6 flow label")?;
        add(R::Ipv6HeaderFlowLabel(Ipv6HeaderFlowLabel(
            u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]),
        )));
    }
    if let Some(addresses) = &config.ipv6_static_addresses {
        for entry in addresses {
            add(R::Ipv6StaticAddress {
                set_selector: entry.set_selector,
                enabled: entry.enabled.unwrap_or(true),
                source_type: entry.source_type.unwrap_or(0),
                address: required(parse_ipv6(&entry.address), "IPv6 static address")?,
                prefix_length: entry.prefix_length,
                status: entry.status.unwrap_or(0),
            });
        }
    }
    if let Some(value) = config.default_gateway_mac.as_deref() {
        if force_write_all {
            add(R::DefaultGatewayMacAddress(required(
                parse_mac(value),
                "default gateway MAC",
            )?));
        } else {
            log::warn!("Skipping default gateway MAC write; this parameter is often read-only (use --force-write-all to override)");
        }
    }
    if let Some(value) = config.backup_gateway.as_deref() {
        add(R::BackupGatewayAddress(required(
            parse_ipv4(value),
            "backup gateway",
        )?));
    }
    if let Some(value) = config.backup_gateway_mac.as_deref() {
        if force_write_all {
            add(R::BackupGatewayMacAddress(required(
                parse_mac(value),
                "backup gateway MAC",
            )?));
        } else {
            log::warn!("Skipping backup gateway MAC write; this parameter is often read-only (use --force-write-all to override)");
        }
    }

    Ok(writes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipmi_rs::connection::NetFn;

    #[test]
    fn invalid_example_config_fails_before_any_write() {
        let config = LanConfigInput {
            ip_address: Some("192.0.2.4".into()),
            ipv6_static_addresses: Some(vec![crate::types::Ipv6AddressEntryInput {
                set_selector: 1,
                enabled: Some(true),
                source_type: Some(0),
                address: "2001:db8::1".into(),
                prefix_length: 129,
                status: None,
            }]),
            ..Default::default()
        };
        let writes = prepare_writes(&config, false).unwrap();
        let result = lan_write_guarded(
            |_command| -> Result<(), ()> { panic!("no write should be sent") },
            Channel::Current,
            &writes,
            |_| LanBeginFailure::Uncertain,
        );
        assert!(matches!(
            result,
            Err(ipmi_rs::transport::LanWriteError::Validation(_))
        ));
    }

    #[test]
    fn completed_rejections_leave_other_writers_alone_but_lost_ack_is_uncertain() {
        for code in 0x80..=0x83 {
            let rejected = IpmiError::<(), ()>::Failed {
                netfn: NetFn::Transport,
                cmd: 1,
                completion_code: CompletionErrorCode::CommandSpecific(code),
                data: Vec::new(),
            };
            assert_eq!(classify_begin_error(&rejected), LanBeginFailure::Rejected);
        }
        assert_eq!(
            classify_begin_error(&IpmiError::<(), ()>::Connection(())),
            LanBeginFailure::Uncertain
        );
    }
}
