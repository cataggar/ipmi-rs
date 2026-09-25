use std::{cell::Cell, collections::VecDeque, num::NonZeroU8, rc::Rc};

use ipmi_rs::{
    connection::{
        Address, Channel, ChannelNumber, IpmiCommand, IpmiConnection, LogicalUnit, Message, NetFn,
        Request, RequestTargetAddress, Response,
    },
    oem::{
        dell::{
            ActiveNic, ClearPower, Controller, DecodeError, DellError, DriveBdf, DriveLed,
            Failover, GetPowerCapStatus, Kvm, LcdLock, LcdMode, LegacyNic, LocalVflash, NicMode,
            PowerCapStatus, PowerCapValue, SdHealth, WriteIntent,
        },
        kontron::{BootDevice, GetManufacturingDate, SetNextBoot},
        quanta::{GetPlatformId, MemoryLocation, Platform, PlatformError},
        sun::{GetVersion, VersionError},
        OemCommand, OemError,
    },
    storage::sel::{Entry, GetSelEntry},
    Ipmi, IpmiError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockError {
    Timeout,
}

#[derive(Debug, PartialEq)]
struct Sent {
    netfn: u8,
    cmd: u8,
    data: Vec<u8>,
    target: RequestTargetAddress,
}

#[derive(Default)]
struct Mock {
    sent: Vec<Sent>,
    replies: VecDeque<Result<Response, MockError>>,
}

impl Mock {
    fn reply(&mut self, netfn: u8, cmd: u8, cc: u8, data: &[u8]) {
        let mut bytes = vec![cc];
        bytes.extend_from_slice(data);
        self.replies.push_back(Ok(Response::new(
            Message::new_response(NetFn::from(netfn), cmd, bytes),
            0,
        )
        .unwrap()));
    }

    fn identity(&mut self, manufacturer_id: u32, product_id: u16) {
        let manufacturer = manufacturer_id.to_le_bytes();
        let product = product_id.to_le_bytes();
        self.reply(
            0x06,
            0x01,
            0,
            &[
                1,
                1,
                1,
                0x23,
                0x51,
                0,
                manufacturer[0],
                manufacturer[1],
                manufacturer[2],
                product[0],
                product[1],
            ],
        );
    }

    fn dell_reply(&mut self, netfn: u8, cmd: u8, cc: u8, data: &[u8]) {
        self.identity(674, 0x1234);
        self.reply(netfn, cmd, cc, data);
    }

    fn dell_controller(&mut self, imc: u8) {
        let mut validator = [0; 11];
        validator[10] = imc;
        self.dell_reply(0x06, 0x59, 0, &validator);
    }
}

impl IpmiConnection for Mock {
    type SendError = MockError;
    type RecvError = MockError;
    type Error = MockError;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        Err(MockError::Timeout)
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        Err(MockError::Timeout)
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.sent.push(Sent {
            netfn: request.netfn_raw(),
            cmd: request.cmd(),
            data: request.data().to_vec(),
            target: request.target(),
        });
        self.replies.pop_front().unwrap_or(Err(MockError::Timeout))
    }
}

fn sent(netfn: u8, cmd: u8, data: &[u8], lun: LogicalUnit) -> Sent {
    Sent {
        netfn,
        cmd,
        data: data.to_vec(),
        target: RequestTargetAddress::Bmc(lun),
    }
}

fn device_id_request() -> Sent {
    sent(0x06, 0x01, &[], LogicalUnit::Zero)
}

fn quanta_fixture(name: &str) -> Vec<u8> {
    include_str!("fixtures/quanta_sel.txt")
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| *key == name)
        .unwrap_or_else(|| panic!("missing Quanta fixture: {name}"))
        .1
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

#[test]
fn dell_cap_flags_match_delloem_wire_request() {
    let mut mock = Mock::default();
    mock.identity(674, 0x1234);
    mock.reply(0x30, 0xBA, 0, &[0x03]);
    let mut ipmi = Ipmi::new(mock);

    assert_eq!(
        ipmi.send_oem(GetPowerCapStatus).unwrap(),
        PowerCapStatus {
            enabled: true,
            can_set: true
        }
    );
    assert_eq!(
        ipmi.release().sent,
        [
            device_id_request(),
            sent(0x30, 0xBA, &[1, 0xFF], LogicalUnit::Zero)
        ]
    );
}

#[test]
fn sun_version_decodes_struct_prefix_without_reading_spare() {
    let mut version = [0; 65];
    version[..5].copy_from_slice(&[1, 3, 2, 0, 0]);
    version[25..35].copy_from_slice(b"ILOM 3.2.0");
    let mut mock = Mock::default();
    mock.identity(42, 1);
    mock.reply(0x2E, 0x24, 0, &version);
    let mut ipmi = Ipmi::new(mock);

    let parsed = ipmi.send_oem(GetVersion).unwrap();
    assert_eq!(
        (parsed.major, parsed.minor, parsed.update, parsed.micro),
        (3, 2, 0, 0)
    );
    assert_eq!(parsed.text, "ILOM 3.2.0");
    assert_eq!(
        ipmi.release().sent,
        [
            device_id_request(),
            sent(0x2E, 0x24, &[], LogicalUnit::Zero)
        ]
    );
    assert_eq!(
        GetVersion::parse_success_response(&[1, 3, 2, 0, 0]),
        Err(VersionError::TooShort(5))
    );
    version[25] = 0xFF;
    assert_eq!(
        GetVersion::parse_success_response(&version),
        Err(VersionError::InvalidText)
    );
}

#[test]
fn kontron_lun_three_reads_manufacturing_date_and_writes_cp6012_boot_selection() {
    let mut mock = Mock::default();
    mock.identity(15000, 6012);
    mock.reply(0x3E, 0x0E, 0, &[1, 2, 3]);
    mock.identity(15000, 6012);
    mock.reply(0x3E, 0x02, 0, &[]);
    let mut ipmi = Ipmi::new(mock);

    assert_eq!(ipmi.send_oem(GetManufacturingDate).unwrap(), [1, 2, 3]);
    assert!(matches!(
        ipmi.send_oem(SetNextBoot(BootDevice::Network)),
        Ok(())
    ));
    assert_eq!(
        ipmi.release().sent,
        [
            device_id_request(),
            sent(0x3E, 0x0E, &[0xB4, 0x90, 0x91, 0x8B], LogicalUnit::Three),
            device_id_request(),
            sent(
                0x3E,
                0x02,
                &[0xB4, 0x90, 0x91, 0x8B, 0x9D, 4, 0xFF],
                LogicalUnit::Three,
            ),
        ]
    );
    assert!(GetManufacturingDate::parse_success_response(&[1, 2]).is_err());
}

#[test]
fn quanta_platform_id_uses_magic_and_rejects_unknown_platforms() {
    let device_id = quanta_fixture("device_id");
    assert_eq!(
        ipmi_rs::app::DeviceId::from_data(&device_id)
            .unwrap()
            .manufacturer_id,
        7244
    );

    for (response, expected) in [
        ("platform_grantley", Platform::Grantley),
        ("platform_purley", Platform::Purley),
    ] {
        let mut mock = Mock::default();
        mock.reply(0x06, 0x01, 0, &device_id);
        mock.reply(0x36, 0x65, 0, &quanta_fixture(response));
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(ipmi.send_oem(GetPlatformId), Ok(platform) if platform == expected));
        assert_eq!(
            ipmi.release().sent,
            [
                device_id_request(),
                sent(
                    0x36,
                    0x65,
                    &quanta_fixture("platform_request"),
                    LogicalUnit::Zero
                ),
            ]
        );
    }
}

#[test]
fn quanta_rejects_malformed_platform_replies_and_completion_codes() {
    for (fixture, error) in [
        ("platform_zero", PlatformError::Unsupported(0)),
        ("platform_unknown", PlatformError::Unsupported(3)),
        ("platform_empty", PlatformError::TooShort),
    ] {
        let mut mock = Mock::default();
        mock.reply(0x06, 0x01, 0, &quanta_fixture("device_id"));
        mock.reply(0x36, 0x65, 0, &quanta_fixture(fixture));
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.send_oem(GetPlatformId),
            Err(OemError::Command(IpmiError::Command { error: actual, .. })) if actual == error
        ));
        assert_eq!(ipmi.release().sent.len(), 2);
    }

    let mut mock = Mock::default();
    mock.reply(0x06, 0x01, 0, &quanta_fixture("device_id"));
    mock.reply(0x36, 0x65, 0xC1, &quanta_fixture("platform_purley"));
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.send_oem(GetPlatformId),
        Err(OemError::Command(IpmiError::Failed { .. }))
    ));
    assert_eq!(ipmi.release().sent.len(), 2);
}

#[test]
fn quanta_identity_mismatch_or_malformed_identity_never_sends_oem_request() {
    let mut mock = Mock::default();
    mock.reply(0x06, 0x01, 0, &quanta_fixture("device_id_non_quanta"));
    mock.reply(0x36, 0x65, 0, &quanta_fixture("platform_purley"));
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.send_oem(GetPlatformId),
        Err(OemError::UnsupportedDevice {
            manufacturer_id: 42,
            expected_manufacturer_id: 7244,
            ..
        })
    ));
    assert_eq!(ipmi.release().sent, [device_id_request()]);

    let mut mock = Mock::default();
    mock.reply(0x06, 0x01, 0, &quanta_fixture("device_id_short"));
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.send_oem(GetPlatformId),
        Err(OemError::Identity(IpmiError::Command { .. }))
    ));
    assert_eq!(ipmi.release().sent, [device_id_request()]);

    let mut mock = Mock::default();
    mock.reply(0x06, 0x01, 0xC1, &quanta_fixture("device_id"));
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.send_oem(GetPlatformId),
        Err(OemError::Identity(IpmiError::Failed { .. }))
    ));
    assert_eq!(ipmi.release().sent, [device_id_request()]);
}

#[test]
fn quanta_purley_memory_location_decodes_sel_fixture_without_cli_text() {
    for fixture in ["sel_cpu0_a0", "sel_cpu1_b3", "sel_cpu3_h7", "sel_cpu2_c2"] {
        let location = quanta_fixture(&format!("{fixture}_location"));
        let expected = MemoryLocation {
            cpu: location[0],
            channel: location[1],
            dimm: location[2],
        };
        let info = GetSelEntry::parse_success_response(&quanta_fixture(fixture)).unwrap();
        assert_eq!(
            MemoryLocation::from_sel_entry(Platform::Purley, &info),
            Some(expected)
        );
        assert_eq!(
            MemoryLocation::from_sel_entry(Platform::Grantley, &info),
            None
        );
        if fixture == "sel_cpu3_h7" {
            assert_eq!(info.raw[13..], [0, 0x11, 0xFF]);
        }
    }

    for fixture in ["sel_temperature", "sel_other_event"] {
        let info = GetSelEntry::parse_success_response(&quanta_fixture(fixture)).unwrap();
        assert_eq!(
            MemoryLocation::from_sel_entry(Platform::Purley, &info),
            None
        );
    }
    assert!(GetSelEntry::parse_success_response(&[0, 0, 1]).is_err());
}

#[test]
fn existing_sel_system_variant_supports_exhaustive_match_and_construction() {
    let info = GetSelEntry::parse_success_response(&quanta_fixture("sel_cpu3_h7")).unwrap();
    let original = info.entry.clone();
    let Entry::System {
        record_id,
        timestamp,
        generator_id,
        event_message_format,
        sensor_type,
        sensor_number,
        event_direction,
        event_type,
        event_data,
    } = info.entry
    else {
        panic!("expected standard SEL entry");
    };
    let reconstructed = Entry::System {
        record_id,
        timestamp,
        generator_id,
        event_message_format,
        sensor_type,
        sensor_number,
        event_direction,
        event_type,
        event_data,
    };
    assert_eq!(reconstructed, original);
}

#[test]
fn wrong_vendor_or_board_never_receives_the_oem_request() {
    let mut mock = Mock::default();
    mock.identity(42, 6012);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.send_oem(SetNextBoot(BootDevice::Bios)),
        Err(OemError::UnsupportedDevice {
            manufacturer_id: 42,
            expected_manufacturer_id: 15000,
            expected_product_id: Some(6012),
            ..
        })
    ));
    assert_eq!(ipmi.release().sent, [device_id_request()]);

    let mut mock = Mock::default();
    mock.identity(15000, 6011);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.send_oem(SetNextBoot(BootDevice::Bios)),
        Err(OemError::UnsupportedDevice {
            product_id: 6011,
            expected_product_id: Some(6012),
            ..
        })
    ));
    assert_eq!(ipmi.release().sent, [device_id_request()]);
}

#[test]
fn failed_lookup_and_ambiguous_boot_write_do_not_replay() {
    let mut ipmi = Ipmi::new(Mock::default());
    assert!(matches!(
        ipmi.send_oem(GetPowerCapStatus),
        Err(OemError::Identity(IpmiError::Connection(
            MockError::Timeout
        )))
    ));
    assert_eq!(ipmi.release().sent, [device_id_request()]);

    let mut mock = Mock::default();
    mock.identity(15000, 6012);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.send_oem(SetNextBoot(BootDevice::HardDrive)),
        Err(OemError::Command(IpmiError::Connection(MockError::Timeout)))
    ));
    assert_eq!(ipmi.release().sent.len(), 2);
}

#[test]
fn short_device_id_and_wrong_oem_netfn_are_not_silently_accepted() {
    let mut mock = Mock::default();
    mock.reply(0x06, 0x01, 0, &[0; 10]);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.send_oem(GetPowerCapStatus),
        Err(OemError::Identity(IpmiError::Command { .. }))
    ));
    assert_eq!(ipmi.release().sent, [device_id_request()]);

    let mut mock = Mock::default();
    mock.identity(674, 1);
    mock.reply(0x32, 0xBA, 0, &[3]);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.send_oem(GetPowerCapStatus),
        Err(OemError::Command(IpmiError::UnexpectedResponse { .. }))
    ));
}

#[test]
fn custom_capability_predicate_cannot_override_manufacturer_guard() {
    struct Permissive;
    impl OemCommand for Permissive {
        type Output = PowerCapStatus;
        type Error = <GetPowerCapStatus as OemCommand>::Error;
        const MANUFACTURER_ID: u32 = 674;

        fn into_message(self) -> Message {
            GetPowerCapStatus.into_message()
        }
        fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
            GetPowerCapStatus::parse_success_response(data)
        }
        fn supports(&self, _: &ipmi_rs::app::DeviceId) -> bool {
            true
        }
    }
    let mut mock = Mock::default();
    mock.identity(42, 1);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.send_oem(Permissive),
        Err(OemError::UnsupportedDevice { .. })
    ));
    assert_eq!(ipmi.release().sent, [device_id_request()]);
}

#[derive(Debug)]
struct BridgedVersion;

impl OemCommand for BridgedVersion {
    type Output = <GetVersion as OemCommand>::Output;
    type Error = <GetVersion as OemCommand>::Error;
    const MANUFACTURER_ID: u32 = 42;

    fn into_message(self) -> Message {
        GetVersion.into_message()
    }
    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        GetVersion::parse_success_response(data)
    }
    fn target(&self) -> Option<(Address, Channel)> {
        Some((
            Address(0x82),
            Channel::Numbered(ChannelNumber::new(NonZeroU8::new(2).unwrap()).unwrap()),
        ))
    }
}

#[test]
fn bridged_identity_and_oem_command_target_same_device() {
    let mut version = [0; 65];
    version[25..29].copy_from_slice(b"ILOM");
    let mut mock = Mock::default();
    mock.identity(42, 42);
    mock.reply(0x2E, 0x24, 0, &version);
    let mut ipmi = Ipmi::new(mock);
    assert_eq!(ipmi.send_oem(BridgedVersion).unwrap().text, "ILOM");

    let sent = ipmi.release().sent;
    assert_eq!(sent[0].target, sent[1].target);
    assert_eq!(
        sent[0].target,
        RequestTargetAddress::BmcOrIpmb(
            Address(0x82),
            Channel::Numbered(ChannelNumber::new(NonZeroU8::new(2).unwrap()).unwrap()),
            LogicalUnit::Zero,
        )
    );
}

#[test]
fn mutable_command_cannot_change_target_or_lun_after_identity_check() {
    struct Retargeting {
        target: Cell<Option<(Address, Channel)>>,
        lun: Cell<LogicalUnit>,
        target_reads: Rc<Cell<usize>>,
    }

    impl OemCommand for Retargeting {
        type Output = <GetVersion as OemCommand>::Output;
        type Error = <GetVersion as OemCommand>::Error;
        const MANUFACTURER_ID: u32 = 42;

        fn into_message(self) -> Message {
            GetVersion.into_message()
        }

        fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
            GetVersion::parse_success_response(data)
        }

        fn target(&self) -> Option<(Address, Channel)> {
            self.target_reads.set(self.target_reads.get() + 1);
            self.target.get()
        }

        fn lun(&self) -> LogicalUnit {
            self.lun.get()
        }

        fn supports(&self, _: &ipmi_rs::app::DeviceId) -> bool {
            self.target.set(Some((Address(0x84), Channel::Primary)));
            self.lun.set(LogicalUnit::Zero);
            true
        }
    }

    let original_target = (
        Address(0x82),
        Channel::Numbered(ChannelNumber::new(NonZeroU8::new(2).unwrap()).unwrap()),
    );
    let target_reads = Rc::new(Cell::new(0));
    let command = Retargeting {
        target: Cell::new(Some(original_target)),
        lun: Cell::new(LogicalUnit::Three),
        target_reads: target_reads.clone(),
    };
    let mut mock = Mock::default();
    mock.identity(42, 1);
    mock.reply(0x2E, 0x24, 0, &[0; 65]);
    let mut ipmi = Ipmi::new(mock);

    assert!(ipmi.send_oem(command).is_ok());
    assert_eq!(target_reads.get(), 1);
    let requests = ipmi.release().sent;
    assert_eq!(
        requests[0].target,
        RequestTargetAddress::BmcOrIpmb(original_target.0, original_target.1, LogicalUnit::Zero),
    );
    assert_eq!(
        requests[1].target,
        RequestTargetAddress::BmcOrIpmb(original_target.0, original_target.1, LogicalUnit::Three),
    );
}

#[test]
fn oem_completion_code_remains_visible() {
    let mut mock = Mock::default();
    mock.identity(674, 1);
    mock.reply(0x30, 0xBA, 0xC1, &[]);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.send_oem(GetPowerCapStatus),
        Err(OemError::Command(IpmiError::Failed { .. }))
    ));
}

fn assert_pairs(sends: &[Sent], expected: &[(u8, u8, &[u8])]) {
    assert_eq!(sends.len(), expected.len() * 2);
    for (index, (netfn, cmd, bytes)) in expected.iter().enumerate() {
        assert_eq!(sends[index * 2], device_id_request());
        assert_eq!(
            sends[index * 2 + 1],
            sent(*netfn, *cmd, bytes, LogicalUnit::Zero)
        );
    }
}

const VALIDATOR: &[u8] = &[0, 0xDD, 2, 0];

#[test]
fn dell_discovery_rejects_other_vendors_unknown_models_and_short_replies() {
    let mut wrong = Mock::default();
    wrong.identity(42, 1);
    let mut ipmi = Ipmi::new(wrong);
    assert!(matches!(
        ipmi.dell(),
        Err(DellError::Dispatch(OemError::UnsupportedDevice { .. }))
    ));
    assert_eq!(ipmi.release().sent, [device_id_request()]);

    for bytes in [&[0; 10][..], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9][..]] {
        let mut mock = Mock::default();
        mock.dell_reply(0x06, 0x59, 0, bytes);
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.dell(),
            Err(DellError::Dispatch(OemError::Command(IpmiError::Command {
                error: DecodeError::Short { .. } | DecodeError::UnsupportedModel(9),
                ..
            })))
        ));
        assert_pairs(&ipmi.release().sent, &[(6, 0x59, VALIDATOR)]);
    }
}

#[test]
fn dell_write_rechecks_controller_type_and_never_sends_after_swap() {
    let mut mock = Mock::default();
    mock.dell_controller(0x10);
    mock.dell_controller(0x20);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.dell()
            .unwrap()
            .set_power_cap_enabled(WriteIntent, true),
        Err(DellError::UnsupportedGeneration(Controller::Idrac13 {
            modular: false
        }))
    ));
    assert_pairs(
        &ipmi.release().sent,
        &[(6, 0x59, VALIDATOR), (6, 0x59, VALIDATOR)],
    );
}

#[test]
fn dell_lcd_reads_and_writes_preserve_status_and_extended_fields() {
    let mut mock = Mock::default();
    mock.dell_controller(0x10); // iDRAC7 12G monolithic
    mock.dell_reply(6, 0x59, 0, &[0x11, 1, 2, 0, 0]); // LCD E7 probe
    mock.dell_reply(6, 0x59, 0, &[0x11, 1, 1, 62, 0, 0, 0]); // CF caps
    mock.dell_reply(6, 0x59, 0, &[0x11, 0, 0, 3, b'A', b'B', b'C']); // C1 text
    mock.dell_controller(0x10); // mutation revalidates generation
    mock.dell_reply(6, 0x59, 0, &[0x11, 1, 0, 0xAA, 0xBB]); // E7 writable
    mock.dell_reply(6, 0x59, 0, &[0x11, 1, 0, 0xAA, 0xBB]); // E7 probe
    mock.dell_reply(
        6,
        0x59,
        0,
        &[0x11, 1, 0, 0, 0, 3, 0, 0x77, 0x88, 0x99, 0xAA, 2, 0x55],
    ); // C2
    mock.dell_reply(6, 0x58, 0, &[]); // C2 write
    mock.dell_controller(0x10);
    mock.dell_reply(6, 0x59, 0, &[0x11, 1, 0, 0xAA, 0xBB]);
    mock.dell_reply(6, 0x58, 0, &[]); // E7 write
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert_eq!(dell.controller(), Controller::Idrac12 { modular: false });
    assert_eq!(dell.lcd_text().unwrap(), "ABC");
    dell.set_lcd_mode(WriteIntent, LcdMode::ServiceTag).unwrap();
    dell.set_lcd_kvm(WriteIntent, Kvm::Inactive).unwrap();
    let sent = ipmi.release().sent;
    assert_pairs(
        &sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xE7, 0, 0]),
            (6, 0x59, &[0, 0xCF, 0, 0]),
            (6, 0x59, &[0, 0xC1, 0, 0]),
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xE7, 0, 0]),
            (6, 0x59, &[0, 0xE7, 0, 0]),
            (6, 0x59, &[0, 0xC2, 0, 0]),
            (
                6,
                0x58,
                &[0xC2, 0x20, 0, 0, 0, 3, 0, 0x77, 0x88, 0x99, 0xAA, 2, 0x55],
            ),
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xE7, 0, 0]),
            (6, 0x58, &[0xE7, 0, 0, 0xAA, 0xBB]),
        ],
    );
}

#[test]
fn dell_lcd_text_chunks_are_bounded_and_failed_capability_cannot_write() {
    let mut mock = Mock::default();
    mock.dell_controller(0x08); // legacy DRAC 10G
    mock.dell_controller(0x08);
    mock.dell_reply(6, 0x59, 0, &[0x11, 0, 0, 0, 0]);
    mock.dell_reply(6, 0x59, 0, &[0x11, 0, 0, 0, 0]);
    mock.dell_reply(6, 0x59, 0, &[0x11, 1, 1, 62, 0, 0, 0]);
    mock.dell_reply(6, 0x58, 0, &[]);
    mock.dell_reply(6, 0x58, 0, &[]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert!(matches!(
        dell.set_lcd_text(WriteIntent, "☃"),
        Err(DellError::InvalidInput(_))
    ));
    assert!(matches!(
        dell.set_lcd_mode(WriteIntent, LcdMode::SystemWatts),
        Err(DellError::UnsupportedGeneration(Controller::Idrac10))
    ));
    dell.set_lcd_text(WriteIntent, "123456789012345").unwrap();
    let sent = ipmi.release().sent;
    assert_eq!(sent.len(), 14);
    assert_eq!(
        sent[11].data,
        [
            0xC1, 0, 0, 15, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2',
            b'3', b'4'
        ]
    );
    assert_eq!(
        sent[13].data,
        [0xC1, 1, b'5', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn dell_mac_and_lom_formats_follow_10g_and_12g_source() {
    let mut mock = Mock::default();
    mock.dell_controller(0x08);
    mock.dell_reply(6, 0x59, 0, &[0x11, 1, 1, 2, 3, 4, 5, 6]);
    mock.dell_reply(0x30, 0xC9, 0, &[0, 0, 0, 0, 0, 0, 0]);
    mock.dell_reply(0x0C, 2, 0, &[0x11, 6, 5, 4, 3, 2, 1]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert_eq!(dell.loms().unwrap()[0].mac.0, [1, 2, 3, 4, 5, 6]);
    assert_eq!(dell.idrac_mac().unwrap().0, [6, 5, 4, 3, 2, 1]);
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xCB, 0, 0]),
            (0x30, 0xC9, &[1]),
            (0x0C, 2, &[1, 5, 0, 0]),
        ],
    );

    let mut mock = Mock::default();
    mock.dell_controller(0x11); // 12G blade
    mock.dell_reply(6, 0x59, 0, &[0x11, 8]);
    mock.dell_reply(6, 0x59, 0, &[0x11, 0, 1, 1, 2, 3, 4, 5, 6]);
    mock.dell_reply(0x30, 0xC9, 0, &[0, 0, 0, 0, 0, 0, 0, 6, 5, 4, 3, 2, 1]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert_eq!(dell.loms().unwrap()[0].number, 1);
    assert_eq!(dell.idrac_mac().unwrap().0, [6, 5, 4, 3, 2, 1]);
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xDA, 0, 0, 0, 0]),
            (6, 0x59, &[0, 0xDA, 0, 0, 0, 8]),
            (0x30, 0xC9, &[1]),
        ],
    );
}

#[test]
fn dell_11g_lom_status_and_unsupported_virtual_mac_fallback() {
    let mut mock = Mock::default();
    mock.dell_controller(0x0A);
    mock.dell_reply(6, 0x59, 0, &[0x11, 8]);
    // blade 2, type Ethernet, status enabled, NIC 4, MAC bytes
    mock.dell_reply(6, 0x59, 0, &[0x11, 2, 4, 1, 2, 3, 4, 5, 6]);
    mock.dell_reply(0x30, 0xC9, 0xC1, &[]);
    mock.dell_reply(0x0C, 2, 0, &[0x11, 6, 5, 4, 3, 2, 1]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    let lom = dell.loms().unwrap()[0];
    assert_eq!(lom.blade_slot, 2);
    assert_eq!(lom.number, 4);
    assert!(lom.enabled && lom.ethernet);
    assert_eq!(dell.idrac_mac().unwrap().0, [6, 5, 4, 3, 2, 1]);
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xDA, 0, 0, 0, 0]),
            (6, 0x59, &[0, 0xDA, 0, 0, 0, 8]),
            (0x30, 0xC9, &[1]),
            (0x0C, 2, &[1, 5, 0, 0]),
        ],
    );
}

#[test]
fn dell_lan_modern_selection_active_link_and_safe_change() {
    let mut mock = Mock::default();
    mock.dell_controller(0x20); // 13G monolithic
    mock.dell_reply(0x30, 0x29, 0, &[2, 0]);
    mock.dell_reply(0x30, 0xC1, 0, &[2]);
    mock.dell_reply(0x30, 0xC1, 0, &[0, 1]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert_eq!(
        dell.nic_mode().unwrap(),
        NicMode::Modern {
            shared_lom: Some(1),
            failover: Failover::None
        }
    );
    assert_eq!(dell.active_nic().unwrap(), ActiveNic::Lom(2));
    assert!(matches!(
        dell.set_nic_mode(
            WriteIntent,
            NicMode::Modern {
                shared_lom: Some(2),
                failover: Failover::Lom(2)
            }
        ),
        Err(DellError::InvalidInput(_))
    ));
    // Invalid input is rejected before any further command.
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (0x30, 0x29, &[]),
            (0x30, 0xC1, &[0, 0, 0]),
            (0x30, 0xC1, &[1, 0, 0]),
        ],
    );
}

#[test]
fn dell_modern_lan_change_requires_readable_current_mode() {
    let mut mock = Mock::default();
    mock.dell_controller(0x20);
    mock.dell_controller(0x20);
    mock.dell_reply(0x30, 0x29, 0, &[2, 0]);
    mock.dell_reply(0x30, 0x28, 0, &[]);
    let mut ipmi = Ipmi::new(mock);
    ipmi.dell()
        .unwrap()
        .set_nic_mode(
            WriteIntent,
            NicMode::Modern {
                shared_lom: Some(2),
                failover: Failover::Lom(1),
            },
        )
        .unwrap();
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, VALIDATOR),
            (0x30, 0x29, &[]),
            (0x30, 0x28, &[3, 2]),
        ],
    );
}

#[test]
fn dell_lcd_locked_is_read_only_and_preserves_current_state() {
    let mut mock = Mock::default();
    mock.dell_controller(0x0A);
    mock.dell_controller(0x0A);
    mock.dell_reply(6, 0x59, 0, &[0x11, 0, 1, 0, 0]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert!(matches!(
        dell.set_lcd_lock(WriteIntent, LcdLock::Disabled),
        Err(DellError::Capability("LCD access is read-only or disabled"))
    ));
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xE7, 0, 0]),
        ],
    );
}

#[test]
fn dell_lan_legacy_and_modular_generation_guards() {
    let mut mock = Mock::default();
    mock.dell_controller(0x0A);
    mock.dell_reply(0x30, 0x25, 0, &[2]);
    mock.dell_controller(0x0A);
    mock.dell_reply(0x30, 0x25, 0, &[2]);
    mock.dell_reply(0x30, 0x24, 0, &[]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert_eq!(
        dell.nic_mode().unwrap(),
        NicMode::Legacy(LegacyNic::Dedicated)
    );
    dell.set_nic_mode(WriteIntent, NicMode::Legacy(LegacyNic::Shared))
        .unwrap();
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (0x30, 0x25, &[]),
            (6, 0x59, VALIDATOR),
            (0x30, 0x25, &[]),
            (0x30, 0x24, &[0]),
        ],
    );

    let mut mock = Mock::default();
    mock.dell_controller(0x0B); // iDRAC6 blade: LAN unsupported
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert!(matches!(
        dell.nic_mode(),
        Err(DellError::UnsupportedGeneration(_))
    ));
    assert_pairs(&ipmi.release().sent, &[(6, 0x59, VALIDATOR)]);
}

#[test]
fn dell_drive_mapping_probes_support_and_sends_only_known_ses_bits() {
    let mut mock = Mock::default();
    mock.dell_controller(0x11);
    mock.dell_controller(0x11);
    mock.dell_reply(0x30, 0xD5, 0, &[1]);
    mock.dell_reply(0x30, 0xD5, 0, &[0, 0, 0, 0, 0, 0, 0, 3, 9]);
    mock.dell_reply(0x30, 0xD5, 0, &[]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    let bdf = DriveBdf::new(0x12, 0x1F, 7).unwrap();
    assert!(DriveBdf::new(0x12, 32, 0).is_err());
    assert!(DriveBdf::new(0x12, 0, 8).is_err());
    assert!(matches!(
        dell.set_drive_led(WriteIntent, bdf, &[]),
        Err(DellError::InvalidInput(_))
    ));
    dell.set_drive_led(WriteIntent, bdf, &[DriveLed::Identify, DriveLed::Failed])
        .unwrap();
    let mut led = [0; 20];
    led[..12].copy_from_slice(&[0, 4, 14, 0, 0, 0, 14, 0, 3, 9, 8, 4]);
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, VALIDATOR),
            (0x30, 0xD5, &[1, 0, 8, 0, 0, 0, 0, 0, 0, 0]),
            (0x30, 0xD5, &[1, 7, 6, 0, 0, 0, 0x12, 0xFF]),
            (0x30, 0xD5, &led),
        ],
    );
}

#[test]
fn dell_power_reads_route_storage_sensor_app_and_oem() {
    let mut mock = Mock::default();
    mock.dell_controller(0x10);
    mock.dell_reply(0x0A, 0x48, 0, &[1, 2, 3, 4]);
    mock.dell_reply(
        0x30,
        0x9C,
        0,
        &[
            1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 6, 0, 0, 0, 7, 0,
        ],
    );
    mock.dell_reply(0x30, 0xB3, 0, &[8, 0, 9, 0, 0, 0, 0]);
    mock.dell_reply(0x30, 0xBB, 0, &[10, 0, 11, 0]);
    mock.dell_reply(6, 0x59, 0, &[0x11, 12, 0, 13, 0, 14, 0, 15, 0]);
    let mut extrema = [0; 25];
    extrema[1..9].copy_from_slice(&[12, 0, 13, 0, 14, 0, 15, 0]);
    extrema[9..13].copy_from_slice(&0x12345678u32.to_le_bytes());
    mock.dell_reply(6, 0x59, 0, &extrema);
    mock.dell_reply(6, 0x59, 0, &extrema);
    mock.dell_reply(0x04, 0x2D, 0, &[42, 0xC0, 0, 0]);
    mock.dell_reply(0x04, 0x27, 0, &[0x18, 0, 0, 0, 48, 55, 0]);
    mock.dell_reply(0x30, 0xBA, 0, &[3]);
    let budget = [0x11, 90, 0, 0, 100, 0, 80, 0, 2, 0, 110, 0, 3, 0, 0, 0];
    mock.dell_reply(6, 0x59, 0, &budget);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert_eq!(dell.sel_time().unwrap(), 0x04030201);
    assert_eq!(dell.power_monitor().unwrap().peak_watts, 7);
    assert_eq!(dell.instant_power().unwrap().watts, 8);
    assert_eq!(dell.power_headroom().unwrap().peak_watts, 11);
    assert_eq!(dell.average_power().unwrap().week, 15);
    assert_eq!(dell.peak_power().unwrap().times[0], 0x12345678);
    assert_eq!(dell.minimum_power().unwrap().watts.minute, 12);
    assert_eq!(dell.power_sensor(0x98).unwrap().upper_critical, 55);
    assert!(dell.power_cap_status().unwrap().can_set);
    let budget = dell.power_budget().unwrap();
    assert_eq!(budget.cap, PowerCapValue::Watts(90));
    assert_eq!(budget.min_watts, 80);
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (0x0A, 0x48, &[]),
            (0x30, 0x9C, &[7, 1]),
            (0x30, 0xB3, &[0x0A, 0]),
            (0x30, 0xBB, &[]),
            (6, 0x59, &[0, 0xEB, 0, 0]),
            (6, 0x59, &[0, 0xEC, 0, 0]),
            (6, 0x59, &[0, 0xED, 0, 0]),
            (4, 0x2D, &[0x98]),
            (4, 0x27, &[0x98]),
            (0x30, 0xBA, &[1, 0xFF]),
            (6, 0x59, &[0, 0xEA, 0, 0]),
        ],
    );
}

#[test]
fn dell_power_budget_preserves_btu_per_hour_wire_value_and_watt_bounds() {
    // ipmi_delloem.c:3604-3607 writes the numeric BTU/hr cap unchanged
    // with unit=1; EA replies preserve that cap while min/max remain watts.
    let btu_budget = [0x11, 0x55, 0x01, 1, 100, 0, 80, 0, 2, 0, 110, 0, 3, 0, 0, 0];
    let mut mock = Mock::default();
    mock.dell_controller(0x10);
    mock.dell_reply(6, 0x59, 0, &btu_budget);
    mock.dell_controller(0x10);
    mock.dell_reply(0x30, 0xBA, 0, &[3]);
    mock.dell_reply(6, 0x59, 0, &btu_budget);
    mock.dell_reply(6, 0x58, 0, &[]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    let budget = dell.power_budget().unwrap();
    assert_eq!(budget.cap, PowerCapValue::BtuPerHour(341));
    assert_eq!((budget.min_watts, budget.max_watts), (80, 100));
    dell.set_power_budget(WriteIntent, 95).unwrap();
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xEA, 0, 0]),
            (6, 0x59, VALIDATOR),
            (0x30, 0xBA, &[1, 0xFF]),
            (6, 0x59, &[0, 0xEA, 0, 0]),
            (6, 0x58, &[0xEA, 95, 0, 0, 100, 0, 80, 0, 2, 110, 0, 3, 0]),
        ],
    );
}

#[test]
fn dell_power_budget_rejects_unknown_unit_before_any_write() {
    let unknown_budget = [0x11, 0x55, 0x01, 3, 100, 0, 80, 0, 2, 0, 110, 0, 3, 0, 0, 0];
    let mut mock = Mock::default();
    mock.dell_controller(0x10);
    mock.dell_controller(0x10);
    mock.dell_reply(0x30, 0xBA, 0, &[3]);
    mock.dell_reply(6, 0x59, 0, &unknown_budget);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.dell().unwrap().set_power_budget(WriteIntent, 95),
        Err(DellError::Dispatch(OemError::Command(IpmiError::Command {
            error: DecodeError::InvalidValue(3),
            ..
        })))
    ));
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, VALIDATOR),
            (0x30, 0xBA, &[1, 0xFF]),
            (6, 0x59, &[0, 0xEA, 0, 0]),
        ],
    );
}

#[test]
fn dell_power_writes_validate_flags_limits_and_never_retry_timeout() {
    let mut mock = Mock::default();
    mock.dell_controller(0x10);
    mock.dell_controller(0x10);
    mock.dell_reply(0x30, 0xBA, 0, &[3]);
    mock.dell_reply(
        6,
        0x59,
        0,
        &[0x11, 90, 0, 0, 100, 0, 80, 0, 2, 0, 110, 0, 3, 0, 0, 0],
    );
    mock.dell_reply(6, 0x58, 0, &[]);
    mock.dell_controller(0x10);
    mock.dell_reply(0x30, 0xBA, 0, &[3]);
    mock.identity(674, 0x1234); // write is sent, but its response is lost
                                // No reply to the write: its outcome is unknown. No replay.
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    dell.set_power_budget(WriteIntent, 95).unwrap();
    assert!(matches!(
        dell.set_power_cap_enabled(WriteIntent, false),
        Err(DellError::Dispatch(OemError::Command(
            IpmiError::Connection(MockError::Timeout)
        )))
    ));
    let sent = ipmi.release().sent;
    assert_pairs(
        &sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, VALIDATOR),
            (0x30, 0xBA, &[1, 0xFF]),
            (6, 0x59, &[0, 0xEA, 0, 0]),
            (6, 0x58, &[0xEA, 95, 0, 0, 100, 0, 80, 0, 2, 110, 0, 3, 0]),
            (6, 0x59, VALIDATOR),
            (0x30, 0xBA, &[1, 0xFF]),
            (0x30, 0xBA, &[0, 0]),
        ],
    );
}

#[test]
fn dell_power_read_only_and_out_of_range_prevent_writes() {
    let mut mock = Mock::default();
    mock.dell_controller(0x10);
    mock.dell_controller(0x10);
    mock.dell_reply(0x30, 0xBA, 0, &[1]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert!(matches!(
        dell.set_power_budget(WriteIntent, 90),
        Err(DellError::Capability("power cap disabled or read-only"))
    ));
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, VALIDATOR),
            (0x30, 0xBA, &[1, 0xFF]),
        ],
    );

    let mut mock = Mock::default();
    mock.dell_controller(0x20);
    mock.dell_controller(0x20);
    mock.dell_reply(0x30, 0xBA, 0, &[3]);
    mock.dell_reply(
        6,
        0x59,
        0,
        &[0x11, 90, 0, 0, 100, 0, 80, 0, 2, 0, 110, 0, 3, 0, 0, 0],
    );
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert!(matches!(
        dell.set_power_budget(WriteIntent, 101),
        Err(DellError::InvalidInput(_))
    ));
    assert_eq!(ipmi.release().sent.len(), 8); // only four read commands
}

#[test]
fn dell_clear_requires_readable_monitor_and_uses_correct_selector() {
    let mut mock = Mock::default();
    mock.dell_controller(0x0A);
    mock.dell_controller(0x0A);
    mock.dell_reply(0x30, 0x9C, 0, &[0; 24]);
    mock.dell_reply(0x30, 0x9D, 0, &[]);
    let mut ipmi = Ipmi::new(mock);
    ipmi.dell()
        .unwrap()
        .clear_power(WriteIntent, ClearPower::Peak)
        .unwrap();
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, VALIDATOR),
            (0x30, 0x9C, &[7, 1]),
            (0x30, 0x9D, &[7, 1, 2]),
        ],
    );
}

#[test]
fn dell_vflash_card_is_local_only_and_reports_license_and_health() {
    let mut mock = Mock::default();
    mock.dell_controller(0x21);
    mock.dell_reply(0x30, 0xA4, 0, &[0, 0xFD, 0, 4, 0, 0, 0, 2, 0, 0, 3, 0]);
    mock.dell_reply(0x30, 0xA4, 0, &[0x33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    let card = dell.vflash_sd_card(LocalVflash::Open).unwrap();
    assert_eq!(card.size_mb, 1024);
    assert_eq!(card.available_mb, 512);
    assert_eq!(card.health, SdHealth::Warning);
    assert!(card.licensed && card.initialized && card.enabled);
    assert!(matches!(
        dell.vflash_sd_card(LocalVflash::Wmi),
        Err(DellError::Dispatch(OemError::Command(IpmiError::Command {
            error: DecodeError::Unlicensed,
            ..
        })))
    ));
    assert_pairs(
        &ipmi.release().sent,
        &[
            (6, 0x59, VALIDATOR),
            (0x30, 0xA4, &[0, 0]),
            (0x30, 0xA4, &[0, 0]),
        ],
    );
}

#[test]
fn dell_licensed_or_unsupported_reply_preserves_completion_code() {
    let mut mock = Mock::default();
    mock.dell_controller(0x10);
    mock.dell_reply(0x30, 0xBB, 0x6F, &[]);
    mock.dell_reply(0x30, 0xB3, 0xC1, &[]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert!(matches!(
        dell.power_headroom(),
        Err(DellError::Dispatch(OemError::Command(IpmiError::Command {
            error: DecodeError::Unlicensed,
            completion_code: Some(_),
            ..
        })))
    ));
    assert!(matches!(
        dell.instant_power(),
        Err(DellError::Dispatch(OemError::Command(IpmiError::Command {
            error: DecodeError::Unsupported,
            ..
        })))
    ));
    assert_eq!(ipmi.release().sent.len(), 6);
}

#[test]
fn dell_lcd_model_qualifier_error_display_and_lock_use_app_selectors() {
    let config = [0x11, 1, 0, 0, 0, 0x10, 0x33, 1, 2, 3, 4, 2, 0x55];
    let writable = [0x11, 0, 0, 8, 9];
    let mut mock = Mock::default();
    mock.dell_controller(0x0A);
    mock.dell_reply(6, 0x59, 0, &writable);
    mock.dell_reply(6, 0x59, 0, &[0x11, 0, 0, 5, b'R', b'6', b'3', b'0', b'-']);
    mock.dell_controller(0x0A);
    mock.dell_reply(6, 0x59, 0, &writable);
    mock.dell_reply(6, 0x59, 0, &writable);
    mock.dell_reply(6, 0x59, 0, &config);
    mock.dell_reply(6, 0x58, 0, &[]);
    mock.dell_controller(0x0A);
    mock.dell_reply(6, 0x59, 0, &writable);
    mock.dell_reply(6, 0x59, 0, &writable);
    mock.dell_reply(6, 0x59, 0, &config);
    mock.dell_reply(6, 0x58, 0, &[]);
    mock.dell_controller(0x0A);
    mock.dell_reply(6, 0x59, 0, &writable);
    mock.dell_reply(6, 0x58, 0, &[]);
    let mut ipmi = Ipmi::new(mock);
    let mut dell = ipmi.dell().unwrap();
    assert_eq!(dell.lcd_model_name().unwrap(), "R630-");
    dell.set_lcd_qualifier(WriteIntent, true, true).unwrap();
    dell.set_lcd_error_display(WriteIntent, true).unwrap();
    dell.set_lcd_lock(WriteIntent, LcdLock::ViewOnly).unwrap();
    let sent = ipmi.release().sent;
    assert_pairs(
        &sent,
        &[
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xE7, 0, 0]),
            (6, 0x59, &[0, 0xD1, 0, 0]),
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xE7, 0, 0]),
            (6, 0x59, &[0, 0xE7, 0, 0]),
            (6, 0x59, &[0, 0xC2, 0, 0]),
            (
                6,
                0x58,
                &[0xC2, 1, 0, 0, 0, 0x13, 0x33, 1, 2, 3, 4, 2, 0x55],
            ),
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xE7, 0, 0]),
            (6, 0x59, &[0, 0xE7, 0, 0]),
            (6, 0x59, &[0, 0xC2, 0, 0]),
            (
                6,
                0x58,
                &[0xC2, 1, 0, 0, 0, 0x10, 0x33, 1, 2, 3, 4, 1, 0x55],
            ),
            (6, 0x59, VALIDATOR),
            (6, 0x59, &[0, 0xE7, 0, 0]),
            (6, 0x58, &[0xE7, 0, 1, 8, 9]),
        ],
    );
}

#[test]
fn dell_led_bad_mapping_and_generation_rejection_send_no_mutation() {
    let mut mock = Mock::default();
    mock.dell_controller(0x10);
    mock.dell_controller(0x10);
    mock.dell_reply(0x30, 0xD5, 0, &[1]);
    mock.dell_reply(0x30, 0xD5, 0, &[0, 0, 0, 0, 0, 0, 0, 0xFF, 3]);
    let mut ipmi = Ipmi::new(mock);
    let result = ipmi.dell().unwrap().set_drive_led(
        WriteIntent,
        DriveBdf::new(0, 0, 0).unwrap(),
        &[DriveLed::Identify],
    );
    assert!(matches!(
        result,
        Err(DellError::Dispatch(OemError::Command(IpmiError::Command {
            error: DecodeError::Unsupported,
            ..
        })))
    ));
    assert_eq!(ipmi.release().sent.len(), 8); // no D5 set

    let mut mock = Mock::default();
    mock.dell_controller(0x08);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.dell().unwrap().vflash_sd_card(LocalVflash::Open),
        Err(DellError::UnsupportedGeneration(Controller::Idrac10))
    ));
    assert_pairs(&ipmi.release().sent, &[(6, 0x59, VALIDATOR)]);

    let mut mock = Mock::default();
    mock.dell_controller(0x21);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.dell().unwrap().set_nic_mode(
            WriteIntent,
            NicMode::Modern {
                shared_lom: Some(1),
                failover: Failover::None
            }
        ),
        Err(DellError::UnsupportedGeneration(Controller::Idrac13 {
            modular: true
        }))
    ));
    assert_pairs(&ipmi.release().sent, &[(6, 0x59, VALIDATOR)]);
}
