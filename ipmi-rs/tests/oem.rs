use std::{cell::Cell, collections::VecDeque, num::NonZeroU8, rc::Rc};

use ipmi_rs::{
    connection::{
        Address, Channel, ChannelNumber, IpmiConnection, LogicalUnit, Message, NetFn, Request,
        RequestTargetAddress, Response,
    },
    oem::{
        dell::{GetPowerCapStatus, PowerCapStatus},
        kontron::{BootDevice, GetManufacturingDate, SetNextBoot},
        quanta::{GetPlatformId, Platform, PlatformError},
        sun::{GetVersion, VersionError},
        OemCommand, OemError,
    },
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
    let mut mock = Mock::default();
    mock.identity(7244, 77);
    mock.reply(0x36, 0x65, 0, &[2, 0]);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(ipmi.send_oem(GetPlatformId), Ok(Platform::Purley)));
    assert_eq!(
        ipmi.release().sent,
        [
            device_id_request(),
            sent(0x36, 0x65, &[0x4C, 0x1C, 0, 2], LogicalUnit::Zero),
        ]
    );
    assert_eq!(
        GetPlatformId::parse_success_response(&[0]),
        Err(PlatformError::Unsupported(0))
    );
    assert_eq!(
        GetPlatformId::parse_success_response(&[]),
        Err(PlatformError::TooShort)
    );
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
