use ipmi_rs::{
    connection::{
        Address, Channel, IpmiConnection, LogicalUnit, Message, NetFn, Request,
        RequestTargetAddress, Response,
    },
    storage::fru::{FruAccess, FruCommandError, FruDevice, FruInfo, FruParseError},
    FruReadError, FruWriteError, Ipmi, IpmiError,
};

fn fixture() -> Vec<u8> {
    include_str!("../../ipmi-rs-core/src/storage/fru/fixtures/inventory.hex")
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

#[derive(Debug, PartialEq)]
enum MockError {
    LostResponse,
}

#[derive(Clone, Copy)]
enum WriteBehavior {
    Normal,
    LostAt(usize),
    ShortAckAt(usize),
    RejectAt(usize),
}

struct Mock {
    image: Vec<u8>,
    access: FruAccess,
    read_limit: usize,
    read_limit_code: u8,
    read_rejection: bool,
    short_read: bool,
    write_behavior: WriteBehavior,
    requests: Vec<(u8, Vec<u8>)>,
    targets: Vec<RequestTargetAddress>,
}

impl Mock {
    fn new(access: FruAccess) -> Self {
        Self {
            image: fixture(),
            access,
            read_limit: 16,
            read_limit_code: 0xca,
            read_rejection: false,
            short_read: false,
            write_behavior: WriteBehavior::Normal,
            requests: Vec::new(),
            targets: Vec::new(),
        }
    }

    fn response(&self, command: u8, cc: u8, data: &[u8]) -> Response {
        let mut body = vec![cc];
        body.extend_from_slice(data);
        Response::new(Message::new_response(NetFn::Storage, command, body), 0).unwrap()
    }
}

impl IpmiConnection for Mock {
    type SendError = MockError;
    type RecvError = MockError;
    type Error = MockError;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        unreachable!()
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        unreachable!()
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let cmd = request.cmd();
        let data = request.data().to_vec();
        self.requests.push((cmd, data.clone()));
        self.targets.push(request.target());
        assert_eq!(request.netfn(), NetFn::Storage);
        assert_eq!(data[0], 0);
        let unit = if self.access == FruAccess::Word { 2 } else { 1 };
        match cmd {
            0x10 => {
                let size = self.image.len() as u16;
                let [lo, hi] = size.to_le_bytes();
                Ok(self.response(cmd, 0, &[lo, hi, (unit - 1) as u8]))
            }
            0x11 => {
                let offset = u16::from_le_bytes([data[1], data[2]]) as usize * unit;
                let size = data[3] as usize;
                if self.read_rejection {
                    return Ok(self.response(cmd, 0xcb, &[]));
                }
                if size > self.read_limit {
                    return Ok(self.response(cmd, self.read_limit_code, &[]));
                }
                assert!(offset + size <= self.image.len());
                let returned = if self.short_read { size - unit } else { size };
                let mut result = vec![(returned / unit) as u8];
                result.extend_from_slice(&self.image[offset..offset + returned]);
                Ok(self.response(cmd, 0, &result))
            }
            0x12 => {
                let offset = u16::from_le_bytes([data[1], data[2]]) as usize * unit;
                let payload = &data[3..];
                let reject =
                    matches!(self.write_behavior, WriteBehavior::RejectAt(at) if at == offset);
                if reject {
                    return Ok(self.response(cmd, 0x80, &[]));
                }
                self.image[offset..offset + payload.len()].copy_from_slice(payload);
                if matches!(self.write_behavior, WriteBehavior::LostAt(at) if at == offset) {
                    return Err(MockError::LostResponse);
                }
                let count = if matches!(self.write_behavior, WriteBehavior::ShortAckAt(at) if at == offset)
                {
                    (payload.len() / unit - 1) as u8
                } else {
                    (payload.len() / unit) as u8
                };
                Ok(self.response(cmd, 0, &[count]))
            }
            _ => panic!("unexpected command"),
        }
    }
}

#[test]
fn discovered_target_lun_is_used_by_storage_commands() {
    let mut ipmi = Ipmi::new(Mock::new(FruAccess::Byte));
    let device = FruDevice {
        id: 0,
        target: Some((Address(0x42), Channel::new(1).unwrap())),
        lun: LogicalUnit::One,
    };
    assert_eq!(ipmi.fru_info(device).unwrap().size, 128);
    assert_eq!(
        ipmi.release().targets,
        [RequestTargetAddress::BmcOrIpmb(
            Address(0x42),
            Channel::new(1).unwrap(),
            LogicalUnit::One
        )]
    );
}

#[test]
fn byte_reads_are_bounded_and_never_mutate_inventory() {
    let mut ipmi = Ipmi::new(Mock::new(FruAccess::Byte));
    let result = ipmi.read_fru_inventory(FruDevice::BUILTIN).unwrap();
    assert_eq!(
        result.board.unwrap().product_name.text.as_deref(),
        Some("CPU")
    );
    let mock = ipmi.release();
    assert_eq!(mock.image, fixture());
    assert_eq!(mock.requests.len(), 9);
    assert_eq!(mock.requests[0], (0x10, vec![0]));
    assert_eq!(mock.requests[1], (0x11, vec![0, 0, 0, 16]));
    assert_eq!(mock.requests[8], (0x11, vec![0, 112, 0, 16]));
    assert!(mock.requests.iter().all(|(cmd, _)| *cmd != 0x12));
}

#[test]
fn word_reads_convert_offsets_and_counts_and_shrink_on_size_code() {
    for code in [0xc7, 0xc8, 0xca] {
        let mut mock = Mock::new(FruAccess::Word);
        mock.read_limit = 8;
        mock.read_limit_code = code;
        let mut ipmi = Ipmi::new(mock);
        assert_eq!(ipmi.read_fru_image(FruDevice::BUILTIN).unwrap(), fixture());
        let mock = ipmi.release();
        assert_eq!(mock.requests.len(), 18);
        assert_eq!(mock.requests[1], (0x11, vec![0, 0, 0, 16]));
        assert_eq!(mock.requests[2], (0x11, vec![0, 0, 0, 8]));
        assert_eq!(mock.requests[3], (0x11, vec![0, 4, 0, 8]));
        assert_eq!(mock.requests[17], (0x11, vec![0, 60, 0, 8]));
    }
}

#[test]
fn read_failure_does_not_fabricate_bytes_or_write_anything() {
    let mut mock = Mock::new(FruAccess::Byte);
    mock.read_rejection = true;
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.read_fru_image(FruDevice::BUILTIN),
        Err(FruReadError::Command(IpmiError::Failed { cmd: 0x11, .. }))
    ));
    assert_eq!(ipmi.release().requests.len(), 2);

    let mut mock = Mock::new(FruAccess::Byte);
    mock.short_read = true;
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.read_fru_image(FruDevice::BUILTIN),
        Err(FruReadError::Transfer(FruCommandError::UnexpectedCount))
    ));
    assert_eq!(ipmi.release().requests.len(), 2);

    let mut mock = Mock::new(FruAccess::Word);
    mock.read_limit = 0;
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.read_fru_image(FruDevice::BUILTIN),
        Err(FruReadError::Command(IpmiError::Failed { cmd: 0x11, .. }))
    ));
    assert_eq!(ipmi.release().requests.len(), 5);

    let mut mock = Mock::new(FruAccess::Byte);
    mock.image[22] ^= 1;
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.read_fru_inventory(FruDevice::BUILTIN),
        Err(FruReadError::Inventory(FruParseError::Checksum))
    ));
}

#[test]
fn validated_writes_are_explicit_chunked_and_word_addressed() {
    let source = fixture();
    let info = FruInfo {
        size: source.len() as u16,
        access: FruAccess::Word,
    };
    let mut ipmi = Ipmi::new(Mock::new(FruAccess::Word));
    ipmi.write_fru_image(FruDevice::BUILTIN, info, &source)
        .unwrap();
    let mock = ipmi.release();
    assert_eq!(mock.requests.len(), 8);
    assert!(mock.requests.iter().all(|(cmd, _)| *cmd == 0x12));
    assert_eq!(&mock.requests[1].1[..3], [0, 8, 0]);
    assert_eq!(mock.image, source);
}

#[test]
fn invalid_write_is_rejected_locally_before_sending_anything() {
    let mut source = fixture();
    source[116] ^= 1;
    let info = FruInfo {
        size: source.len() as u16,
        access: FruAccess::Byte,
    };
    let mut ipmi = Ipmi::new(Mock::new(FruAccess::Byte));
    assert!(matches!(
        ipmi.write_fru_image(FruDevice::BUILTIN, info, &source),
        Err(FruWriteError::InvalidImage(FruParseError::Checksum))
    ));
    assert!(ipmi.release().requests.is_empty());

    let mut ipmi = Ipmi::new(Mock::new(FruAccess::Byte));
    let short = FruInfo {
        size: 16,
        access: FruAccess::Byte,
    };
    assert!(matches!(
        ipmi.write_fru_image(FruDevice::BUILTIN, short, &fixture()),
        Err(FruWriteError::SizeMismatch)
    ));
    assert!(ipmi.release().requests.is_empty());
}

#[test]
fn lost_or_bad_write_acknowledgement_is_ambiguous_and_never_retried() {
    let source = fixture();
    let info = FruInfo {
        size: source.len() as u16,
        access: FruAccess::Byte,
    };
    let mut mock = Mock::new(FruAccess::Byte);
    mock.write_behavior = WriteBehavior::LostAt(16);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.write_fru_image(FruDevice::BUILTIN, info, &source),
        Err(FruWriteError::OutcomeUnknown {
            offset: 16,
            bytes_confirmed: 16,
            source: IpmiError::Connection(MockError::LostResponse),
        })
    ));
    let mock = ipmi.release();
    assert_eq!(mock.requests.len(), 2);
    assert_eq!(&mock.image[..32], &source[..32]);

    for behavior in [WriteBehavior::ShortAckAt(0), WriteBehavior::RejectAt(0)] {
        let mut mock = Mock::new(FruAccess::Byte);
        mock.write_behavior = behavior;
        let mut ipmi = Ipmi::new(mock);
        let result = ipmi.write_fru_image(FruDevice::BUILTIN, info, &source);
        match behavior {
            WriteBehavior::ShortAckAt(_) => assert!(matches!(
                result,
                Err(FruWriteError::OutcomeUnconfirmed {
                    offset: 0,
                    bytes_confirmed: 0,
                    error: FruCommandError::UnexpectedCount
                })
            )),
            WriteBehavior::RejectAt(_) => assert!(matches!(
                result,
                Err(FruWriteError::OutcomeUnknown {
                    offset: 0,
                    bytes_confirmed: 0,
                    source: IpmiError::Failed { cmd: 0x12, .. }
                })
            )),
            _ => unreachable!(),
        }
        assert_eq!(ipmi.release().requests.len(), 1);
    }
}
