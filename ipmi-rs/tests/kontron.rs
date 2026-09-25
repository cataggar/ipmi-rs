use std::{collections::HashMap, time::Duration};

use ipmi_rs::{
    connection::{
        Address, Channel, IpmiConnection, LogicalUnit, Message, NetFn, Request,
        RequestTargetAddress, Response,
    },
    oem::{
        kontron::{BootDevice, GetManufacturingDate, GetSerialNumber, SerialError},
        OemCommand, OemError,
    },
    rmcp::Rmcp,
    storage::fru::{FruAccess, FruDevice, FruInventory},
    Ipmi, IpmiError, KontronArea, KontronBootError, KontronBufferFailure, KontronBufferStep,
    KontronFruError, KontronWriteApproval, KontronWriteFailure,
};

fn original_image() -> Vec<u8> {
    include_str!("../../ipmi-rs-core/src/storage/fru/fixtures/inventory.hex")
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

fn compact_image() -> Vec<u8> {
    let mut header = vec![1u8, 0, 0, 1, 3, 0, 0, 0];
    let mut board = vec![
        1, 2, 0, 0x10, 0x20, 0x30, 0xc0, 0xc0, 0xc2, b'B', b'0', 0xc0, 0xc0, 0xc1,
    ];
    let mut product = vec![
        1, 2, 0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc2, b'S', b'0', 0xc0, 0xc0, 0xc1,
    ];
    for area in [&mut header, &mut board, &mut product] {
        if area.len() > 8 {
            area.resize(15, 0);
        } else {
            area.pop();
        }
        let sum = area.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        area.push(sum.wrapping_neg());
    }
    header.extend(board);
    header.extend(product);
    assert_eq!(header.len(), 40);
    FruInventory::parse(&header).unwrap();
    header
}

fn approve() -> KontronWriteApproval {
    KontronWriteApproval::acknowledge_risk()
}

fn bridged() -> FruDevice {
    FruDevice {
        id: 0,
        target: Some((Address(0x82), Channel::new(2).unwrap())),
        lun: LogicalUnit::Zero,
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Sent {
    netfn: u8,
    command: u8,
    data: Vec<u8>,
    target: RequestTargetAddress,
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    TimeoutBefore,
    TimeoutAfter,
    Reject,
    ShortAck,
}

#[derive(Default)]
struct Mock {
    sent: Vec<Sent>,
    image: Vec<u8>,
    access: Option<FruAccess>,
    manufacturer: u32,
    product: u16,
    remote_manufacturer: u32,
    remote_product: Option<u16>,
    remote_product_changes_after: Option<usize>,
    remote_identity_calls: usize,
    serial: Vec<u8>,
    date: [u8; 3],
    faults: HashMap<(u8, u8, usize), Fault>,
    calls: HashMap<(u8, u8), usize>,
    corrupt_after_write: bool,
    read_limit: Option<usize>,
    sequence_budget: Option<usize>,
    reserved_sequences: Option<usize>,
    local_buffers: [u8; 2],
    remote_buffer: u8,
}

impl Mock {
    fn new() -> Self {
        Self {
            image: original_image(),
            access: Some(FruAccess::Byte),
            manufacturer: 15000,
            product: 6012,
            remote_manufacturer: 15000,
            serial: b"Z123".to_vec(),
            date: [1, 2, 3],
            ..Default::default()
        }
    }

    fn fail(&mut self, netfn: u8, command: u8, nth: usize, fault: Fault) {
        self.faults.insert((netfn, command, nth), fault);
    }

    fn count(&self, netfn: u8, command: u8) -> usize {
        *self.calls.get(&(netfn, command)).unwrap_or(&0)
    }

    fn response(netfn: u8, command: u8, code: u8, bytes: &[u8]) -> Response {
        let mut data = vec![code];
        data.extend_from_slice(bytes);
        Response::new(Message::new_response(NetFn::from(netfn), command, data), 0).unwrap()
    }

    fn is_remote(target: RequestTargetAddress) -> bool {
        matches!(target, RequestTargetAddress::BmcOrIpmb(..))
    }
}

#[derive(Debug, PartialEq)]
enum MockError {
    Lost,
}

impl IpmiConnection for Mock {
    type SendError = MockError;
    type RecvError = MockError;
    type Error = MockError;

    fn supports_long_mutation_workflows(&self) -> bool {
        self.sequence_budget.is_none()
    }

    fn send(&mut self, _: &mut Request) -> Result<(), MockError> {
        unreachable!()
    }

    fn recv(&mut self) -> Result<Response, MockError> {
        unreachable!()
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, MockError> {
        let (netfn, command) = (request.netfn_raw(), request.cmd());
        let data = request.data().to_vec();
        let target = request.target();
        self.sent.push(Sent {
            netfn,
            command,
            data: data.clone(),
            target,
        });
        if let Some(available) = &mut self.sequence_budget {
            let used = if Mock::is_remote(target) { 2 } else { 1 };
            assert!(*available >= used);
            *available -= used;
            if let Some(reserved) = &mut self.reserved_sequences {
                assert!(*reserved >= used);
                *reserved -= used;
            }
        }
        let count = self.calls.entry((netfn, command)).or_default();
        *count += 1;
        let fault = self.faults.get(&(netfn, command, *count)).copied();
        if matches!(fault, Some(Fault::TimeoutBefore | Fault::TimeoutAfter)) && command != 0x12 {
            return Err(MockError::Lost);
        }
        if matches!(fault, Some(Fault::Reject)) {
            return Ok(Self::response(netfn, command, 0x80, &[]));
        }
        if netfn == 0x0a
            && command == 0x11
            && self
                .read_limit
                .is_some_and(|limit| data[3] as usize > limit)
        {
            return Ok(Self::response(netfn, command, 0xca, &[]));
        }
        let result = match (netfn, command) {
            (0x06, 0x01) => {
                assert_eq!(target.lun(), LogicalUnit::Zero);
                if Self::is_remote(target) {
                    self.remote_identity_calls += 1;
                }
                let vendor = if Self::is_remote(target) {
                    self.remote_manufacturer
                } else {
                    self.manufacturer
                }
                .to_le_bytes();
                let product = if Self::is_remote(target) {
                    if self
                        .remote_product_changes_after
                        .is_some_and(|limit| self.remote_identity_calls > limit)
                    {
                        6011
                    } else {
                        self.remote_product.unwrap_or(self.product)
                    }
                } else {
                    self.product
                }
                .to_le_bytes();
                vec![
                    1, 1, 1, 0x23, 0x51, 0, vendor[0], vendor[1], vendor[2], product[0], product[1],
                ]
            }
            (0x3e, 0x0c) => {
                assert_eq!(target.lun(), LogicalUnit::Three);
                assert_eq!(data, [0xb4, 0x90, 0x91, 0x8b]);
                self.serial.clone()
            }
            (0x3e, 0x0e) => {
                assert_eq!(target.lun(), LogicalUnit::Three);
                assert_eq!(data, [0xb4, 0x90, 0x91, 0x8b]);
                self.date.to_vec()
            }
            (0x3e, 0x02) => {
                assert_eq!(target.lun(), LogicalUnit::Three);
                assert_eq!(&data[..5], [0xb4, 0x90, 0x91, 0x8b, 0x9d]);
                assert_eq!(data.len(), 7);
                assert_eq!(data[6], 0xff);
                vec![]
            }
            (0x3e, 0x82) => {
                assert_eq!(target.lun(), LogicalUnit::Zero);
                assert!(data[0] == 0 || data[0] == 0x0e);
                if Self::is_remote(target) {
                    self.remote_buffer = data[1];
                } else {
                    self.local_buffers[usize::from(data[0] == 0)] = data[1];
                }
                vec![]
            }
            (0x0a, 0x10) => {
                assert_eq!(data, [0]);
                let mut result = self.image.len().to_le_bytes()[..2].to_vec();
                result.push(u8::from(self.access == Some(FruAccess::Word)));
                result
            }
            (0x0a, 0x11) => {
                assert_eq!(data[0], 0);
                let unit = if self.access == Some(FruAccess::Word) {
                    2
                } else {
                    1
                };
                let offset = u16::from_le_bytes([data[1], data[2]]) as usize * unit;
                let length = data[3] as usize;
                let mut result = vec![(length / unit) as u8];
                result.extend_from_slice(&self.image[offset..offset + length]);
                result
            }
            (0x0a, 0x12) => {
                assert_eq!(data[0], 0);
                let unit = if self.access == Some(FruAccess::Word) {
                    2
                } else {
                    1
                };
                let offset = u16::from_le_bytes([data[1], data[2]]) as usize * unit;
                let length = data.len() - 3;
                if !matches!(fault, Some(Fault::TimeoutBefore)) {
                    self.image[offset..offset + length].copy_from_slice(&data[3..]);
                }
                if self.corrupt_after_write {
                    self.image[17] = 0xee;
                }
                if matches!(fault, Some(Fault::TimeoutBefore | Fault::TimeoutAfter)) {
                    return Err(MockError::Lost);
                }
                vec![(length / unit) as u8 - u8::from(matches!(fault, Some(Fault::ShortAck)))]
            }
            _ => panic!("unexpected request {netfn:02x}/{command:02x}"),
        };
        Ok(Self::response(netfn, command, 0, &result))
    }

    fn ipmb_sequence_budget(&self) -> Option<usize> {
        self.sequence_budget
    }

    fn reserve_ipmb_sequences(&mut self, minimum: usize) -> bool {
        if self.reserved_sequences.is_some() || self.sequence_budget.is_none_or(|n| n < minimum) {
            return false;
        }
        self.reserved_sequences = Some(minimum);
        true
    }

    fn release_ipmb_sequences(&mut self) {
        self.reserved_sequences = None;
    }
}

struct PlainForward<T>(T);

impl<T: IpmiConnection> IpmiConnection for PlainForward<T> {
    type SendError = T::SendError;
    type RecvError = T::RecvError;
    type Error = T::Error;

    fn send(&mut self, request: &mut Request) -> Result<(), Self::SendError> {
        self.0.send(request)
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        self.0.recv()
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.0.send_recv(request)
    }
}

#[test]
fn source_oem_fixtures_and_cp6012_gate_use_explicit_routing() {
    let target = bridged().target;
    let mut ipmi = Ipmi::new(Mock::new());
    assert_eq!(
        ipmi.send_oem(GetManufacturingDate.at(target)).unwrap(),
        [1, 2, 3]
    );
    assert_eq!(ipmi.send_oem(GetSerialNumber.at(target)).unwrap(), b"Z123");
    ipmi.kontron_set_next_boot(target, BootDevice::Network, approve())
        .unwrap();
    let requests = ipmi.release().sent;
    for pair in requests.chunks(2) {
        assert_eq!(pair[0].netfn, 6);
        assert_eq!(pair[0].command, 1);
        assert_eq!(
            pair[0].target,
            RequestTargetAddress::BmcOrIpmb(
                Address(0x82),
                Channel::new(2).unwrap(),
                LogicalUnit::Zero
            )
        );
        assert_eq!(pair[1].target.lun(), LogicalUnit::Three);
        assert_eq!(pair[1].data[..4], [0xb4, 0x90, 0x91, 0x8b]);
    }
    assert_eq!(requests[1].command, 0x0e);
    assert_eq!(requests[3].command, 0x0c);
    assert_eq!(requests[5].data, [0xb4, 0x90, 0x91, 0x8b, 0x9d, 4, 0xff]);
}

#[test]
fn vendor_product_mismatch_and_lost_nextboot_never_send_or_replay() {
    let mut mock = Mock::new();
    mock.product = 6011;
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.kontron_set_next_boot(None, BootDevice::Bios, approve()),
        Err(KontronBootError::Command(OemError::UnsupportedDevice {
            expected_product_id: Some(6012),
            ..
        }))
    ));
    assert_eq!(ipmi.release().sent.len(), 1);

    let mut mock = Mock::new();
    mock.fail(0x3e, 0x02, 1, Fault::TimeoutBefore);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.kontron_set_next_boot(None, BootDevice::Bios, approve()),
        Err(KontronBootError::Command(OemError::Command(
            IpmiError::Connection(MockError::Lost)
        )))
    ));
    assert_eq!(ipmi.release().count(0x3e, 0x02), 1);
}

#[test]
fn serial_preparation_backs_up_both_areas_and_writes_only_changed_areas() {
    for access in [FruAccess::Byte, FruAccess::Word] {
        let mut mock = Mock::new();
        mock.access = Some(access);
        let mut ipmi = Ipmi::new(mock);
        let change = ipmi.prepare_kontron_serial(bridged()).unwrap();
        assert_eq!(change.backup().image(), original_image());
        assert_eq!(change.backup().board().len(), 40);
        assert_eq!(change.backup().product().len(), 40);
        assert_eq!(change.backup().board()[39], 0xd3);
        assert_eq!(change.backup().product()[39], 0x2f);
        assert_eq!(change.proposed_image()[71], 0xb6);
        assert_eq!(change.proposed_image()[111], 0x23);
        assert_eq!(
            FruInventory::parse(change.proposed_image())
                .unwrap()
                .board
                .unwrap()
                .serial_number
                .text
                .as_deref(),
            Some("Z123")
        );
        assert_eq!(ipmi.inner_mut().count(0x0a, 0x12), 0);
        ipmi.apply_kontron_fru_change(&change, approve()).unwrap();
        let mock = ipmi.release();
        assert_eq!(mock.image, change.proposed_image());
        let writes: Vec<_> = mock
            .sent
            .iter()
            .filter(|sent| (sent.netfn, sent.command) == (0x0a, 0x12))
            .collect();
        assert_eq!(writes.len(), 6);
        let unit = if access == FruAccess::Byte { 1 } else { 2 };
        assert_eq!(writes[0].data[..3], [0, (32 / unit) as u8, 0]);
        assert_eq!(writes[3].data[..3], [0, (72 / unit) as u8, 0]);
        assert!(writes.iter().all(|write| write.target
            == RequestTargetAddress::BmcOrIpmb(
                Address(0x82),
                Channel::new(2).unwrap(),
                LogicalUnit::Zero
            )));
    }
}

#[test]
fn remote_128_and_256_byte_images_fail_budget_before_any_write() {
    for size in [128, 256] {
        let mut mock = Mock::new();
        mock.image.resize(size, 0);
        mock.sequence_budget = Some(64);
        let mut ipmi = Ipmi::new(mock);
        let change = ipmi.prepare_kontron_serial(bridged()).unwrap();
        let available = ipmi.inner_mut().ipmb_sequence_budget().unwrap();
        let result = ipmi.apply_kontron_fru_change(&change, approve());
        assert!(matches!(
            result,
            Err(KontronFruError::SequenceBudget {
                needed,
                available: observed
            }) if needed > observed && observed == available
        ));
        let mock = ipmi.release();
        assert_eq!(mock.count(0x0a, 0x12), 0);
        assert_eq!(mock.sequence_budget, Some(available));
        assert!(mock.reserved_sequences.is_none());
    }
}

#[test]
fn opaque_delegating_rmcp_wrapper_fails_closed_before_any_write() {
    let mut mock = Mock::new();
    mock.sequence_budget = Some(64);
    let mut ipmi = Ipmi::new(PlainForward(mock));
    let change = ipmi.prepare_kontron_serial(bridged()).unwrap();
    assert!(matches!(
        ipmi.apply_kontron_fru_change(&change, approve()),
        Err(KontronFruError::UnverifiedSequenceBudget)
    ));
    let wrapper = ipmi.release();
    assert_eq!(wrapper.0.count(0x0a, 0x12), 0);
    assert_eq!(wrapper.0.sequence_budget, Some(36));

    let rmcp = Rmcp::new("127.0.0.1:623", Duration::from_millis(10)).unwrap();
    let mut ipmi = Ipmi::new(PlainForward(rmcp));
    assert!(matches!(
        ipmi.apply_kontron_fru_change(&change, approve()),
        Err(KontronFruError::UnverifiedSequenceBudget)
    ));
    assert!(!ipmi.release().0.is_active());
}

#[test]
fn unknown_budget_blocks_boot_and_buffer_without_even_an_identity_probe() {
    let mut ipmi = Ipmi::new(PlainForward(Mock::new()));
    assert!(matches!(
        ipmi.kontron_set_next_boot(None, BootDevice::Bios, approve()),
        Err(KontronBootError::UnverifiedSequenceBudget)
    ));
    assert!(matches!(
        ipmi.kontron_set_large_buffer(bridged().target, 64),
        Err(ipmi_rs::KontronBufferError {
            source: KontronBufferFailure::UnverifiedSequenceBudget,
            ..
        })
    ));
    assert!(ipmi.release().0.sent.is_empty());
}

#[test]
fn small_bridged_fru_can_write_and_verify_inside_64_sequence_session() {
    let mut mock = Mock::new();
    mock.image = compact_image();
    mock.serial = b"Z1".to_vec();
    mock.sequence_budget = Some(64);
    let mut ipmi = Ipmi::new(mock);
    let change = ipmi.prepare_kontron_serial(bridged()).unwrap();
    assert_eq!(change.backup().board().len(), 16);
    assert_eq!(change.backup().product().len(), 16);
    ipmi.apply_kontron_fru_change(&change, approve()).unwrap();
    let mock = ipmi.release();
    assert_eq!(mock.image, change.proposed_image());
    assert_eq!(mock.count(0x0a, 0x12), 2);
    assert!(mock.sequence_budget.unwrap() > 0);
    assert!(mock.reserved_sequences.is_none());
}

#[test]
fn audited_local_mutation_and_mutable_connection_reference_remain_supported() {
    let mut mock = Mock::new();
    let mut ipmi = Ipmi::new(&mut mock);
    let change = ipmi.prepare_kontron_mfg_date(FruDevice::BUILTIN).unwrap();
    ipmi.apply_kontron_fru_change(&change, approve()).unwrap();
    ipmi.release();
    assert_eq!(mock.count(0x0a, 0x12), 3);
}

#[test]
fn read_shrink_spends_budget_before_write_and_fails_closed() {
    let mut mock = Mock::new();
    mock.image = compact_image();
    mock.serial = b"Z1".to_vec();
    mock.sequence_budget = Some(50);
    let mut ipmi = Ipmi::new(mock);
    let change = ipmi.prepare_kontron_serial(bridged()).unwrap();
    ipmi.inner_mut().read_limit = Some(8);
    assert!(matches!(
        ipmi.apply_kontron_fru_change(&change, approve()),
        Err(KontronFruError::SequenceBudget { .. })
    ));
    assert_eq!(ipmi.release().count(0x0a, 0x12), 0);
}

#[test]
fn exhausted_bridge_budget_rejects_boot_and_buffer_before_mutation() {
    let mut mock = Mock::new();
    mock.sequence_budget = Some(3);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.kontron_set_next_boot(bridged().target, BootDevice::Bios, approve()),
        Err(KontronBootError::SequenceBudget {
            needed: 4,
            available: 3
        })
    ));
    assert!(matches!(
        ipmi.kontron_set_large_buffer(bridged().target, 32),
        Err(ipmi_rs::KontronBufferError {
            source: KontronBufferFailure::SequenceBudget { .. },
            ..
        })
    ));
    assert!(ipmi.release().sent.is_empty());
}

#[test]
fn manufacturing_date_changes_board_only_and_rechecks_image() {
    let mut ipmi = Ipmi::new(Mock::new());
    let change = ipmi.prepare_kontron_mfg_date(FruDevice::BUILTIN).unwrap();
    assert_eq!(&change.proposed_image()[35..38], [1, 2, 3]);
    assert_eq!(change.proposed_image()[71], 0x2d);
    assert_eq!(&change.proposed_image()[72..112], change.backup().product());
    ipmi.apply_kontron_fru_change(&change, approve()).unwrap();
    assert_eq!(ipmi.release().count(0x0a, 0x12), 3);
}

#[test]
fn invalid_serial_or_inventory_or_wrong_target_cannot_write() {
    for serial in [vec![], vec![0x1b; 4], vec![b'A'; 64], b"TOO".to_vec()] {
        let mut mock = Mock::new();
        mock.serial = serial;
        let mut ipmi = Ipmi::new(mock);
        assert!(ipmi.prepare_kontron_serial(FruDevice::BUILTIN).is_err());
        assert_eq!(ipmi.release().count(0x0a, 0x12), 0);
    }
    assert_eq!(
        GetSerialNumber::parse_success_response(&[0]),
        Err(SerialError::NonPrintable)
    );
    let mut mock = Mock::new();
    mock.image[71] ^= 1;
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.prepare_kontron_serial(FruDevice::BUILTIN),
        Err(KontronFruError::Inventory(_))
    ));
    assert_eq!(ipmi.release().count(0x0a, 0x12), 0);
    for index in [33, 73, 111] {
        let mut mock = Mock::new();
        mock.image[index] ^= 1;
        let mut ipmi = Ipmi::new(mock);
        assert!(matches!(
            ipmi.prepare_kontron_mfg_date(FruDevice::BUILTIN),
            Err(KontronFruError::Inventory(_))
        ));
        assert_eq!(ipmi.release().count(0x0a, 0x12), 0);
    }
    let mut mock = Mock::new();
    mock.image[4] = 0;
    mock.image[7] = mock.image[..7]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
        .wrapping_neg();
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.prepare_kontron_mfg_date(FruDevice::BUILTIN),
        Err(KontronFruError::MissingArea)
    ));
    assert_eq!(ipmi.release().count(0x0a, 0x12), 0);

    let mut mock = Mock::new();
    mock.remote_manufacturer = 42;
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.prepare_kontron_serial(bridged()),
        Err(KontronFruError::Identity(
            OemError::UnsupportedDevice { .. }
        ))
    ));
    assert_eq!(ipmi.release().sent.len(), 1);
    let mut ipmi = Ipmi::new(Mock::new());
    assert!(matches!(
        ipmi.prepare_kontron_serial(FruDevice {
            id: 1,
            ..FruDevice::BUILTIN
        }),
        Err(KontronFruError::UnsupportedFru)
    ));
    assert!(ipmi.release().sent.is_empty());
}

#[test]
fn restoration_requires_a_separate_approval_and_rejects_other_image_changes() {
    let mut mock = Mock::new();
    mock.fail(0x0a, 0x12, 2, Fault::TimeoutAfter);
    let mut ipmi = Ipmi::new(mock);
    let change = ipmi.prepare_kontron_serial(FruDevice::BUILTIN).unwrap();
    assert!(matches!(
        ipmi.apply_kontron_fru_change(&change, approve()),
        Err(KontronFruError::Write {
            area: KontronArea::Board,
            offset: 48,
            ..
        })
    ));
    assert_eq!(ipmi.inner_mut().count(0x0a, 0x12), 2);
    ipmi.restore_kontron_fru_backup(&change, approve()).unwrap();
    assert_eq!(ipmi.inner_mut().image, original_image());
    assert_eq!(ipmi.inner_mut().count(0x0a, 0x12), 5);

    ipmi.inner_mut().image[17] ^= 1;
    assert!(matches!(
        ipmi.restore_kontron_fru_backup(&change, approve()),
        Err(KontronFruError::InventoryChanged)
    ));
    assert_eq!(ipmi.release().count(0x0a, 0x12), 5);
}

#[test]
fn changed_identity_or_image_at_apply_time_sends_no_writes() {
    let mut ipmi = Ipmi::new(Mock::new());
    let change = ipmi.prepare_kontron_serial(FruDevice::BUILTIN).unwrap();
    ipmi.inner_mut().product = 6011;
    assert!(matches!(
        ipmi.apply_kontron_fru_change(&change, approve()),
        Err(KontronFruError::TargetChanged)
    ));
    assert_eq!(ipmi.release().count(0x0a, 0x12), 0);

    let mut ipmi = Ipmi::new(Mock::new());
    let change = ipmi.prepare_kontron_serial(FruDevice::BUILTIN).unwrap();
    ipmi.inner_mut().image[23] ^= 1;
    assert!(matches!(
        ipmi.apply_kontron_fru_change(&change, approve()),
        Err(KontronFruError::InventoryChanged)
    ));
    assert_eq!(ipmi.release().count(0x0a, 0x12), 0);
}

#[test]
fn failed_partial_serial_write_returns_observation_and_never_replays() {
    for fault in [
        Fault::TimeoutBefore,
        Fault::TimeoutAfter,
        Fault::Reject,
        Fault::ShortAck,
    ] {
        let mut mock = Mock::new();
        mock.fail(0x0a, 0x12, 4, fault);
        let mut ipmi = Ipmi::new(mock);
        let change = ipmi.prepare_kontron_serial(FruDevice::BUILTIN).unwrap();
        let error = ipmi
            .apply_kontron_fru_change(&change, approve())
            .unwrap_err();
        match error {
            KontronFruError::Write {
                area: KontronArea::Product,
                offset: 72,
                bytes_confirmed: 0,
                reason,
                observed: Ok(bytes),
            } => {
                assert_eq!(bytes.len(), 128);
                if matches!(fault, Fault::ShortAck) {
                    assert!(matches!(reason, KontronWriteFailure::Count(_)));
                } else {
                    assert!(matches!(reason, KontronWriteFailure::Command(_)));
                }
            }
            other => panic!("unexpected failure: {other:?}"),
        }
        assert_eq!(change.backup().image(), original_image());
        assert_eq!(ipmi.release().count(0x0a, 0x12), 4);
    }
}

#[test]
fn postwrite_mismatch_is_reported_without_automatic_recovery() {
    let mut ipmi = Ipmi::new(Mock::new());
    let change = ipmi.prepare_kontron_serial(FruDevice::BUILTIN).unwrap();
    ipmi.inner_mut().corrupt_after_write = true;
    assert!(matches!(
        ipmi.apply_kontron_fru_change(&change, approve()),
        Err(KontronFruError::ReadbackMismatch(_))
    ));
    assert_eq!(ipmi.release().count(0x0a, 0x12), 6);
}

#[test]
fn buffer_setup_routes_local_and_remote_and_restores_all_attempted_channels() {
    let destination = bridged().target;
    let mut ipmi = Ipmi::new(Mock::new());
    ipmi.kontron_set_large_buffer(destination, 64).unwrap();
    let commands: Vec<_> = ipmi
        .release()
        .sent
        .into_iter()
        .filter(|sent| sent.command == 0x82)
        .collect();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0].data, [0x0e, 64]);
    assert_eq!(commands[1].data, [0, 64]);
    assert_eq!(commands[2].data, [0x0e, 64]);
    assert!(matches!(
        commands[0].target,
        RequestTargetAddress::Bmc(LogicalUnit::Zero)
    ));
    assert!(matches!(
        commands[2].target,
        RequestTargetAddress::BmcOrIpmb(..)
    ));

    for failed_step in 1..=3 {
        let mut mock = Mock::new();
        mock.fail(0x3e, 0x82, failed_step, Fault::TimeoutBefore);
        let mut ipmi = Ipmi::new(mock);
        let error = ipmi.kontron_set_large_buffer(destination, 64).unwrap_err();
        assert!(error.restore.is_empty());
        assert_eq!(
            error.step,
            [
                KontronBufferStep::LocalCurrent,
                KontronBufferStep::LocalIpmb,
                KontronBufferStep::RemoteCurrent
            ][failed_step - 1]
        );
        let requests: Vec<_> = ipmi
            .release()
            .sent
            .into_iter()
            .filter(|sent| sent.command == 0x82)
            .collect();
        assert_eq!(requests.len(), failed_step * 2);
        assert_eq!(requests[failed_step].data[1], 0);
        assert_eq!(
            requests.last().unwrap().data,
            [0x0e, 0],
            "local current restored last"
        );
    }
}

#[test]
fn buffer_restore_failure_is_reported_and_remote_vendor_is_never_sent_oem() {
    let mut mock = Mock::new();
    mock.fail(0x3e, 0x82, 3, Fault::TimeoutAfter);
    mock.fail(0x3e, 0x82, 4, Fault::Reject);
    let mut ipmi = Ipmi::new(mock);
    let error = ipmi
        .kontron_set_large_buffer(bridged().target, 80)
        .unwrap_err();
    assert_eq!(error.step, KontronBufferStep::RemoteCurrent);
    assert_eq!(error.restore.len(), 1);
    assert_eq!(error.restore[0].0, KontronBufferStep::RemoteCurrent);

    let mut mock = Mock::new();
    mock.remote_manufacturer = 42;
    mock.local_buffers = [48, 64];
    mock.remote_buffer = 32;
    let mut ipmi = Ipmi::new(mock);
    let error = ipmi
        .kontron_set_large_buffer(bridged().target, 80)
        .unwrap_err();
    assert_eq!(error.step, KontronBufferStep::RemoteCurrent);
    assert!(matches!(
        error.source,
        KontronBufferFailure::Identity(OemError::UnsupportedDevice { .. })
    ));
    assert!(error.restore.is_empty());
    let mock = ipmi.release();
    assert_eq!(mock.local_buffers, [48, 64]);
    assert_eq!(mock.remote_buffer, 32);
    let requests = mock.sent;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].command, 0x01);
    assert!(requests.iter().all(|sent| sent.command != 0x82));
}

#[test]
fn remote_product_change_after_local_setup_never_mutates_changed_remote() {
    let mut mock = Mock::new();
    mock.remote_product_changes_after = Some(1);
    let mut ipmi = Ipmi::new(mock);
    let error = ipmi
        .kontron_set_large_buffer(bridged().target, 80)
        .unwrap_err();
    assert!(matches!(error.source, KontronBufferFailure::TargetChanged));
    assert!(error.restore.is_empty());
    let mock = ipmi.release();
    assert_eq!(mock.remote_buffer, 0);
    assert_eq!(mock.local_buffers, [0, 0]);
    let buffer_commands: Vec<_> = mock
        .sent
        .iter()
        .filter(|sent| sent.command == 0x82)
        .collect();
    assert_eq!(buffer_commands.len(), 4);
    assert!(buffer_commands
        .iter()
        .all(|sent| matches!(sent.target, RequestTargetAddress::Bmc(LogicalUnit::Zero))));
}
