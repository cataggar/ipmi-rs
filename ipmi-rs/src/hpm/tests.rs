use std::collections::VecDeque;

use ipmi_rs_core::{
    connection::{CompletionErrorCode, IpmiConnection, Message, NetFn, Request, Response},
    hpm::HpmResponseError,
};

#[cfg(feature = "hpm-update")]
use ipmi_rs_core::{
    app::DeviceId,
    hpm::{
        ComponentId, FirmwareVersion, GeneralProperties, GetTargetCapabilities, TargetCapabilities,
    },
};

use super::read_inventory;
#[cfg(feature = "hpm-update")]
use super::{ComponentInventory, Inventory};
use crate::{Ipmi, IpmiError};

#[derive(Debug)]
struct Exchange {
    cmd: u8,
    request: Vec<u8>,
    reply: Result<(u8, Vec<u8>), &'static str>,
    response_cmd: Option<u8>,
}

#[derive(Debug)]
struct MockController {
    script: VecDeque<Exchange>,
    sent: Vec<(u8, Vec<u8>)>,
}

impl MockController {
    fn new(script: Vec<Exchange>) -> Self {
        Self {
            script: script.into(),
            sent: Vec::new(),
        }
    }
}

impl IpmiConnection for MockController {
    type SendError = &'static str;
    type RecvError = &'static str;
    type Error = &'static str;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        panic!("test must use send_recv")
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        panic!("test must use send_recv")
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let expected = self.script.pop_front().expect("unexpected IPMI command");
        assert_eq!(request.cmd(), expected.cmd);
        assert_eq!(request.data(), expected.request);
        self.sent.push((request.cmd(), request.data().to_vec()));
        let (code, data) = expected.reply?;
        let mut packet = vec![code];
        packet.extend(data);
        Response::new(
            Message::new_response(
                request.netfn(),
                expected.response_cmd.unwrap_or(request.cmd()),
                packet,
            ),
            0,
        )
        .ok_or("invalid scripted response")
    }
}

fn good(cmd: u8, request: &[u8], response: &[u8]) -> Exchange {
    Exchange {
        cmd,
        request: request.to_vec(),
        reply: Ok((0, response.to_vec())),
        response_cmd: None,
    }
}

fn fail(cmd: u8, request: &[u8], code: u8, response: &[u8]) -> Exchange {
    Exchange {
        cmd,
        request: request.to_vec(),
        reply: Ok((code, response.to_vec())),
        response_cmd: None,
    }
}

fn lost(cmd: u8, request: &[u8]) -> Exchange {
    Exchange {
        cmd,
        request: request.to_vec(),
        reply: Err("lost response"),
        response_cmd: None,
    }
}

#[cfg(feature = "hpm-update")]
fn device() -> DeviceId {
    DeviceId::from_data(&[2, 1, 1, 0x02, 0x51, 0, 1, 2, 3, 2, 1]).unwrap()
}

#[cfg(feature = "hpm-update")]
fn caps(mask: u8, flags: u8) -> TargetCapabilities {
    use ipmi_rs_core::connection::IpmiCommand;
    GetTargetCapabilities::parse_success_response(&[0, 0x10, flags, 1, 2, 3, 4, mask]).unwrap()
}

#[cfg(feature = "hpm-update")]
fn inventory(flags: u8, general: u8) -> Inventory {
    Inventory {
        device: device(),
        capabilities: caps(1, flags),
        components: vec![ComponentInventory {
            id: ComponentId::new(0).unwrap(),
            general: GeneralProperties {
                rollback_backup: general & 3,
                preparation: general & 4 != 0,
                comparison: general & 8 != 0,
                deferred_activation: general & 16 != 0,
                payload_cold_reset: general & 32 != 0,
            },
            description: [0; 12],
            current: FirmwareVersion([1, 2, 3, 4, 5, 6]),
            rollback: None,
            deferred: None,
        }],
    }
}

#[test]
fn inventory_adapts_to_capabilities_and_checks_reply_shapes() {
    let id = [2, 1, 1, 0x02, 0x51, 0, 1, 2, 3, 2, 1];
    let version = [0, 1, 2, 3, 4, 5, 6];
    let mut description = vec![0];
    description.extend(b"component 0 ");
    for (flags, general, version_byte, expected_count) in [(0, 0, 0x10, 5), (0x07, 0x13, 0x20, 7)] {
        let mut script = vec![
            good(0x01, &[], &id),
            good(0x2e, &[0], &[0, version_byte, flags, 1, 2, 3, 4, 1]),
            good(0x2f, &[0, 0, 0], &[0, general]),
            good(0x2f, &[0, 0, 2], &description),
            good(0x2f, &[0, 0, 1], &version),
        ];
        if general & 3 != 0 {
            script.push(good(0x2f, &[0, 0, 3], &version));
        }
        if general & 16 != 0 {
            script.push(good(0x2f, &[0, 0, 4], &version));
        }
        let mut ipmi = Ipmi::new(MockController::new(script));
        let found = read_inventory(&mut ipmi).unwrap();
        assert_eq!(found.capabilities.version, version_byte);
        assert_eq!(found.capabilities.manual_rollback, flags & 4 != 0);
        assert_eq!(found.components[0].rollback.is_some(), general & 3 != 0);
        assert_eq!(found.components[0].deferred.is_some(), general & 16 != 0);
        assert_eq!(ipmi.inner_mut().sent.len(), expected_count);
        assert!(ipmi.inner_mut().script.is_empty());
    }
    let mut ipmi = Ipmi::new(MockController::new(vec![
        good(0x01, &[], &id),
        good(0x2e, &[0], &[1, 0x10, 0, 1, 2, 3, 4, 1]),
    ]));
    assert!(matches!(
        read_inventory(&mut ipmi),
        Err(super::InventoryError::Hpm(IpmiError::Command {
            error: HpmResponseError::Identifier(1),
            ..
        }))
    ));
    assert_eq!(NetFn::Reserved(0x2c).request_value(), 0x2c);
}

fn advertised_optional_versions() -> Vec<Exchange> {
    vec![
        good(0x01, &[], &[2, 1, 1, 0x02, 0x51, 0, 1, 2, 3, 2, 1]),
        good(0x2e, &[0], &[0, 0x10, 0x04, 1, 2, 3, 4, 1]),
        good(0x2f, &[0, 0, 0], &[0, 0x13]),
        good(0x2f, &[0, 0, 2], &[0; 13]),
        good(0x2f, &[0, 0, 1], &[0, 1, 2, 3, 4, 5, 6]),
    ]
}

#[test]
fn missing_advertised_optional_version_slots_are_not_inventory_failures() {
    for (rollback_code, deferred_code) in [(0x81, 0xcb), (0x83, 0x81), (0xcb, 0x83)] {
        let mut script = advertised_optional_versions();
        script.push(fail(0x2f, &[0, 0, 3], rollback_code, &[]));
        script.push(fail(0x2f, &[0, 0, 4], deferred_code, &[]));
        let mut ipmi = Ipmi::new(MockController::new(script));
        let found = read_inventory(&mut ipmi).unwrap();
        assert_eq!(found.components[0].general.rollback_backup, 3);
        assert!(found.components[0].general.deferred_activation);
        assert_eq!(found.components[0].rollback, None);
        assert_eq!(found.components[0].deferred, None);
        assert_eq!(found.components[0].current.0, [1, 2, 3, 4, 5, 6]);
        assert_eq!(ipmi.inner_mut().sent.len(), 7);
        assert!(ipmi.inner_mut().script.is_empty());
    }

    let mut script = advertised_optional_versions();
    script.push(fail(0x2f, &[0, 0, 3], 0x81, &[]));
    script.push(good(0x2f, &[0, 0, 4], &[0, 7, 8, 9, 10, 11, 12]));
    let mut ipmi = Ipmi::new(MockController::new(script));
    let found = read_inventory(&mut ipmi).unwrap();
    assert_eq!(found.components[0].rollback, None);
    assert_eq!(
        found.components[0].deferred.unwrap().0,
        [7, 8, 9, 10, 11, 12]
    );
}

#[test]
fn optional_version_reads_preserve_genuine_errors() {
    for code in [0x82, 0xc0, 0xc3, 0xcc] {
        let mut script = advertised_optional_versions();
        script.push(fail(0x2f, &[0, 0, 3], code, &[]));
        let mut ipmi = Ipmi::new(MockController::new(script));
        assert!(matches!(
            read_inventory(&mut ipmi),
            Err(super::InventoryError::Hpm(IpmiError::Failed {
                completion_code,
                ..
            })) if completion_code == CompletionErrorCode::try_from(code).unwrap()
        ));
        assert_eq!(ipmi.inner_mut().sent.len(), 6);
    }

    let mut script = advertised_optional_versions();
    script.push(fail(0x2f, &[0, 0, 3], 0x81, &[]));
    script.push(fail(0x2f, &[0, 0, 4], 0x82, &[]));
    let mut ipmi = Ipmi::new(MockController::new(script));
    assert!(matches!(
        read_inventory(&mut ipmi),
        Err(super::InventoryError::Hpm(IpmiError::Failed {
            completion_code: CompletionErrorCode::CommandSpecific(0x82),
            ..
        }))
    ));

    let mut script = advertised_optional_versions();
    script.push(lost(0x2f, &[0, 0, 3]));
    let mut ipmi = Ipmi::new(MockController::new(script));
    assert!(matches!(
        read_inventory(&mut ipmi),
        Err(super::InventoryError::Hpm(IpmiError::Connection(
            "lost response"
        )))
    ));

    for response in [vec![0], vec![1, 1, 2, 3, 4, 5, 6]] {
        let mut script = advertised_optional_versions();
        script.push(good(0x2f, &[0, 0, 3], &response));
        let mut ipmi = Ipmi::new(MockController::new(script));
        assert!(matches!(
            read_inventory(&mut ipmi),
            Err(super::InventoryError::Hpm(IpmiError::Command { .. }))
        ));
    }

    let mut script = advertised_optional_versions();
    let mut wrong = good(0x2f, &[0, 0, 3], &[0, 1, 2, 3, 4, 5, 6]);
    wrong.response_cmd = Some(0x34);
    script.push(wrong);
    let mut ipmi = Ipmi::new(MockController::new(script));
    assert!(matches!(
        read_inventory(&mut ipmi),
        Err(super::InventoryError::Hpm(IpmiError::UnexpectedResponse {
            cmd_sent: 0x2f,
            cmd_recvd: 0x34,
            ..
        }))
    ));

    let mut script = advertised_optional_versions();
    script.truncate(2);
    script.push(fail(0x2f, &[0, 0, 0], 0x81, &[]));
    let mut ipmi = Ipmi::new(MockController::new(script));
    assert!(matches!(
        read_inventory(&mut ipmi),
        Err(super::InventoryError::Hpm(IpmiError::Failed {
            completion_code: CompletionErrorCode::CommandSpecific(0x81),
            ..
        }))
    ));

    let mut script = advertised_optional_versions();
    script.pop();
    script.push(fail(0x2f, &[0, 0, 1], 0xcb, &[]));
    let mut ipmi = Ipmi::new(MockController::new(script));
    assert!(matches!(
        read_inventory(&mut ipmi),
        Err(super::InventoryError::Hpm(IpmiError::Failed {
            completion_code: CompletionErrorCode::RequestedDatapointNotPresent,
            ..
        }))
    ));
}

#[cfg(feature = "hpm-update")]
mod firmware {
    use super::*;
    use crate::hpm::{
        package::{Package, PackageAction, PackageError},
        update::{Operation, Phase, UpdateError, UpdateOptions, Updater},
    };

    fn sign(bytes: &mut Vec<u8>) {
        bytes.truncate(bytes.len().saturating_sub(16));
        bytes.extend_from_slice(&md5::compute(&bytes[..]).0);
    }

    fn fixture(image: &[u8], backup: bool, prepare: bool) -> Vec<u8> {
        let mut header = [0u8; 34];
        header[0..8].copy_from_slice(b"PICMGFWU");
        header[9] = 2;
        header[10..13].copy_from_slice(&[1, 2, 3]);
        header[13..15].copy_from_slice(&[2, 1]);
        header[20] = 1;
        header[24..26].copy_from_slice(&[1, 0x01]);
        let mut bytes = header.to_vec();
        bytes.push((0u8).wrapping_sub(bytes.iter().fold(0u8, |s, b| s.wrapping_add(*b))));
        if backup {
            bytes.extend([0, 1, 255]);
        }
        if prepare {
            bytes.extend([1, 1, 254]);
        }
        bytes.extend([2, 1, 253]);
        bytes.extend([1, 2, 3, 4, 5, 6]);
        bytes.extend([b' '; 21]);
        bytes.extend((image.len() as u32).to_le_bytes());
        bytes.extend(image);
        bytes.extend([0; 16]);
        sign(&mut bytes);
        bytes
    }

    fn resign_header(bytes: &mut Vec<u8>) {
        bytes[34] = 0u8.wrapping_sub(bytes[..34].iter().fold(0u8, |s, b| s.wrapping_add(*b)));
        sign(bytes);
    }

    fn opts(size: u8, blocks: u32) -> UpdateOptions {
        UpdateOptions::new(size, blocks, false).unwrap()
    }

    #[test]
    fn empty_optional_slots_do_not_block_write_free_update_preflight() {
        let image = fixture(&[7], false, false);
        let package = Package::parse(&image).unwrap();
        let mut script = advertised_optional_versions();
        script.push(fail(0x2f, &[0, 0, 3], 0x81, &[]));
        script.push(fail(0x2f, &[0, 0, 4], 0xcb, &[]));
        let mut ipmi = Ipmi::new(MockController::new(script));
        let inventory = read_inventory(&mut ipmi).unwrap();
        {
            let updater = Updater::new(&mut ipmi, &package, &inventory, opts(1, 1)).unwrap();
            assert_eq!(updater.state().phase, Phase::Prepared);
        }
        assert_eq!(ipmi.inner_mut().sent.len(), 7);
        assert!(ipmi.inner_mut().script.is_empty());
    }

    #[test]
    fn package_rejects_malformed_records_before_a_write() {
        let good = fixture(&[1, 2, 3, 4, 5], true, true);
        let parsed = Package::parse(&good).unwrap();
        assert_eq!(parsed.actions().len(), 3);
        assert!(matches!(
            parsed.actions()[2],
            PackageAction::Upload {
                data: &[1, 2, 3, 4, 5],
                ..
            }
        ));
        let mut cases = Vec::new();
        let mut short = good.clone();
        short.truncate(40);
        cases.push((short, PackageError::Bounds));
        let mut tampered = good.clone();
        tampered[74] ^= 1;
        cases.push((tampered, PackageError::Integrity));
        let mut signature = good.clone();
        signature[0] ^= 1;
        resign_header(&mut signature);
        cases.push((signature, PackageError::Format));
        let mut checksum = good.clone();
        checksum[34] ^= 1;
        sign(&mut checksum);
        cases.push((checksum, PackageError::Checksum));
        let mut zero_mask = good.clone();
        zero_mask[20] = 0;
        resign_header(&mut zero_mask);
        cases.push((zero_mask, PackageError::Components));
        let mut mismatched = good.clone();
        mismatched[20] = 3;
        resign_header(&mut mismatched);
        cases.push((mismatched, PackageError::MissingImage));
        let mut invalid_action = good.clone();
        invalid_action[35] = 0x7f;
        invalid_action[37] = (0u8).wrapping_sub(invalid_action[35] + invalid_action[36]);
        sign(&mut invalid_action);
        cases.push((invalid_action, PackageError::Action(0x7f)));
        let mut bad_length = good.clone();
        let length_offset = 35 + 3 + 3 + 3 + 27;
        bad_length[length_offset..length_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        sign(&mut bad_length);
        cases.push((bad_length, PackageError::Bounds));
        let mut bad_record_checksum = good.clone();
        bad_record_checksum[37] ^= 1;
        sign(&mut bad_record_checksum);
        cases.push((bad_record_checksum, PackageError::Checksum));
        let mut oem_bounds = good.clone();
        oem_bounds[32..34].copy_from_slice(&u16::MAX.to_le_bytes());
        sign(&mut oem_bounds);
        cases.push((oem_bounds, PackageError::Bounds));
        for (bytes, expected) in cases {
            assert_eq!(Package::parse(&bytes).unwrap_err(), expected);
        }
    }

    #[test]
    fn package_accepts_full_upload_header_checksum_and_rejects_oversized_images() {
        let mut image = fixture(&[42], false, false);
        let record_offset = 35;
        image[record_offset + 2] = 0;
        let checksum = image[record_offset..record_offset + 34]
            .iter()
            .fold(0u8, |s, b| s.wrapping_add(*b));
        image[record_offset + 2] = (0u8).wrapping_sub(checksum);
        assert_ne!(
            image[record_offset..record_offset + 3]
                .iter()
                .fold(0u8, |s, b| s.wrapping_add(*b)),
            0
        );
        sign(&mut image);
        assert!(Package::parse(&image).is_ok());
        assert_eq!(
            Package::parse(&vec![0; 64 * 1024 * 1024 + 1]).unwrap_err(),
            PackageError::Limit
        );
    }

    #[test]
    fn preflight_rejects_mismatch_disruption_and_budget_without_writes() {
        let bytes = fixture(&[1; 48], true, true);
        let package = Package::parse(&bytes).unwrap();
        let mut target = inventory(0, 0x05);
        let mut ipmi = Ipmi::new(MockController::new(vec![]));
        assert!(matches!(
            Updater::new(&mut ipmi, &package, &target, opts(23, 2)),
            Err(UpdateError::Limit)
        ));
        target.device.product_id = 42;
        assert!(matches!(
            Updater::new(&mut ipmi, &package, &target, opts(23, 3)),
            Err(UpdateError::Incompatible(_))
        ));
        target.device.product_id = 0x0102;
        target.capabilities.services_affected = true;
        assert!(matches!(
            Updater::new(&mut ipmi, &package, &target, opts(23, 3)),
            Err(UpdateError::Incompatible(_))
        ));
        assert!(UpdateOptions::new(24, 1, true).is_none());
        assert!(ipmi.inner_mut().sent.is_empty());
    }

    #[test]
    fn upload_requires_explicit_activate_and_never_exceeds_chunk_bound() {
        let bytes = fixture(&[1, 2, 3, 4, 5], true, true);
        let package = Package::parse(&bytes).unwrap();
        let target = inventory(4, 0x05);
        let script = vec![
            good(0x31, &[0, 1, 0], &[0]),
            good(0x31, &[0, 1, 1], &[0]),
            good(0x31, &[0, 1, 2], &[0]),
            good(0x32, &[0, 0, 1, 2], &[0]),
            good(0x32, &[0, 1, 3, 4], &[0]),
            good(0x32, &[0, 2, 5], &[0]),
            good(0x33, &[0, 0, 5, 0, 0, 0], &[0]),
            good(0x35, &[0], &[0]),
            good(0x36, &[0], &[0, 0x55, 0]),
            good(0x38, &[0], &[0]),
            good(0x37, &[0], &[0, 1]),
        ];
        let mut ipmi = Ipmi::new(MockController::new(script));
        let mut updater = Updater::new(&mut ipmi, &package, &target, opts(2, 3)).unwrap();
        let mut bytes_seen = Vec::new();
        let state = updater
            .upload(|state| {
                bytes_seen.push(state.confirmed_bytes);
                true
            })
            .unwrap();
        assert_eq!(state.phase, Phase::Uploaded);
        assert_eq!(state.confirmed_bytes, 5);
        assert_eq!(state.finished_images, 1);
        assert!(bytes_seen.contains(&2) && bytes_seen.contains(&4) && bytes_seen.contains(&5));
        assert_eq!(
            updater.activate().unwrap().phase,
            Phase::ActivationAcknowledged
        );
        assert_eq!(updater.self_test_result().unwrap().result1, 0x55);
        assert_eq!(
            updater.rollback().unwrap().phase,
            Phase::RollbackAcknowledged
        );
        assert_eq!(updater.rollback_status().unwrap().components, 1);
        assert!(matches!(
            updater.rollback(),
            Err(UpdateError::InvalidState(_))
        ));
        assert!(ipmi.inner_mut().script.is_empty());
        assert!(ipmi
            .inner_mut()
            .sent
            .iter()
            .filter(|(cmd, _)| *cmd == 0x32)
            .all(|(_, d)| d.len() <= 25));
    }

    #[test]
    fn cancellation_and_partial_write_do_not_retry_or_finish() {
        let bytes = fixture(&[1, 2, 3, 4], false, false);
        let package = Package::parse(&bytes).unwrap();
        let target = inventory(0, 0);
        let script = vec![
            good(0x31, &[0, 1, 2], &[0]),
            good(0x32, &[0, 0, 1, 2], &[0]),
            lost(0x32, &[0, 1, 3, 4]),
            good(0x34, &[0], &[0, 0x32, 0x80]),
        ];
        let mut ipmi = Ipmi::new(MockController::new(script));
        let mut updater = Updater::new(&mut ipmi, &package, &target, opts(2, 2)).unwrap();
        let error = updater.upload(|_| true).unwrap_err();
        let UpdateError::Uncertain {
            state,
            source: IpmiError::Connection("lost response"),
        } = error
        else {
            panic!("lost block should be uncertain: {error:?}");
        };
        assert_eq!(state.confirmed_bytes, 2);
        assert_eq!(
            state.uncertain,
            Some(Operation::Upload {
                block: 1,
                offset: 2,
                length: 2
            })
        );
        assert_eq!(updater.upgrade_status().unwrap().completion_code, 0x80);
        assert!(matches!(
            updater.upload(|_| true),
            Err(UpdateError::InvalidState(_))
        ));
        assert!(ipmi.inner_mut().script.is_empty());
        assert_eq!(ipmi.inner_mut().sent.len(), 4);

        let mut ipmi = Ipmi::new(MockController::new(vec![
            good(0x31, &[0, 1, 2], &[0]),
            good(0x32, &[0, 0, 1, 2], &[0]),
        ]));
        let mut updater = Updater::new(&mut ipmi, &package, &target, opts(2, 2)).unwrap();
        let cancelled = updater.upload(|s| s.confirmed_bytes < 2).unwrap_err();
        assert!(
            matches!(cancelled, UpdateError::Cancelled(s) if s.confirmed_bytes == 2 && s.phase == Phase::Uploading && s.uncertain.is_none())
        );
        assert!(matches!(
            updater.activate(),
            Err(UpdateError::InvalidState(_))
        ));
        assert_eq!(ipmi.inner_mut().sent.len(), 2);
    }

    #[test]
    fn malformed_or_partial_ack_stops_without_sending_next_block() {
        let bytes = fixture(&[1, 2, 3, 4], false, false);
        let package = Package::parse(&bytes).unwrap();
        let target = inventory(0, 0);
        let mut ipmi = Ipmi::new(MockController::new(vec![
            good(0x31, &[0, 1, 2], &[0]),
            good(0x32, &[0, 0, 1, 2], &[0, 1]),
        ]));
        let mut updater = Updater::new(&mut ipmi, &package, &target, opts(2, 2)).unwrap();
        assert!(matches!(
            updater.upload(|_| true),
            Err(UpdateError::Uncertain {
                state: super::super::update::TransferState {
                    confirmed_bytes: 0,
                    uncertain: Some(Operation::Upload { block: 0, .. }),
                    ..
                },
                source: IpmiError::Command {
                    error: HpmResponseError::Length { .. },
                    ..
                }
            })
        ));
        assert_eq!(ipmi.inner_mut().sent.len(), 2);

        let mut ipmi = Ipmi::new(MockController::new(vec![
            good(0x31, &[0, 1, 2], &[0]),
            good(0x32, &[0, 0, 1, 2], &[0, 3, 0, 0, 0, 1, 0, 0, 0]),
        ]));
        let mut updater = Updater::new(&mut ipmi, &package, &target, opts(2, 2)).unwrap();
        assert!(matches!(
            updater.upload(|_| true),
            Err(UpdateError::UnsupportedSection(state)) if state.confirmed_bytes == 2
        ));
        assert_eq!(ipmi.inner_mut().sent.len(), 2);
    }

    #[test]
    fn activation_loss_and_rollback_failure_remain_observable() {
        let bytes = fixture(&[1], false, false);
        let package = Package::parse(&bytes).unwrap();
        let target = inventory(4, 0);
        let script = vec![
            good(0x31, &[0, 1, 2], &[0]),
            good(0x32, &[0, 0, 1], &[0]),
            good(0x33, &[0, 0, 1, 0, 0, 0], &[0]),
            lost(0x35, &[0]),
            good(0x34, &[0], &[0, 0x35, 0]),
        ];
        let mut ipmi = Ipmi::new(MockController::new(script));
        let mut updater = Updater::new(&mut ipmi, &package, &target, opts(1, 1)).unwrap();
        updater.upload(|_| true).unwrap();
        assert!(matches!(
            updater.activate(),
            Err(UpdateError::Uncertain { state, .. })
                if state.phase == Phase::Uploaded && state.uncertain == Some(Operation::Activate)
        ));
        assert_eq!(updater.upgrade_status().unwrap().command, 0x35);
        assert!(matches!(
            updater.activate(),
            Err(UpdateError::InvalidState(_))
        ));
        assert!(matches!(
            updater.rollback(),
            Err(UpdateError::InvalidState(_))
        ));
        assert!(ipmi.inner_mut().script.is_empty());

        let mut ipmi = Ipmi::new(MockController::new(vec![
            good(0x38, &[0], &[0]),
            fail(0x37, &[0], 0x81, &[0, 1]),
        ]));
        let mut updater = Updater::new(&mut ipmi, &package, &target, opts(1, 1)).unwrap();
        updater.rollback().unwrap();
        assert!(matches!(
            updater.rollback_status(),
            Err(UpdateError::Read(IpmiError::Command {
                error: HpmResponseError::RollbackFailed(1),
                ..
            }))
        ));
        assert!(ipmi.inner_mut().script.is_empty());
    }

    #[test]
    fn in_progress_and_rollback_loss_do_not_trigger_implicit_retries() {
        let bytes = fixture(&[7], false, false);
        let package = Package::parse(&bytes).unwrap();
        let target = inventory(4, 0);
        let mut ipmi = Ipmi::new(MockController::new(vec![
            fail(0x31, &[0, 1, 2], 0x80, &[]),
            good(0x34, &[0], &[0, 0x31, 0x80]),
        ]));
        let mut updater = Updater::new(&mut ipmi, &package, &target, opts(1, 1)).unwrap();
        assert!(matches!(
            updater.upload(|_| true),
            Err(UpdateError::Uncertain { state, .. })
                if state.uncertain == Some(Operation::Initiate(
                    ipmi_rs_core::hpm::UpgradeAction::Upgrade, 1
                ))
        ));
        assert_eq!(updater.upgrade_status().unwrap().completion_code, 0x80);
        assert_eq!(ipmi.inner_mut().sent.len(), 2);

        let mut ipmi = Ipmi::new(MockController::new(vec![lost(0x38, &[0])]));
        let mut updater = Updater::new(&mut ipmi, &package, &target, opts(1, 1)).unwrap();
        assert!(matches!(
            updater.rollback(),
            Err(UpdateError::Uncertain { state, .. })
                if state.uncertain == Some(Operation::Rollback)
        ));
        assert_eq!(ipmi.inner_mut().sent.len(), 1);
    }

    #[test]
    fn long_transfer_wraps_hpm_block_number_without_exceeding_budget() {
        let image = vec![7; 257];
        let bytes = fixture(&image, false, false);
        let package = Package::parse(&bytes).unwrap();
        let target = inventory(0, 0);
        let mut script = vec![good(0x31, &[0, 1, 2], &[0])];
        for index in 0..257 {
            script.push(good(0x32, &[0, index as u8, 7], &[0]));
        }
        script.push(good(0x33, &[0, 0, 1, 1, 0, 0], &[0]));
        let mut ipmi = Ipmi::new(MockController::new(script));
        let mut updater = Updater::new(&mut ipmi, &package, &target, opts(1, 257)).unwrap();
        assert_eq!(updater.upload(|_| true).unwrap().confirmed_bytes, 257);
        assert_eq!(ipmi.inner_mut().sent.len(), 259);
    }
}
