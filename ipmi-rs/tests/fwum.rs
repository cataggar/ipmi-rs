use std::collections::VecDeque;

use ipmi_rs::{
    connection::{
        Address, Channel, IpmiConnection, LogicalUnit, Message, NetFn, Request,
        RequestTargetAddress, Response,
    },
    fwum::{FwumReadError, Inventory},
    oem::fwum::{FirmwareImage, FwumTarget, ImageError},
    Ipmi,
};

#[cfg(feature = "kontron-fwum-update")]
use ipmi_rs::fwum::{
    MutationOutcome, PrepareError, TransportKind, TransportLimits, UpdateAuthorization,
    UpdateCause, UpdatePhase,
};

const SIZE: usize = 0x5b4;
const BOARD: u16 = 5002;

fn image(board: u16, iana: u32, marker: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; SIZE];
    let h = 0x5a0;
    bytes[0] = marker;
    bytes[h..h + 4].copy_from_slice(&(SIZE as u32).to_be_bytes());
    bytes[h + 6..h + 8].copy_from_slice(&board.to_be_bytes());
    bytes[h + 8] = 0x22;
    bytes[h + 9] = 1;
    bytes[h + 10] = 2;
    bytes[h + 11] = 3;
    bytes[h + 12] = 0x45;
    bytes[h + 13] = 7;
    bytes[h + 14..h + 17].copy_from_slice(&iana.to_le_bytes()[..3]);
    let sum = bytes
        .iter()
        .fold(0u16, |sum, byte| sum.wrapping_add(*byte as u16));
    bytes[h + 4..h + 6].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
    bytes
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Timeout,
}

#[derive(Default)]
struct Mock {
    sent: Vec<(u8, u8, Vec<u8>, RequestTargetAddress)>,
    manufacturer: u32,
    board: u16,
    truncated_info: bool,
    old_protocol: bool,
    bank_count: u8,
    staged: bool,
    activated: bool,
    rolled_back: bool,
    lost_save_ack: Option<usize>,
    lost_rollback_ack: bool,
    save_count: usize,
    buffer_count: usize,
    reject_buffer_at: Option<usize>,
    lost_buffer_ack_at: Option<usize>,
    reject_rollback: bool,
    activation_pending: bool,
    rollback_pending: bool,
    pending_activation_snapshot: bool,
    pending_rollback_snapshot: bool,
    scripted: VecDeque<Result<Vec<u8>, Fault>>,
}

impl Mock {
    fn kontron() -> Self {
        Self {
            manufacturer: 15000,
            board: BOARD,
            bank_count: 2,
            ..Self::default()
        }
    }

    fn response(netfn: u8, cmd: u8, payload: Vec<u8>) -> Response {
        Response::new(Message::new_response(NetFn::from(netfn), cmd, payload), 0).unwrap()
    }

    fn status(&mut self, bank: u8) -> Vec<u8> {
        if bank == 0 {
            self.pending_activation_snapshot = self.activated && self.activation_pending;
            self.pending_rollback_snapshot = self.rolled_back && self.rollback_pending;
        }
        let pending_activate = self.pending_activation_snapshot;
        let pending_rollback = self.pending_rollback_snapshot;
        if bank == 1 {
            if self.activated {
                self.activation_pending = false;
            }
            if self.rolled_back {
                self.rollback_pending = false;
            }
        }
        if bank == 0 {
            let state = if self.activated && !pending_activate && !self.rolled_back {
                4
            } else {
                3
            };
            vec![state, 100, 0, 0, 1, 0x12, 3]
        } else if self.rolled_back && !pending_rollback {
            vec![4, SIZE as u8, (SIZE >> 8) as u8, 0, 3, 0x45, 7]
        } else if self.activated && !pending_activate {
            vec![3, SIZE as u8, (SIZE >> 8) as u8, 0, 3, 0x45, 7]
        } else if self.staged {
            vec![1, SIZE as u8, (SIZE >> 8) as u8, 0, 3, 0x45, 7]
        } else {
            vec![0; 7]
        }
    }
}

impl IpmiConnection for Mock {
    type SendError = Fault;
    type RecvError = Fault;
    type Error = Fault;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        unreachable!()
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        unreachable!()
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let netfn = request.netfn_raw();
        let cmd = request.cmd();
        let data = request.data().to_vec();
        let target = request.target();
        self.sent.push((netfn, cmd, data.clone(), target));
        let payload = if (netfn, cmd) == (6, 1) {
            let product = match target {
                RequestTargetAddress::Bmc(_) => 77,
                _ => self.board,
            };
            let iana = self.manufacturer.to_le_bytes();
            let mut bytes = vec![0, 0x22, 1, 0x12, 0x51, 0, iana[0], iana[1], iana[2]];
            bytes[0] = 0x22;
            bytes.extend_from_slice(&product.to_le_bytes());
            bytes.extend_from_slice(&[7, 0, 0, 0]);
            bytes
        } else if let Some(next) = self.scripted.pop_front() {
            return next.map(|bytes| Self::response(netfn, cmd, bytes));
        } else {
            match (netfn, cmd) {
                (8, 0) if self.truncated_info => vec![0, 1],
                (8, 0) if self.old_protocol => vec![5, 0x22, 0, 3, 0x45, self.bank_count],
                (8, 0) => vec![6, 0x22, 2, 3, 0x45, self.bank_count, 0],
                (8, 7) => self.status(data[0]),
                (8, 0x0f) => {
                    let mut entries = vec![0; 21];
                    if data[0] == 0 {
                        entries[..3].copy_from_slice(&[0x0b, 3, 0]);
                    }
                    entries
                }
                (0x3e, 0x82) => {
                    self.buffer_count += 1;
                    if self.reject_buffer_at == Some(self.buffer_count) {
                        return Ok(Self::response(netfn, cmd, vec![0xc7]));
                    }
                    if self.lost_buffer_ack_at == Some(self.buffer_count) {
                        return Err(Fault::Timeout);
                    }
                    vec![]
                }
                (8, 0x0a) => vec![1],
                (8, 0x0b) => {
                    self.save_count += 1;
                    if self.lost_save_ack == Some(self.save_count) {
                        return Err(Fault::Timeout);
                    }
                    vec![]
                }
                (8, 0x0c) => {
                    self.staged = true;
                    vec![]
                }
                (8, 0x09) => {
                    self.activated = true;
                    vec![]
                }
                (8, 0x0e) => {
                    if self.reject_rollback {
                        return Ok(Self::response(netfn, cmd, vec![0xd5]));
                    }
                    self.rolled_back = true;
                    if self.lost_rollback_ack {
                        return Err(Fault::Timeout);
                    }
                    vec![]
                }
                _ => panic!("unexpected request {netfn:02x}/{cmd:02x}"),
            }
        };
        let mut bytes = vec![0];
        bytes.extend(payload);
        Ok(Self::response(netfn, cmd, bytes))
    }
}

fn direct() -> FwumTarget {
    FwumTarget::new(None, 77)
}

fn bridged() -> FwumTarget {
    FwumTarget::new(Some((Address(0x30), Channel::Primary)), BOARD)
}

fn count(mock: &Mock, netfn: u8, cmd: u8) -> usize {
    mock.sent
        .iter()
        .filter(|(n, c, _, _)| (*n, *c) == (netfn, cmd))
        .count()
}

#[test]
fn source_header_checksum_size_and_identity_faults() {
    let bytes = image(BOARD, 15000, 1);
    let parsed = FirmwareImage::parse(&bytes).unwrap();
    assert_eq!(
        (parsed.iana, parsed.board_id, parsed.device_id),
        (15000, BOARD, 0x22)
    );
    assert_eq!(parsed.len(), SIZE);
    assert_eq!(
        parsed.padding(),
        0u16.wrapping_sub(bytes.iter().map(|b| u16::from(*b)).sum())
    );
    assert!(matches!(
        FirmwareImage::parse(&bytes[..0x5a0]),
        Err(ImageError::Truncated)
    ));
    let mut invalid = bytes.clone();
    invalid[20] ^= 1;
    assert!(matches!(
        FirmwareImage::parse(&invalid),
        Err(ImageError::ChecksumMismatch)
    ));
    let mut invalid = bytes.clone();
    invalid[0x5a0 + 3] ^= 1;
    assert!(matches!(
        FirmwareImage::parse(&invalid),
        Err(ImageError::SizeMismatch)
    ));
    assert!(matches!(
        FirmwareImage::parse(&vec![0u8; 512 * 1024 + 1]),
        Err(ImageError::TooLarge)
    ));

    let mut mock = Mock::kontron();
    mock.manufacturer = 42;
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.fwum_inventory(bridged()),
        Err(FwumReadError::UnsupportedDevice {
            manufacturer: 42,
            ..
        })
    ));
    assert_eq!(count(&ipmi.release(), 8, 0), 0);
    let mut ipmi = Ipmi::new(Mock::kontron());
    assert!(matches!(
        ipmi.fwum_inventory(FwumTarget::new(bridged().address, 42)),
        Err(FwumReadError::UnsupportedDevice { .. })
    ));
    assert_eq!(count(&ipmi.release(), 8, 0), 0);
}

#[test]
fn inventory_status_trace_and_truncation_are_bounded() {
    let mut ipmi = Ipmi::new(Mock::kontron());
    let Inventory {
        kontron_5002_sdr_revision,
        ..
    } = ipmi.fwum_inventory(bridged()).unwrap();
    assert_eq!(kontron_5002_sdr_revision, Some(7));
    let banks = ipmi.fwum_banks(bridged()).unwrap();
    assert_eq!(banks.banks.len(), 2);
    let trace = ipmi.fwum_trace(bridged()).unwrap();
    assert_eq!(trace.len(), 1);
    assert_eq!((trace[0].command_id, trace[0].state), (11, 3));
    let mock = ipmi.release();
    assert_eq!(count(&mock, 8, 0x0f), 7);
    assert!(mock.sent.iter().any(|(n, c, bytes, target)| {
        *n == 8
            && *c == 7
            && bytes == &[1]
            && *target
                == RequestTargetAddress::BmcOrIpmb(
                    Address(0x30),
                    Channel::Primary,
                    LogicalUnit::Zero,
                )
    }));
    let mut mock = Mock::kontron();
    mock.truncated_info = true;
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.fwum_inventory(bridged()),
        Err(FwumReadError::Command(_))
    ));
    assert_eq!(count(&ipmi.release(), 8, 0), 1);
    let mut mock = Mock::kontron();
    mock.bank_count = 200;
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.fwum_banks(bridged()),
        Err(FwumReadError::BankLimit(200))
    ));
    assert_eq!(count(&ipmi.release(), 8, 7), 0);
    let mut ipmi = Ipmi::new(Mock::kontron());
    let _ = ipmi.fwum_inventory(direct()).unwrap();
    assert_eq!(count(&ipmi.release(), 8, 0), 1);
}

#[cfg(feature = "kontron-fwum-update")]
fn authorization<'a>(recovery: &'a [u8]) -> UpdateAuthorization<'a> {
    UpdateAuthorization::new(
        "approved night maintenance",
        recovery,
        "halt writes; inspect bank status and trace; use out-of-band console",
        "verify prior good image before manual rollback",
    )
    .unwrap()
}

#[cfg(feature = "kontron-fwum-update")]
#[test]
fn bad_image_or_recovery_fails_before_any_mutation() {
    let bytes = image(BOARD, 15000, 1);
    let recovery = image(BOARD, 15000, 2);
    assert!(matches!(
        UpdateAuthorization::new("", &recovery, "inspect", "rollback"),
        Err(PrepareError::MissingProcedure)
    ));
    let auth = authorization(&recovery);
    let mut ipmi = Ipmi::new(Mock::kontron());
    let wrong = image(BOARD + 1, 15000, 1);
    assert!(matches!(
        ipmi.fwum_prepare_update(
            bridged(),
            &wrong,
            &auth,
            TransportLimits::standard(TransportKind::Bridged)
        ),
        Err(err) if matches!(err.cause, UpdateCause::Preflight(PrepareError::ImageTargetMismatch))
    ));
    assert!(ipmi.inner_mut().sent.is_empty());
    let wrong = image(BOARD, 674, 1);
    assert!(matches!(
        ipmi.fwum_prepare_update(
            bridged(),
            &wrong,
            &auth,
            TransportLimits::standard(TransportKind::Bridged)
        ),
        Err(err) if matches!(err.cause, UpdateCause::Preflight(PrepareError::ImageTargetMismatch))
    ));
    let mut corrupted = bytes.clone();
    corrupted[21] ^= 3;
    assert!(matches!(
        ipmi.fwum_prepare_update(
            bridged(),
            &corrupted,
            &auth,
            TransportLimits::standard(TransportKind::Bridged)
        ),
        Err(err) if matches!(err.cause, UpdateCause::Preflight(PrepareError::Image(ImageError::ChecksumMismatch)))
    ));
    assert!(ipmi.inner_mut().sent.is_empty());
    let auth = authorization(&bytes);
    assert!(matches!(
        ipmi.fwum_prepare_update(
            bridged(),
            &bytes,
            &auth,
            TransportLimits::standard(TransportKind::Bridged)
        ),
        Err(err) if matches!(err.cause, UpdateCause::Preflight(PrepareError::RecoveryNotAlternative))
    ));
    assert!(ipmi.inner_mut().sent.is_empty());
}

#[cfg(feature = "kontron-fwum-update")]
#[test]
fn bridged_setup_upload_finish_activate_and_rollback_with_verified_progress() {
    let bytes = image(BOARD, 15000, 1);
    let recovery = image(BOARD, 15000, 2);
    let mut mock = Mock::kontron();
    mock.activation_pending = true;
    mock.rollback_pending = true;
    let mut ipmi = Ipmi::new(mock);
    let mut session = ipmi
        .fwum_prepare_update(
            bridged(),
            &bytes,
            &authorization(&recovery),
            TransportLimits::negotiated(TransportKind::Bridged, 32, 32).unwrap(),
        )
        .unwrap();
    let mut progress = Vec::new();
    assert_eq!(
        session
            .stage(|step| {
                progress.push(step);
                true
            })
            .unwrap(),
        1
    );
    assert_eq!(progress.first().unwrap().confirmed_bytes, 0);
    assert_eq!(progress.last().unwrap().confirmed_bytes, SIZE);
    assert_eq!(session.phase(), UpdatePhase::Staged { bank: 1 });
    session.activate().unwrap();
    let first = session.verify_activation();
    assert!(
        matches!(first, Err(ref err) if matches!(err.cause, UpdateCause::Pending)),
        "{first:?}"
    );
    session.verify_activation().unwrap();
    assert_eq!(session.phase(), UpdatePhase::Activated { bank: 1 });
    session.rollback().unwrap();
    assert!(matches!(
        session.verify_rollback(),
        Err(err) if matches!(err.cause, UpdateCause::Pending)
    ));
    session.verify_rollback().unwrap();
    assert_eq!(session.phase(), UpdatePhase::RolledBack { bank: 1 });
    drop(session);
    let mock = ipmi.release();
    assert_eq!(count(&mock, 8, 0x0a), 1);
    assert_eq!(count(&mock, 8, 0x0c), 1);
    assert_eq!(count(&mock, 8, 0x09), 1);
    assert_eq!(count(&mock, 8, 0x0e), 1);
    assert_eq!(count(&mock, 0x3e, 0x82), 6);
    let buffer: Vec<_> = mock
        .sent
        .iter()
        .filter(|(netfn, cmd, ..)| (*netfn, *cmd) == (0x3e, 0x82))
        .map(|(_, _, bytes, target)| (bytes.clone(), *target))
        .collect();
    assert_eq!(buffer[0].0, [0x0e, 32]);
    assert_eq!(buffer[1].0, [0x00, 32]);
    assert_eq!(buffer[2].0, [0x0e, 32]);
    assert_eq!(buffer[3].0, [0x0e, 0]);
    assert_eq!(buffer[4].0, [0x00, 0]);
    assert_eq!(buffer[5].0, [0x0e, 0]);
    assert_eq!(buffer[0].1, RequestTargetAddress::Bmc(LogicalUnit::Zero));
    assert_eq!(
        buffer[2].1,
        RequestTargetAddress::BmcOrIpmb(Address(0x30), Channel::Primary, LogicalUnit::Zero)
    );
    let start = mock
        .sent
        .iter()
        .find(|(n, c, ..)| (*n, *c) == (8, 0x0a))
        .unwrap();
    assert_eq!(
        start.2,
        [
            SIZE as u8,
            (SIZE >> 8) as u8,
            0,
            FirmwareImage::parse(&bytes).unwrap().padding() as u8,
            (FirmwareImage::parse(&bytes).unwrap().padding() >> 8) as u8,
            1,
        ]
    );
    let saves: Vec<_> = mock
        .sent
        .iter()
        .filter(|(n, c, ..)| (*n, *c) == (8, 0x0b))
        .collect();
    assert!(saves.iter().all(|s| s.2.len() <= 29));
    assert_eq!(
        saves
            .iter()
            .flat_map(|s| &s.2[1..])
            .copied()
            .collect::<Vec<_>>(),
        bytes
    );
    assert_eq!(saves.first().unwrap().2[0], 0);
}

#[cfg(feature = "kontron-fwum-update")]
#[test]
fn lost_save_ack_or_operator_interruption_never_replays_or_finishes() {
    let bytes = image(BOARD, 15000, 1);
    let recovery = image(BOARD, 15000, 2);
    let mut mock = Mock::kontron();
    mock.lost_save_ack = Some(2);
    let mut ipmi = Ipmi::new(mock);
    let mut session = ipmi
        .fwum_prepare_update(
            bridged(),
            &bytes,
            &authorization(&recovery),
            TransportLimits::negotiated(TransportKind::Bridged, 32, 32).unwrap(),
        )
        .unwrap();
    let err = session.stage(|_| true).unwrap_err();
    assert_eq!(err.confirmed_bytes, 28);
    assert_eq!(err.phase, UpdatePhase::Interrupted);
    assert!(matches!(
        err.cause,
        UpdateCause::Mutation(ref write) if write.outcome == MutationOutcome::Unknown
    ));
    assert!(matches!(
        session.stage(|_| true),
        Err(err) if matches!(err.cause, UpdateCause::InvalidPhase)
    ));
    assert!(session.inspect().is_ok());
    drop(session);
    let mock = ipmi.release();
    assert_eq!(count(&mock, 8, 0x0b), 2);
    assert_eq!(count(&mock, 8, 0x0c), 0);
    assert_eq!(count(&mock, 8, 0x09), 0);
    assert_eq!(count(&mock, 0x3e, 0x82), 6);

    let mut ipmi = Ipmi::new(Mock::kontron());
    let mut session = ipmi
        .fwum_prepare_update(
            bridged(),
            &bytes,
            &authorization(&recovery),
            TransportLimits::standard(TransportKind::Bridged),
        )
        .unwrap();
    let err = session.stage(|step| step.confirmed_bytes == 0).unwrap_err();
    assert_eq!(err.confirmed_bytes, 28);
    assert!(matches!(err.cause, UpdateCause::OperatorInterrupted));
    drop(session);
    let mock = ipmi.release();
    assert_eq!(count(&mock, 8, 0x0b), 1);
    assert_eq!(count(&mock, 8, 0x0c), 0);
    assert_eq!(count(&mock, 0x3e, 0x82), 0);
}

#[cfg(feature = "kontron-fwum-update")]
#[test]
fn lost_rollback_ack_is_unknown_and_not_retried() {
    let bytes = image(BOARD, 15000, 1);
    let recovery = image(BOARD, 15000, 2);
    let mut mock = Mock::kontron();
    mock.lost_rollback_ack = true;
    let mut ipmi = Ipmi::new(mock);
    let mut session = ipmi
        .fwum_prepare_update(
            bridged(),
            &bytes,
            &authorization(&recovery),
            TransportLimits::standard(TransportKind::Bridged),
        )
        .unwrap();
    session.stage(|_| true).unwrap();
    session.activate().unwrap();
    session.verify_activation().unwrap();
    let err = session.rollback().unwrap_err();
    assert!(matches!(
        err.cause,
        UpdateCause::Mutation(ref action) if action.outcome == MutationOutcome::Unknown
    ));
    assert_eq!(session.phase(), UpdatePhase::Interrupted);
    assert!(matches!(
        session.rollback(),
        Err(err) if matches!(err.cause, UpdateCause::InvalidPhase)
    ));
    drop(session);
    assert_eq!(count(&ipmi.release(), 8, 0x0e), 1);
}

#[cfg(feature = "kontron-fwum-update")]
#[test]
fn addressed_legacy_mode_preserves_offsets_and_page_boundaries() {
    let bytes = image(BOARD, 15000, 1);
    let recovery = image(BOARD, 15000, 2);
    let mut mock = Mock::kontron();
    mock.old_protocol = true;
    let mut ipmi = Ipmi::new(mock);
    let mut session = ipmi
        .fwum_prepare_update(
            bridged(),
            &bytes,
            &authorization(&recovery),
            TransportLimits::standard(TransportKind::Bridged),
        )
        .unwrap();
    session.stage(|_| true).unwrap();
    drop(session);
    let mock = ipmi.release();
    let start = mock
        .sent
        .iter()
        .find(|(n, c, ..)| (*n, *c) == (8, 0x0a))
        .unwrap();
    assert_eq!(start.2.len(), 5);
    let mut uploaded = Vec::new();
    for (_, _, data, _) in mock.sent.iter().filter(|(n, c, ..)| (*n, *c) == (8, 0x0b)) {
        let address =
            usize::from(data[0]) | (usize::from(data[1]) << 8) | (usize::from(data[2]) << 16);
        let count = usize::from(data[3]);
        assert_eq!(address, uploaded.len());
        assert_eq!(data.len(), count + 4);
        assert!(count <= 26);
        assert!(address % 256 + count <= 256);
        uploaded.extend_from_slice(&data[4..]);
    }
    assert_eq!(uploaded, bytes);
}

#[cfg(feature = "kontron-fwum-update")]
#[test]
fn rejected_or_uncertain_buffer_setup_cleans_only_possible_settings() {
    let bytes = image(BOARD, 15000, 1);
    let recovery = image(BOARD, 15000, 2);
    for unknown in [false, true] {
        let mut mock = Mock::kontron();
        if unknown {
            mock.lost_buffer_ack_at = Some(2);
        } else {
            mock.reject_buffer_at = Some(2);
        }
        let mut ipmi = Ipmi::new(mock);
        let mut session = ipmi
            .fwum_prepare_update(
                bridged(),
                &bytes,
                &authorization(&recovery),
                TransportLimits::negotiated(TransportKind::Bridged, 32, 32).unwrap(),
            )
            .unwrap();
        let err = session.stage(|_| true).unwrap_err();
        assert_eq!(err.phase, UpdatePhase::Interrupted);
        assert!(matches!(
            err.cause,
            UpdateCause::Mutation(ref action)
                if action.outcome == if unknown {
                    MutationOutcome::Unknown
                } else {
                    MutationOutcome::Rejected
                }
        ));
        drop(session);
        let mock = ipmi.release();
        assert_eq!(count(&mock, 8, 0x0a), 0);
        let cleared: Vec<_> = mock
            .sent
            .iter()
            .filter(|(n, c, data, _)| (*n, *c) == (0x3e, 0x82) && data[1] == 0)
            .map(|(_, _, data, _)| data[0])
            .collect();
        assert_eq!(cleared, if unknown { vec![0, 0x0e] } else { vec![0x0e] });
    }
}

#[cfg(feature = "kontron-fwum-update")]
#[test]
fn lost_cleanup_ack_is_reported_without_activating_or_replaying() {
    let bytes = image(BOARD, 15000, 1);
    let recovery = image(BOARD, 15000, 2);
    let mut mock = Mock::kontron();
    mock.lost_buffer_ack_at = Some(4);
    let mut ipmi = Ipmi::new(mock);
    let mut session = ipmi
        .fwum_prepare_update(
            bridged(),
            &bytes,
            &authorization(&recovery),
            TransportLimits::negotiated(TransportKind::Bridged, 32, 32).unwrap(),
        )
        .unwrap();
    let err = session.stage(|_| true).unwrap_err();
    assert_eq!(err.phase, UpdatePhase::Interrupted);
    assert!(matches!(err.cause, UpdateCause::Cleanup));
    assert_eq!(err.cleanup.len(), 1);
    assert_eq!(err.cleanup[0].outcome, MutationOutcome::Unknown);
    assert_eq!(err.confirmed_bytes, SIZE);
    assert!(matches!(
        session.activate(),
        Err(err) if matches!(err.cause, UpdateCause::InvalidPhase)
    ));
    drop(session);
    let mock = ipmi.release();
    assert_eq!(count(&mock, 0x3e, 0x82), 6);
    assert_eq!(count(&mock, 8, 0x0c), 1);
    assert_eq!(count(&mock, 8, 0x09), 0);
}

#[cfg(feature = "kontron-fwum-update")]
#[test]
fn rejected_rollback_and_read_retries_never_replay_mutations() {
    let bytes = image(BOARD, 15000, 1);
    let recovery = image(BOARD, 15000, 2);
    let mut mock = Mock::kontron();
    mock.scripted.extend([
        Err(Fault::Timeout),
        Err(Fault::Timeout),
        Err(Fault::Timeout),
    ]);
    let mut ipmi = Ipmi::new(mock);
    assert!(matches!(
        ipmi.fwum_inventory(bridged()),
        Err(FwumReadError::Command(_))
    ));
    assert_eq!(count(ipmi.inner_mut(), 8, 0), 3);
    let mut mock = Mock::kontron();
    mock.reject_rollback = true;
    let mut ipmi = Ipmi::new(mock);
    let mut session = ipmi
        .fwum_prepare_update(
            bridged(),
            &bytes,
            &authorization(&recovery),
            TransportLimits::standard(TransportKind::Bridged),
        )
        .unwrap();
    session.stage(|_| true).unwrap();
    session.activate().unwrap();
    session.verify_activation().unwrap();
    let err = session.rollback().unwrap_err();
    assert!(matches!(
        err.cause,
        UpdateCause::Mutation(ref action) if action.outcome == MutationOutcome::Rejected
    ));
    assert_eq!(session.phase(), UpdatePhase::Interrupted);
    drop(session);
    assert_eq!(count(&ipmi.release(), 8, 0x0e), 1);
}
