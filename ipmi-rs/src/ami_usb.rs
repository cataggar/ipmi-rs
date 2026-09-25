//! Opt-in AMI virtual-CD IPMI transport through Linux SCSI generic (`SG_IO`).
//!
//! This protocol is not a generic USB or libusb interface. Only devices which
//! answer the AMI identify command with `$$$AMI$$$` are accepted.

use std::{io, path::Path, time::Duration};

use crate::{
    connection::{IpmiConnection, Request, Response},
    rmcp::CancellationToken,
};

/// An AMI transport failure. The completion byte in a valid response is
/// returned through `Response` (and handled by `Ipmi`), not this error type.
#[derive(Debug)]
pub enum AmiUsbError {
    /// SCSI generic is available only on Linux.
    UnsupportedPlatform,
    /// Device does not provide the AMI G2 virtual-CD signature.
    UnsupportedDevice,
    /// The requested IPMI address or netfn cannot be represented.
    InvalidRequest,
    /// The request exceeds the supported 255-byte IPMI data limit.
    RequestTooLong,
    /// Another request is pending.
    RequestPending,
    /// A previous request's outcome was unknown; reopen before sending again.
    ConnectionUncertain,
    /// The operation was cancelled before dispatch.
    Cancelled,
    /// SCSI I/O error.
    Io(io::Error),
    /// No pending response.
    NoPendingRequest,
    /// The operation exceeded its deadline.
    Timeout,
    /// Invalid signature, length, or incomplete response.
    InvalidResponse,
    /// AMI CONFIG_CMD status (distinct from the IPMI completion code).
    DeviceStatus(u16),
    /// A request may have executed. Do not automatically retry a mutation.
    OutcomeUnknown(Box<AmiUsbError>),
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        os::fd::AsRawFd,
        time::Instant,
    };

    use crate::connection::{Message, RequestTargetAddress};

    const SIGNATURE: &[u8; 16] = b"$G2-CONFIG-HOST$";
    const HEADER_LEN: usize = 36;
    const MAX_RESPONSE: usize = 256;
    const POLL_INTERVAL: Duration = Duration::from_millis(10);
    const IO_INTERVAL: Duration = Duration::from_millis(200);

    enum Direction {
        Read,
        Write,
    }

    trait ScsiDevice: Send {
        fn exchange(
            &mut self,
            cdb: [u8; 10],
            direction: Direction,
            data: &mut [u8],
            timeout: Duration,
        ) -> io::Result<usize>;
    }

    #[repr(C)]
    struct SgIoHdr {
        interface_id: libc::c_int,
        dxfer_direction: libc::c_int,
        cmd_len: u8,
        mx_sb_len: u8,
        iovec_count: u16,
        dxfer_len: u32,
        dxferp: *mut libc::c_void,
        cmdp: *mut u8,
        sbp: *mut u8,
        timeout: u32,
        flags: u32,
        pack_id: libc::c_int,
        usr_ptr: *mut libc::c_void,
        status: u8,
        masked_status: u8,
        msg_status: u8,
        sb_len_wr: u8,
        host_status: u16,
        driver_status: u16,
        resid: libc::c_int,
        duration: u32,
        info: u32,
    }

    struct LinuxSg(File);

    impl ScsiDevice for LinuxSg {
        fn exchange(
            &mut self,
            mut cdb: [u8; 10],
            direction: Direction,
            data: &mut [u8],
            timeout: Duration,
        ) -> io::Result<usize> {
            let mut sense = [0u8; 32];
            let mut hdr = SgIoHdr {
                interface_id: b'S' as libc::c_int,
                dxfer_direction: match direction {
                    Direction::Read => -3,
                    Direction::Write => -2,
                },
                cmd_len: 10,
                mx_sb_len: sense.len() as u8,
                iovec_count: 0,
                dxfer_len: data.len() as u32,
                dxferp: data.as_mut_ptr().cast(),
                cmdp: cdb.as_mut_ptr(),
                sbp: sense.as_mut_ptr(),
                timeout: timeout.as_millis().clamp(1, u32::MAX as u128) as u32,
                flags: 0,
                pack_id: 0,
                usr_ptr: std::ptr::null_mut(),
                status: 0,
                masked_status: 0,
                msg_status: 0,
                sb_len_wr: 0,
                host_status: 0,
                driver_status: 0,
                resid: 0,
                duration: 0,
                info: 0,
            };
            // SAFETY: SG_IO (0x2285) receives a correctly laid out sg_io_hdr
            // whose pointers refer to live buffers for the duration of ioctl.
            if unsafe { libc::ioctl(self.0.as_raw_fd(), 0x2285, &mut hdr) } < 0 {
                return Err(io::Error::last_os_error());
            }
            if hdr.status != 0
                || hdr.host_status != 0
                || hdr.driver_status != 0
                || hdr.info & 1 != 0
                || hdr.resid < 0
                || hdr.resid as usize > data.len()
            {
                return Err(io::Error::other("AMI SG_IO command failed"));
            }
            Ok(data.len() - hdr.resid as usize)
        }
    }

    fn cdb(opcode: u8, sector: u8) -> [u8; 10] {
        let mut packet = [0; 10];
        packet[0] = opcode;
        packet[5] = sector;
        packet[7..9].copy_from_slice(&1u16.to_be_bytes());
        packet
    }

    struct Pending {
        netfn: u8,
        cmd: u8,
        deadline: Instant,
    }

    /// A Linux `/dev/sgN` connection to an AMI G2 virtual-CD IPMI device.
    pub struct AmiUsb {
        device: Box<dyn ScsiDevice>,
        timeout: Duration,
        cancellation: CancellationToken,
        operation_deadline: Option<Instant>,
        operation_cancellation: Option<CancellationToken>,
        pending: Option<Pending>,
        uncertain: bool,
        sequence: i64,
    }

    impl AmiUsb {
        /// Open the specified SCSI generic device and verify its AMI identity.
        ///
        /// No device enumeration or USB VID/PID matching is performed.
        pub fn open(path: impl AsRef<Path>, timeout: Duration) -> Result<Self, AmiUsbError> {
            if timeout.is_zero() {
                return Err(AmiUsbError::Timeout);
            }
            let device = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(AmiUsbError::Io)?;
            // The wire protocol has no transaction ID: keep an advisory
            // exclusive lock until drop so cooperating clients cannot mix replies.
            if unsafe { libc::flock(device.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(AmiUsbError::Io(io::Error::last_os_error()));
            }
            Self::with_device(Box::new(LinuxSg(device)), timeout)
        }

        fn with_device(
            mut device: Box<dyn ScsiDevice>,
            timeout: Duration,
        ) -> Result<Self, AmiUsbError> {
            if timeout.is_zero() {
                return Err(AmiUsbError::Timeout);
            }
            let mut identity = [0u8; 10];
            let mut identify = [0; 10];
            identify[0] = 0xEE;
            let len = device
                .exchange(
                    identify,
                    Direction::Read,
                    &mut identity,
                    timeout.min(IO_INTERVAL),
                )
                .map_err(|error| {
                    if error.raw_os_error() == Some(libc::ENOTTY) {
                        AmiUsbError::UnsupportedDevice
                    } else {
                        AmiUsbError::Io(error)
                    }
                })?;
            if len < 9 || &identity[..9] != b"$$$AMI$$$" {
                return Err(AmiUsbError::UnsupportedDevice);
            }
            Ok(Self {
                device,
                timeout,
                cancellation: CancellationToken::default(),
                operation_deadline: None,
                operation_cancellation: None,
                pending: None,
                uncertain: false,
                sequence: 0,
            })
        }

        /// A sticky cancellation signal. Reset only after the operation returns.
        ///
        /// Linux SG_IO cannot be interrupted mid-ioctl; each operation is
        /// limited to at most 200 ms before cancellation is checked again.
        pub fn cancellation_token(&self) -> CancellationToken {
            self.cancellation.clone()
        }

        fn cancelled(&self) -> bool {
            self.cancellation.is_cancelled()
                || self
                    .operation_cancellation
                    .as_ref()
                    .is_some_and(CancellationToken::is_cancelled)
        }

        fn remaining(&self, deadline: Instant) -> Result<Duration, AmiUsbError> {
            if self.cancelled() {
                return Err(AmiUsbError::Cancelled);
            }
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(AmiUsbError::Timeout)
        }

        fn transfer(
            &mut self,
            sector: u8,
            direction: Direction,
            buffer: &mut [u8],
            deadline: Instant,
        ) -> Result<(), AmiUsbError> {
            let timeout = self.remaining(deadline)?.min(IO_INTERVAL);
            let op = match direction {
                Direction::Read => 0xE3,
                Direction::Write => 0xE2,
            };
            let len = self
                .device
                .exchange(cdb(op, sector), direction, buffer, timeout)
                .map_err(AmiUsbError::Io)?;
            if len != buffer.len() {
                return Err(AmiUsbError::InvalidResponse);
            }
            Ok(())
        }

        fn header(in_len: u32) -> [u8; HEADER_LEN] {
            let mut header = [0; HEADER_LEN];
            header[..16].copy_from_slice(SIGNATURE);
            header[20..24].copy_from_slice(&in_len.to_le_bytes());
            header[24..28].copy_from_slice(&(MAX_RESPONSE as u32).to_le_bytes());
            header
        }

        fn status(header: &[u8; HEADER_LEN]) -> Result<(u16, usize), AmiUsbError> {
            if &header[..16] != SIGNATURE || header[16..18] != [0, 0] {
                return Err(AmiUsbError::InvalidResponse);
            }
            let status = u16::from_le_bytes([header[18], header[19]]);
            let length = u32::from_le_bytes(header[24..28].try_into().unwrap()) as usize;
            if length > MAX_RESPONSE {
                return Err(AmiUsbError::InvalidResponse);
            }
            Ok((status, length))
        }

        fn poison(&mut self, error: AmiUsbError) -> AmiUsbError {
            self.uncertain = true;
            self.pending = None;
            AmiUsbError::OutcomeUnknown(Box::new(error))
        }
    }

    impl IpmiConnection for AmiUsb {
        type SendError = AmiUsbError;
        type RecvError = AmiUsbError;
        type Error = AmiUsbError;

        fn supports_long_mutation_workflows(&self) -> bool {
            true
        }

        fn send(&mut self, request: &mut Request) -> Result<(), Self::SendError> {
            if self.uncertain {
                return Err(AmiUsbError::ConnectionUncertain);
            }
            if self.pending.is_some() {
                return Err(AmiUsbError::RequestPending);
            }
            if self.cancelled() {
                return Err(AmiUsbError::Cancelled);
            }
            if request.netfn_raw() & 1 != 0
                || request.netfn_raw() > 0x3e
                || !matches!(
                    request.target(),
                    RequestTargetAddress::Bmc(_)
                        | RequestTargetAddress::BmcOrIpmb(
                            crate::connection::Address(0x20),
                            crate::connection::Channel::Primary,
                            _
                        )
                )
            {
                return Err(AmiUsbError::InvalidRequest);
            }
            if request.data().len() > 255 {
                return Err(AmiUsbError::RequestTooLong);
            }
            let deadline = Instant::now() + self.timeout;
            let deadline = self
                .operation_deadline
                .map_or(deadline, |limit| limit.min(deadline));
            let mut payload = vec![
                (request.netfn_raw() << 2) | request.target().lun().value(),
                request.cmd(),
            ];
            payload.extend_from_slice(request.data());
            let mut header = Self::header(payload.len() as u32);
            let pending = Pending {
                netfn: request.netfn_raw(),
                cmd: request.cmd(),
                deadline,
            };
            self.pending = Some(pending);
            if let Err(error) = self
                .transfer(1, Direction::Write, &mut header, deadline)
                .and_then(|()| self.transfer(2, Direction::Write, &mut payload, deadline))
            {
                return Err(self.poison(error));
            }
            Ok(())
        }

        fn recv(&mut self) -> Result<Response, Self::RecvError> {
            let pending = self.pending.take().ok_or(AmiUsbError::NoPendingRequest)?;
            let result = (|| loop {
                let mut header = [0u8; HEADER_LEN];
                self.transfer(1, Direction::Read, &mut header, pending.deadline)?;
                let (status, len) = Self::status(&header)?;
                if status & 0x8000 != 0 {
                    std::thread::sleep(POLL_INTERVAL.min(self.remaining(pending.deadline)?));
                    continue;
                }
                if status != 0 {
                    return Err(AmiUsbError::DeviceStatus(status));
                }
                if len == 0 {
                    return Err(AmiUsbError::InvalidResponse);
                }
                let mut data = vec![0u8; len];
                self.transfer(2, Direction::Read, &mut data, pending.deadline)?;
                self.sequence += 1;
                return Response::new(
                    Message::new_raw(pending.netfn | 1, pending.cmd, data),
                    self.sequence,
                )
                .ok_or(AmiUsbError::InvalidResponse);
            })();
            result.map_err(|error| self.poison(error))
        }

        fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
            self.send(request)?;
            self.recv()
        }

        fn send_recv_deadline(
            &mut self,
            request: &mut Request,
            deadline: Instant,
            cancellation: &CancellationToken,
        ) -> Result<Response, Self::Error> {
            if cancellation.is_cancelled() {
                return Err(AmiUsbError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(AmiUsbError::Timeout);
            }
            let old_deadline = self.operation_deadline.replace(deadline);
            let old_cancellation = self.operation_cancellation.replace(cancellation.clone());
            let result = self.send_recv(request);
            self.operation_deadline = old_deadline;
            self.operation_cancellation = old_cancellation;
            result
        }
    }

    #[cfg(test)]
    mod tests;
}

#[cfg(target_os = "linux")]
pub use linux::AmiUsb;

/// An unsupported-platform stub; enabling the feature is safe on non-Linux.
#[cfg(not(target_os = "linux"))]
pub struct AmiUsb;

#[cfg(not(target_os = "linux"))]
impl AmiUsb {
    /// Return `UnsupportedPlatform` on non-Linux hosts.
    pub fn open(_path: impl AsRef<Path>, _timeout: Duration) -> Result<Self, AmiUsbError> {
        Err(AmiUsbError::UnsupportedPlatform)
    }
}

#[cfg(not(target_os = "linux"))]
impl IpmiConnection for AmiUsb {
    type SendError = AmiUsbError;
    type RecvError = AmiUsbError;
    type Error = AmiUsbError;

    fn send(&mut self, _request: &mut Request) -> Result<(), AmiUsbError> {
        Err(AmiUsbError::UnsupportedPlatform)
    }
    fn recv(&mut self) -> Result<Response, AmiUsbError> {
        Err(AmiUsbError::UnsupportedPlatform)
    }
    fn send_recv(&mut self, _request: &mut Request) -> Result<Response, AmiUsbError> {
        Err(AmiUsbError::UnsupportedPlatform)
    }
}
