use std::fmt::{Display, Formatter};
use std::{
    ffi::c_int,
    io,
    os::fd::{AsFd, AsRawFd},
    time::{Duration, Instant},
};

use ipmi_rs_core::connection::NetFn;
use ipmi_rs_core::{
    app::{BmcGlobalEnables, GetBmcGlobalEnables, GlobalEnablesError, SetBmcGlobalEnables},
    storage::sel::{Entry, ParseEntryError},
};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags};

use crate::connection::{
    Address, IpmiConnection, Message, Request, RequestTargetAddress, Response,
};
use crate::{rmcp::CancellationToken, Ipmi, IpmiError};

const MAX_DEVICE_RESPONSE: usize = 1 + 9 + 1024; // Completion code + Sun file header + data.

#[repr(C)]
#[derive(Debug)]
pub struct IpmiMessage {
    netfn: u8,
    cmd: u8,
    data_len: u16,
    data: *mut u8,
}

impl IpmiMessage {
    fn data(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.data, self.data_len as usize) }
    }

    fn is_password_command(&self) -> bool {
        (NetFn::from(self.netfn) == NetFn::App && self.cmd == 0x47)
            || NetFn::from(self.netfn).request_value() == 0x2E
    }

    fn trace_data(&self) -> String {
        if self.is_password_command() {
            "[REDACTED]".into()
        } else {
            format!("{:02X?}", self.data())
        }
    }
}

impl IpmiMessage {
    fn log(&self, level: log::Level) {
        log::log!(level, "  NetFn      = 0x{:02X}", self.netfn);
        log::log!(level, "  Command    = 0x{:02X}", self.cmd);
        log::log!(level, "  Data len   = {}", self.data_len);
        if self.data_len > 0 {
            log::log!(level, "  Data       = {}", self.trace_data());
        }
    }
}

#[cfg(test)]
mod password_log_tests {
    use super::*;

    #[test]
    fn local_trace_detects_password_requests_and_responses() {
        let mut secret = *b"never-log-secret";
        for netfn in [0x06, 0x07] {
            let msg = IpmiMessage {
                netfn,
                cmd: 0x47,
                data_len: secret.len() as u16,
                data: secret.as_mut_ptr(),
            };
            assert!(msg.is_password_command());
            assert_eq!(msg.trace_data(), "[REDACTED]");
        }
        let msg = IpmiMessage {
            netfn: 0x06,
            cmd: 0x44,
            data_len: secret.len() as u16,
            data: secret.as_mut_ptr(),
        };
        assert!(!msg.is_password_command());
        assert_ne!(msg.trace_data(), "[REDACTED]");
        for netfn in [0x2e, 0x2f] {
            let msg = IpmiMessage {
                netfn,
                cmd: 0x01,
                data_len: secret.len() as u16,
                data: secret.as_mut_ptr(),
            };
            assert_eq!(msg.trace_data(), "[REDACTED]");
        }
    }
}

#[cfg(test)]
mod full_block_tests {
    use super::*;

    #[test]
    fn local_receive_buffer_holds_complete_sun_file_block() {
        let mut wire = [0u8; MAX_DEVICE_RESPONSE];
        wire[5..9].copy_from_slice(&1024u32.to_be_bytes());
        wire[9] = 1;
        wire[10..].fill(0xa5);
        let mut address = IpmiSysIfaceAddr::bmc(0);
        let received = IpmiRecv {
            recv_type: 0,
            addr: std::ptr::addr_of_mut!(address).cast(),
            addr_len: core::mem::size_of::<IpmiSysIfaceAddr>() as u32,
            msg_id: 7,
            message: IpmiMessage {
                netfn: 0x2f,
                cmd: 0x44,
                data_len: wire.len() as u16,
                data: wire.as_mut_ptr(),
            },
        };
        let response = Response::try_from(received).unwrap();
        assert_eq!(response.seq(), 7);
        assert_eq!(response.cc(), 0);
        assert_eq!(response.data().len(), 9 + 1024);
        assert_eq!(&response.data()[4..8], &1024u32.to_be_bytes());
        assert_eq!(response.data()[8], 1);
        assert_eq!(&response.data()[9..], &[0xa5; 1024]);
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct IpmiRequest {
    addr: *mut u8,
    addr_len: u32,
    msg_id: i64,
    message: IpmiMessage,
}

impl IpmiRequest {
    pub fn log(&self, level: log::Level) {
        log::log!(level, "  Message ID = 0x{:02X}", self.msg_id);
        self.message.log(level);
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct IpmiRecv {
    recv_type: i32,
    addr: *mut u8,
    addr_len: u32,
    msg_id: i64,
    message: IpmiMessage,
}

impl IpmiRecv {
    fn log(&self, level: log::Level) {
        log::log!(level, "  Type       = 0x{:02X}", self.recv_type);
        log::log!(level, "  Message ID = 0x{:02X}", self.msg_id);
        self.message.log(level);
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CreateResponseError {
    NotAResponse,
    NotEnoughData,
    InvalidCmd,
}

impl TryFrom<IpmiRecv> for Response {
    type Error = CreateResponseError;

    fn try_from(value: IpmiRecv) -> Result<Self, Self::Error> {
        let (netfn, cmd) = (value.message.netfn, value.message.cmd);

        let netfn_parsed = NetFn::from(netfn);

        if netfn_parsed.response_value() == netfn {
            let message = Message::new_raw(netfn, cmd, value.message.data().to_vec());
            let response =
                Response::new(message, value.msg_id).ok_or(CreateResponseError::NotEnoughData)?;
            Ok(response)
        } else {
            Err(CreateResponseError::NotAResponse)
        }
    }
}

mod ioctl {
    const IPMI_IOC_MAGIC: u8 = b'i';

    use nix::{ioctl_read, ioctl_readwrite};

    use super::{c_int, IpmiRecv, IpmiRequest};

    ioctl_readwrite!(ipmi_recv_msg_trunc, IPMI_IOC_MAGIC, 11, IpmiRecv);
    ioctl_read!(ipmi_send_request, IPMI_IOC_MAGIC, 13, IpmiRequest);
    ioctl_read!(ipmi_set_gets_events, IPMI_IOC_MAGIC, 16, c_int);
    ioctl_read!(ipmi_get_my_address, IPMI_IOC_MAGIC, 18, u32);
}

#[repr(C)]
enum IpmiAddr {
    SysIface(IpmiSysIfaceAddr),
    Ipmb(IpmiIpmbAddr),
}

impl IpmiAddr {
    fn ptr(&mut self) -> *mut u8 {
        match self {
            IpmiAddr::SysIface(ref mut bmc_addr) => std::ptr::addr_of_mut!(*bmc_addr) as *mut u8,
            IpmiAddr::Ipmb(ref mut ipmb_addr) => std::ptr::addr_of_mut!(*ipmb_addr) as *mut u8,
        }
    }
    fn size(&self) -> u32 {
        match self {
            IpmiAddr::SysIface(_) => core::mem::size_of::<IpmiSysIfaceAddr>() as u32,
            IpmiAddr::Ipmb(_) => core::mem::size_of::<IpmiIpmbAddr>() as u32,
        }
    }
}

impl TryFrom<RequestTargetAddress> for IpmiAddr {
    type Error = io::Error;

    fn try_from(value: RequestTargetAddress) -> io::Result<Self> {
        match value {
            RequestTargetAddress::Bmc(lun) => {
                Ok(IpmiAddr::SysIface(IpmiSysIfaceAddr::bmc(lun.value())))
            }
            RequestTargetAddress::BmcOrIpmb(addr, channel, lun) => Ok(IpmiAddr::Ipmb(
                IpmiIpmbAddr::new(channel.value() as i16, addr.0, lun.value()),
            )),
            RequestTargetAddress::Bridged { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "explicit RMCP bridge routes are not supported by the device-file interface",
            )),
        }
    }
}

impl Display for IpmiAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            IpmiAddr::SysIface(addr) => {
                write!(f, "System interface (LUN: {})", addr.lun)
            }
            IpmiAddr::Ipmb(addr) => {
                write!(
                    f,
                    "IPMB target (Channel: {}, Target: {}, LUN: {})",
                    addr.channel, addr.target_addr, addr.lun
                )
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq)]
pub struct IpmiSysIfaceAddr {
    ty: i32,
    channel: i16,
    lun: u8,
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq)]
pub struct IpmiIpmbAddr {
    ty: i32,
    channel: i16,
    target_addr: u8,
    lun: u8,
}

impl IpmiIpmbAddr {
    const IPMI_IPMB_ADDR_TYPE: i32 = 0x01;

    pub const fn new(channel: i16, target_addr: u8, lun: u8) -> Self {
        Self {
            ty: Self::IPMI_IPMB_ADDR_TYPE,
            channel,
            target_addr,
            lun,
        }
    }
}

impl IpmiSysIfaceAddr {
    const IPMI_SYSTEM_INTERFACE_ADDR_TYPE: i32 = 0x0c;
    const IPMI_BMC_CHANNEL: i16 = 0xf;

    pub const fn bmc(lun: u8) -> Self {
        Self {
            ty: Self::IPMI_SYSTEM_INTERFACE_ADDR_TYPE,
            channel: Self::IPMI_BMC_CHANNEL,
            lun,
        }
    }
}

pub struct File {
    inner: std::fs::File,
    recv_timeout: Duration,
    seq: i64,
    my_addr: Address,
}

/// Opening the local event queue configures the BMC event buffer and kernel
/// subscription. A failed Set BMC Global Enables may have taken effect.
#[derive(Debug)]
pub enum OpenIpmiEventSetupError {
    /// Get BMC Global Enables failed or returned malformed data.
    ReadEnables(IpmiError<io::Error, GlobalEnablesError>),
    /// Set BMC Global Enables failed; do not automatically repeat the write.
    EnableBuffer(IpmiError<io::Error, GlobalEnablesError>),
    /// OpenIPMI did not accept the subscription (also covers unsupported ioctl).
    Subscribe(io::Error),
}

/// One kernel-delivered OpenIPMI asynchronous event, not a SEL poll.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenIpmiEvent {
    /// Parsed standard, OEM or unknown SEL record.
    pub entry: Entry,
    /// Exact 16 bytes supplied by the kernel.
    pub raw: [u8; 16],
}

/// Receive failures, malformed events, cancellation and timeouts are distinct.
#[derive(Debug)]
pub enum OpenIpmiEventError {
    /// Kernel poll or receive failed.
    Io(io::Error),
    /// The kernel reported an event exceeding the 16-byte record buffer.
    Truncated,
    /// Unexpected message type; no event was consumed.
    UnexpectedType(i32),
    /// The event is not exactly 16 bytes.
    InvalidLength(usize),
    /// The SEL record bytes could not be parsed.
    Malformed(ParseEntryError),
    /// Cancellation was requested.
    Cancelled,
    /// The monotonic deadline elapsed.
    DeadlineExpired,
}

/// Exclusive, bounded receiver of true local OpenIPMI notifications.
///
/// The file is borrowed so command replies cannot be accidentally consumed as
/// events by a concurrent request on this descriptor.
pub struct OpenIpmiEventReceiver<'a> {
    file: &'a mut File,
    subscribed: bool,
}

impl OpenIpmiEventReceiver<'_> {
    fn unsubscribe(&mut self) -> io::Result<()> {
        self.subscribed = false;
        let mut disabled: c_int = 0;
        // SAFETY: the ioctl reads a live, initialized int and borrows no data.
        unsafe { ioctl::ipmi_set_gets_events(self.file.fd(), &mut disabled) }
            .map(|_| ())
            .map_err(Into::into)
    }

    /// Stop notifications on this descriptor; reports an unsubscribe failure.
    /// Drop also unsubscribes on a best-effort basis.
    pub fn close(mut self) -> io::Result<()> {
        self.unsubscribe()
    }

    /// Wait for one kernel notification, checking cancellation at most every
    /// 50 ms. Unexpected messages and malformed events are errors.
    pub fn recv_until(
        &mut self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<OpenIpmiEvent, OpenIpmiEventError> {
        loop {
            if cancellation.is_cancelled() {
                return Err(OpenIpmiEventError::Cancelled);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or(OpenIpmiEventError::DeadlineExpired)?;
            let mut polls = [PollFd::new(self.file.inner.as_fd(), PollFlags::POLLIN)];
            let timeout = remaining.as_millis().clamp(1, 50) as u16;
            match nix::poll::poll(&mut polls, timeout) {
                Ok(0) | Err(Errno::EINTR) => continue,
                Ok(_) => {}
                Err(error) => return Err(OpenIpmiEventError::Io(error.into())),
            }
            let revents = polls[0].revents().unwrap_or(PollFlags::empty());
            if !revents.contains(PollFlags::POLLIN) {
                return Err(OpenIpmiEventError::Io(io::Error::other(format!(
                    "OpenIPMI poll returned {revents:?}"
                ))));
            }
            if cancellation.is_cancelled() {
                return Err(OpenIpmiEventError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(OpenIpmiEventError::DeadlineExpired);
            }
            let mut addr = [0u8; 32];
            let mut data = [0u8; 16];
            let mut recv = IpmiRecv {
                recv_type: 0,
                addr: addr.as_mut_ptr(),
                addr_len: addr.len() as u32,
                msg_id: 0,
                message: IpmiMessage {
                    netfn: 0,
                    cmd: 0,
                    data_len: data.len() as u16,
                    data: data.as_mut_ptr(),
                },
            };
            // SAFETY: both output pointers remain valid throughout the ioctl.
            match unsafe { ioctl::ipmi_recv_msg_trunc(self.file.fd(), &mut recv) } {
                Ok(_) => {}
                Err(Errno::EMSGSIZE) => return Err(OpenIpmiEventError::Truncated),
                Err(Errno::EINTR) => continue,
                Err(error) => return Err(OpenIpmiEventError::Io(error.into())),
            }
            let len = usize::from(recv.message.data_len);
            if len > data.len() {
                return Err(OpenIpmiEventError::Truncated);
            }
            return parse_async_event(recv.recv_type, &data[..len]);
        }
    }
}

impl Drop for OpenIpmiEventReceiver<'_> {
    fn drop(&mut self) {
        if self.subscribed {
            if let Err(error) = self.unsubscribe() {
                log::warn!("Failed to unsubscribe from OpenIPMI events: {error}");
            }
        }
    }
}

fn parse_async_event(recv_type: i32, data: &[u8]) -> Result<OpenIpmiEvent, OpenIpmiEventError> {
    if recv_type != 2 {
        return Err(OpenIpmiEventError::UnexpectedType(recv_type));
    }
    let raw: [u8; 16] = data
        .try_into()
        .map_err(|_| OpenIpmiEventError::InvalidLength(data.len()))?;
    let entry = Entry::parse(&raw).map_err(OpenIpmiEventError::Malformed)?;
    Ok(OpenIpmiEvent { entry, raw })
}

fn enable_event_msg_buffer<CON: IpmiConnection<Error = io::Error>>(
    ipmi: &mut Ipmi<CON>,
) -> Result<(), OpenIpmiEventSetupError> {
    let enables = ipmi
        .send_recv(GetBmcGlobalEnables)
        .map_err(OpenIpmiEventSetupError::ReadEnables)?;
    if !enables.contains(BmcGlobalEnables::EVENT_MESSAGE_BUFFER) {
        ipmi.send_recv(SetBmcGlobalEnables(
            enables | BmcGlobalEnables::EVENT_MESSAGE_BUFFER,
        ))
        .map_err(OpenIpmiEventSetupError::EnableBuffer)?;
    }
    Ok(())
}

impl File {
    fn fd(&mut self) -> c_int {
        self.inner.as_raw_fd()
    }

    pub fn new(path: impl AsRef<std::path::Path>, recv_timeout: Duration) -> io::Result<Self> {
        let mut inner = std::fs::File::open(path)?;

        let my_addr = match Self::load_my_address_from_file(&mut inner) {
            Ok(addr) => addr,
            Err(e) => {
                log::warn!("Failed to get local address, defaulting to 0x20: {:?}", e);
                Address(0x20)
            }
        };

        Ok(Self {
            inner,
            recv_timeout,
            seq: -1,
            my_addr,
        })
    }

    /// Enable the BMC event buffer (preserving all other enable bits) and
    /// subscribe this descriptor to OpenIPMI asynchronous events. No setup
    /// failure is silently treated as an empty event stream.
    pub fn open_event_receiver(
        &mut self,
    ) -> Result<OpenIpmiEventReceiver<'_>, OpenIpmiEventSetupError> {
        enable_event_msg_buffer(&mut Ipmi::new(&mut *self))?;
        let mut enabled: c_int = 1;
        // SAFETY: the ioctl reads a live, initialized int and borrows no data.
        unsafe { ioctl::ipmi_set_gets_events(self.fd(), &mut enabled) }
            .map_err(|error| OpenIpmiEventSetupError::Subscribe(error.into()))?;
        Ok(OpenIpmiEventReceiver {
            file: self,
            subscribed: true,
        })
    }

    fn load_my_address_from_file(file: &mut std::fs::File) -> io::Result<Address> {
        let mut my_addr: u32 = 8;
        unsafe { ioctl::ipmi_get_my_address(file.as_raw_fd(), std::ptr::addr_of_mut!(my_addr))? };
        if let Ok(addr) = u8::try_from(my_addr) {
            Ok(Address(addr))
        } else {
            Err(io::Error::other(format!(
                "ipmi_get_my_address returned non-u8 address: {my_addr}"
            )))
        }
    }
}

impl IpmiConnection for File {
    type SendError = io::Error;
    type RecvError = io::Error;
    type Error = io::Error;

    fn send(&mut self, request: &mut Request) -> io::Result<()> {
        let mut addr: IpmiAddr = match request.target() {
            RequestTargetAddress::BmcOrIpmb(a, _, lun) if a == self.my_addr => {
                RequestTargetAddress::Bmc(lun)
            }
            x => x,
        }
        .try_into()?;

        self.seq += 1;

        let netfn = request.netfn_raw();
        let cmd = request.cmd();
        let seq = self.seq;
        let data = request.data_mut();

        let data_len = data.len() as u16;
        let ptr = data.as_mut_ptr();

        log::debug!("Sending request (netfn: 0x{netfn:02X}, cmd: 0x{cmd:02X}) to {addr}");
        let ipmi_message = IpmiMessage {
            netfn,
            cmd,
            data_len,
            data: ptr,
        };
        let mut request = IpmiRequest {
            addr: addr.ptr(),
            addr_len: addr.size(),
            msg_id: seq,
            message: ipmi_message,
        };

        request.log(log::Level::Trace);

        // SAFETY: we send a mut pointer to an owned struct (`request`),
        // which has the correct layout for this IOCTL call.
        unsafe {
            ioctl::ipmi_send_request(self.fd(), std::ptr::addr_of_mut!(request))?;
        }

        // Ensure that data and bmc_addr live until _after_ the IOCTL completes.
        #[allow(clippy::drop_non_drop)]
        drop(request);
        #[allow(clippy::drop_non_drop)]
        drop(addr);

        Ok(())
    }

    fn recv(&mut self) -> io::Result<Response> {
        let start = std::time::Instant::now();

        let mut bmc_addr = IpmiSysIfaceAddr::bmc(0);

        let mut response_data = [0u8; MAX_DEVICE_RESPONSE];

        let response_data_len = response_data.len() as u16;
        let response_data_ptr = response_data.as_mut_ptr();

        let mut recv = IpmiRecv {
            addr: std::ptr::addr_of_mut!(bmc_addr) as *mut u8,
            addr_len: core::mem::size_of::<IpmiSysIfaceAddr>() as u32,
            msg_id: 0,
            recv_type: 0,
            message: IpmiMessage {
                netfn: 0,
                cmd: 0,
                data_len: response_data_len,
                data: response_data_ptr,
            },
        };

        // Poll the device for available data.
        //
        // As of 2026-01-14, the linux driver tracks state for our
        // `fd`, so any data received here will be in response to
        // command we have sent.
        //
        // Ref: https://github.com/datdenkikniet/ipmi-rs/issues/39#issuecomment-3747421945
        let mut polls = [PollFd::new(self.inner.as_fd(), PollFlags::POLLIN)];
        let poll = nix::poll::poll(
            polls.as_mut_slice(),
            self.recv_timeout.as_millis().try_into().unwrap_or(u16::MAX),
        )?;

        if poll != 1 {
            log::warn!(
                "Failed to receive message after waiting for {} ms.",
                start.elapsed().as_millis(),
            );

            return Err(Errno::EAGAIN.into());
        }

        // SAFETY: we send a mut pointer to a fully owned struct (`recv`),
        // which has the correct layout for this IOCTL call.
        let ipmi_result =
            unsafe { ioctl::ipmi_recv_msg_trunc(self.fd(), std::ptr::addr_of_mut!(recv)) };

        let ipmi_result = match ipmi_result {
            Ok(_) => recv,
            Err(e) => {
                log::error!("Error occurred while reading from IPMI: {e:?}");
                return Err(e.into());
            }
        };

        // Ensure that response_data and bmc_addr live until _after_ the
        // IOCTL completes.
        #[allow(dropping_copy_types)]
        drop(response_data);
        #[allow(clippy::drop_non_drop)]
        drop(bmc_addr);

        log::debug!("Received response after {} ms", start.elapsed().as_millis());
        ipmi_result.log(log::Level::Trace);

        match Response::try_from(ipmi_result) {
            Ok(response) => {
                if response.seq() == self.seq {
                    Ok(response)
                } else {
                    Err(io::Error::other(format!(
                        "Invalid sequence number on response. Expected {}, got {}",
                        self.seq,
                        response.seq()
                    )))
                }
            }
            Err(e) => Err(io::Error::other(format!(
                "Error while creating response. {e:?}"
            ))),
        }
    }

    fn send_recv(&mut self, request: &mut Request) -> io::Result<Response> {
        self.send(request)?;

        self.recv()
    }

    fn send_recv_deadline(
        &mut self,
        request: &mut Request,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> io::Result<Response> {
        let original_timeout = self.recv_timeout;
        let result = (|| {
            if cancellation.is_cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.send(request)?;
            loop {
                if cancellation.is_cancelled() {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|duration| !duration.is_zero())
                    .ok_or(io::ErrorKind::TimedOut)?;
                self.recv_timeout = remaining
                    .min(original_timeout)
                    .min(Duration::from_millis(50));
                match self.recv() {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    response => return response,
                }
            }
        })();
        self.recv_timeout = original_timeout;
        result
    }
}

#[cfg(test)]
mod bridge_tests {
    use super::*;
    use crate::connection::{Channel, IpmbTarget, LogicalUnit};

    #[test]
    fn explicit_rmcp_route_is_not_silently_truncated_to_one_hop() {
        let hop = |addr| IpmbTarget::new(Address(addr), Channel::Primary, LogicalUnit::Zero);
        let route = RequestTargetAddress::Bridged {
            target: hop(0x52),
            transit: Some(hop(0x30)),
        };
        assert!(matches!(
            IpmiAddr::try_from(route),
            Err(error) if error.kind() == io::ErrorKind::Unsupported
        ));
    }
}

#[cfg(test)]
#[path = "file/events_tests.rs"]
mod events_tests;
