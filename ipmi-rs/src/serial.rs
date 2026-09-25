//! IPMI serial basic (IPMB) and terminal-mode connections.
//!
//! Both modes use one outstanding request, a single deadline, and no automatic
//! retransmission. After a send has begun, a failed exchange may have executed.

use std::{
    io::{self, Read, Write},
    path::Path,
    time::{Duration, Instant},
};

use crate::{
    connection::{IpmiConnection, Message, Request, RequestTargetAddress, Response},
    rmcp::CancellationToken,
};

const BMC: u8 = 0x20;
const REQUESTER: u8 = 0x81;
const MAX_FRAME: usize = 256;
const MAX_UNRELATED: usize = 32;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The serial wire protocol configured on the BMC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerialMode {
    /// Binary IPMB packets delimited by `A0`/`A5`, with `AA` escaping.
    Basic,
    /// ASCII hexadecimal packets delimited by `[`/`]` and CRLF.
    Terminal,
}

/// A failure before transmission, or one whose outcome may be unknown.
#[derive(Debug)]
pub enum SerialSendError {
    /// The previous request still awaits a response.
    RequestPending,
    /// A previous request's outcome is unknown; reopen before sending again.
    ConnectionUncertain,
    /// The target or channel cannot be addressed by this interface.
    UnsupportedTarget,
    /// The request netfn must be a request value.
    InvalidNetfn,
    /// The request exceeds the selected mode's 40-byte direct limit.
    RequestTooLong,
    /// Cancellation was requested before transmission.
    Cancelled,
    /// Transmission may have started; do not automatically retry mutations.
    OutcomeUnknown(io::Error),
}

/// An error while waiting for a serial response.
#[derive(Debug)]
pub enum SerialRecvError {
    /// No request is pending.
    NoPendingRequest,
    /// The operation exceeded its deadline.
    Timeout,
    /// The operation was cancelled.
    Cancelled,
    /// The peer sent malformed, oversized, or excessive unrelated data.
    InvalidFrame,
    /// Too many unrelated responses were received.
    TooManyUnrelated,
    /// A serial I/O error occurred.
    Io(io::Error),
}

/// Connection error, distinguishing pre-send failures from uncertain outcomes.
#[derive(Debug)]
pub enum SerialError {
    /// No request bytes were sent.
    Send(SerialSendError),
    /// A standalone `recv` failed.
    Receive(SerialRecvError),
    /// The request may have executed; never blindly retry a mutation.
    OutcomeUnknown(SerialRecvError),
}

impl From<SerialSendError> for SerialError {
    fn from(value: SerialSendError) -> Self {
        Self::Send(value)
    }
}

impl From<SerialRecvError> for SerialError {
    fn from(value: SerialRecvError) -> Self {
        Self::Receive(value)
    }
}

trait Port: Read + Write + Send {}
impl<T: Read + Write + Send> Port for T {}

struct SerialPortAdapter(Box<dyn serialport::SerialPort>);

impl Read for SerialPortAdapter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for SerialPortAdapter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[derive(Clone, Copy)]
struct Expected {
    netfn: u8,
    cmd: u8,
    seq: u8,
    target: u8,
}

struct Pending {
    outer: Expected,
    inner: Option<Expected>,
    deadline: Instant,
}

/// A serial IPMI connection. Construct it with an explicit port, baud and mode.
pub struct SerialConnection {
    port: Box<dyn Port>,
    mode: SerialMode,
    timeout: Duration,
    cancellation: CancellationToken,
    operation_deadline: Option<Instant>,
    operation_cancellation: Option<CancellationToken>,
    sequence: u8,
    pending: Option<Pending>,
    uncertain: bool,
}

impl SerialConnection {
    /// Open a serial port configured for 8N1 with no flow control.
    ///
    /// Supported baud rates: 2400, 9600, 19200, 38400, 57600, 115200,
    /// 230400, 460800 (where supported by the OS/driver). Timeouts must be
    /// nonzero. Port I/O is checked for cancellation at most every 50 ms.
    pub fn open(
        path: impl AsRef<Path>,
        baud: u32,
        mode: SerialMode,
        timeout: Duration,
    ) -> Result<Self, serialport::Error> {
        if ![2400, 9600, 19200, 38400, 57600, 115200, 230400, 460800].contains(&baud)
            || timeout.is_zero()
        {
            return Err(serialport::Error::new(
                serialport::ErrorKind::InvalidInput,
                "unsupported baud rate or zero timeout",
            ));
        }
        let path = path.as_ref().to_str().ok_or_else(|| {
            serialport::Error::new(serialport::ErrorKind::InvalidInput, "non-UTF-8 serial path")
        })?;
        let port = serialport::new(path, baud)
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .timeout(POLL_INTERVAL.min(timeout))
            .open()?;
        Ok(Self::with_port(
            Box::new(SerialPortAdapter(port)),
            mode,
            timeout,
        ))
    }

    fn with_port(port: Box<dyn Port>, mode: SerialMode, timeout: Duration) -> Self {
        Self {
            port,
            mode,
            timeout,
            cancellation: CancellationToken::default(),
            operation_deadline: None,
            operation_cancellation: None,
            sequence: 0,
            pending: None,
            uncertain: false,
        }
    }

    /// A sticky cancellation signal. Reset it only after an operation returns.
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

    fn poison_send(&mut self, error: io::Error) -> SerialSendError {
        self.pending = None;
        self.uncertain = true;
        SerialSendError::OutcomeUnknown(error)
    }

    fn check(&self, deadline: Instant) -> Result<(), SerialRecvError> {
        if self.cancelled() {
            Err(SerialRecvError::Cancelled)
        } else if Instant::now() >= deadline {
            Err(SerialRecvError::Timeout)
        } else {
            Ok(())
        }
    }

    fn next_byte(&mut self, deadline: Instant) -> Result<u8, SerialRecvError> {
        loop {
            self.check(deadline)?;
            let mut byte = [0];
            match self.port.read(&mut byte) {
                Ok(1) => return Ok(byte[0]),
                Ok(0) => {
                    return Err(SerialRecvError::Io(io::Error::from(
                        io::ErrorKind::UnexpectedEof,
                    )))
                }
                Ok(_) => unreachable!(),
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(err) => return Err(SerialRecvError::Io(err)),
            }
        }
    }

    fn frame(&mut self, deadline: Instant) -> Result<Vec<u8>, SerialRecvError> {
        let (start, end) = match self.mode {
            SerialMode::Basic => (0xA0, 0xA5),
            SerialMode::Terminal => (b'[', b']'),
        };
        let mut frame = Vec::new();
        let mut started = false;
        let mut escaped = false;
        let mut noise = 0;
        loop {
            let byte = self.next_byte(deadline)?;
            if !started {
                if byte == start {
                    started = true;
                } else {
                    noise += 1;
                    if noise > MAX_FRAME * 2 {
                        return Err(SerialRecvError::InvalidFrame);
                    }
                }
                continue;
            }
            if byte == start {
                frame.clear();
                escaped = false;
                continue;
            }
            if self.mode == SerialMode::Basic {
                if escaped {
                    let value = match byte {
                        0xB0 => 0xA0,
                        0xB5 => 0xA5,
                        0xB6 => 0xA6,
                        0xBA => 0xAA,
                        0x3B => 0x1B,
                        _ => return Err(SerialRecvError::InvalidFrame),
                    };
                    frame.push(value);
                    escaped = false;
                } else if byte == 0xAA {
                    escaped = true;
                    continue;
                } else if byte == end {
                    return Ok(frame);
                } else if byte == 0xA6 {
                    continue;
                } else {
                    frame.push(byte);
                }
            } else if byte == end {
                let hex: Vec<u8> = frame
                    .into_iter()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect();
                if !hex.len().is_multiple_of(2) || hex.len() / 2 > MAX_FRAME {
                    return Err(SerialRecvError::InvalidFrame);
                }
                return hex
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| {
                        let high = (pair[0] as char).to_digit(16);
                        let low = (pair[1] as char).to_digit(16);
                        high.zip(low)
                            .map(|(h, l)| ((h << 4) | l) as u8)
                            .ok_or(SerialRecvError::InvalidFrame)
                    })
                    .collect();
            } else {
                frame.push(byte);
            }
            if frame.len() > MAX_FRAME * if self.mode == SerialMode::Basic { 1 } else { 3 } {
                return Err(SerialRecvError::InvalidFrame);
            }
        }
    }

    fn receive_matching(
        &mut self,
        expected: Expected,
        deadline: Instant,
    ) -> Result<Vec<u8>, SerialRecvError> {
        let mut unrelated = 0;
        loop {
            let frame = self.frame(deadline)?;
            let matched = match self.mode {
                SerialMode::Basic => parse_ipmb(&frame, expected),
                SerialMode::Terminal => (frame.len() >= 4
                    && frame[0] == (expected.netfn | 4)
                    && frame[1] & !3 == expected.seq << 2
                    && frame[2] == expected.cmd)
                    .then(|| frame[3..].to_vec()),
            };
            if let Some(body) = matched {
                return Ok(body);
            }
            unrelated += 1;
            if unrelated >= MAX_UNRELATED {
                return Err(SerialRecvError::TooManyUnrelated);
            }
        }
    }
}

fn checksum(data: &[u8]) -> u8 {
    0u8.wrapping_sub(data.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)))
}

fn ipmb(target: u8, netfn: u8, source: u8, seq: u8, cmd: u8, data: &[u8]) -> Vec<u8> {
    let mut msg = vec![target, netfn];
    msg.push(checksum(&msg));
    msg.extend_from_slice(&[source, seq << 2, cmd]);
    msg.extend_from_slice(data);
    msg.push(checksum(&msg[3..]));
    msg
}

fn parse_ipmb(frame: &[u8], expected: Expected) -> Option<Vec<u8>> {
    if frame.len() < 8
        || checksum(&frame[..3]) != 0
        || checksum(&frame[3..]) != 0
        || frame[0] != REQUESTER
        || frame[1] != ((expected.netfn | 4) & !3)
        || frame[3] != expected.target
        || frame[4] != ((expected.seq << 2) | (expected.netfn & 3))
        || frame[5] != expected.cmd
    {
        return None;
    }
    Some(frame[6..frame.len() - 1].to_vec())
}

fn encode(mode: SerialMode, payload: &[u8]) -> Vec<u8> {
    match mode {
        SerialMode::Basic => {
            let mut wire = Vec::with_capacity(payload.len() * 2 + 2);
            wire.push(0xA0);
            for &byte in payload {
                if let Some(code) = match byte {
                    0xA0 => Some(0xB0),
                    0xA5 => Some(0xB5),
                    0xA6 => Some(0xB6),
                    0xAA => Some(0xBA),
                    0x1B => Some(0x3B),
                    _ => None,
                } {
                    wire.extend_from_slice(&[0xAA, code]);
                } else {
                    wire.push(byte);
                }
            }
            wire.push(0xA5);
            wire
        }
        SerialMode::Terminal => {
            let mut wire = Vec::with_capacity(payload.len() * 2 + 4);
            wire.push(b'[');
            for &byte in payload {
                wire.push(b"0123456789abcdef"[(byte >> 4) as usize]);
                wire.push(b"0123456789abcdef"[(byte & 0xf) as usize]);
            }
            wire.extend_from_slice(b"]\r\n");
            wire
        }
    }
}

impl IpmiConnection for SerialConnection {
    type SendError = SerialSendError;
    type RecvError = SerialRecvError;
    type Error = SerialError;

    fn send(&mut self, request: &mut Request) -> Result<(), Self::SendError> {
        if self.uncertain {
            return Err(SerialSendError::ConnectionUncertain);
        }
        if self.pending.is_some() {
            return Err(SerialSendError::RequestPending);
        }
        if self.cancelled() {
            return Err(SerialSendError::Cancelled);
        }
        if request.netfn_raw() & 1 != 0 || request.netfn_raw() > 0x3e {
            return Err(SerialSendError::InvalidNetfn);
        }
        let bridge = match request.target() {
            RequestTargetAddress::Bmc(_) => None,
            RequestTargetAddress::BmcOrIpmb(address, channel, _)
                if address.0 == BMC && channel.value() == 0 =>
            {
                None
            }
            RequestTargetAddress::BmcOrIpmb(address, channel, _) if channel.value() <= 0xB => {
                Some((address.0, channel.value()))
            }
            _ => return Err(SerialSendError::UnsupportedTarget),
        };
        let max_data = match (self.mode, bridge.is_some()) {
            (SerialMode::Basic, false) => 33,
            (SerialMode::Terminal, false) => 37,
            (SerialMode::Basic, true) => 25,
            (SerialMode::Terminal, true) => 29,
        };
        if request.data().len() > max_data {
            return Err(SerialSendError::RequestTooLong);
        }
        let deadline = Instant::now() + self.timeout;
        let deadline = self
            .operation_deadline
            .map_or(deadline, |limit| limit.min(deadline));
        self.sequence = (self.sequence + 1) & 0x3f;
        let seq = self.sequence;
        let lun = request.target().lun().value();
        let inner = bridge.map(|(target, _)| Expected {
            netfn: (request.netfn_raw() << 2) | lun,
            cmd: request.cmd(),
            seq,
            target,
        });
        let outer = Expected {
            netfn: if bridge.is_some() {
                0x18
            } else {
                (request.netfn_raw() << 2) | lun
            },
            cmd: if bridge.is_some() {
                0x34
            } else {
                request.cmd()
            },
            seq,
            target: BMC,
        };
        let mut body = Vec::new();
        if let Some((target, channel)) = bridge {
            body.push(channel | 0x40);
            body.extend_from_slice(&ipmb(
                target,
                (request.netfn_raw() << 2) | lun,
                REQUESTER,
                seq,
                request.cmd(),
                request.data(),
            ));
        } else {
            body.extend_from_slice(request.data());
        }
        let payload = match self.mode {
            SerialMode::Basic => ipmb(BMC, outer.netfn, REQUESTER, seq, outer.cmd, &body),
            SerialMode::Terminal => {
                let mut payload = vec![outer.netfn, seq << 2, outer.cmd];
                payload.extend_from_slice(&body);
                payload
            }
        };
        let wire = encode(self.mode, &payload);
        self.pending = Some(Pending {
            outer,
            inner,
            deadline,
        });
        let mut offset = 0;
        while offset < wire.len() {
            if self.cancelled() || Instant::now() >= deadline {
                let kind = if self.cancelled() {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::TimedOut
                };
                return Err(self.poison_send(io::Error::new(kind, "serial send outcome unknown")));
            }
            match self.port.write(&wire[offset..]) {
                Ok(0) => break,
                Ok(n) => offset += n,
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(err) => {
                    return Err(self.poison_send(err));
                }
            }
        }
        if offset != wire.len() {
            return Err(self.poison_send(io::ErrorKind::WriteZero.into()));
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        let pending = self
            .pending
            .take()
            .ok_or(SerialRecvError::NoPendingRequest)?;
        let response = (|| {
            let mut body = self.receive_matching(pending.outer, pending.deadline)?;
            let expected = if let Some(inner) = pending.inner {
                if body[0] != 0 {
                    // The Send Message completion code itself is meaningful.
                    inner
                } else if body.len() == 1 {
                    body = self.receive_matching(inner, pending.deadline)?;
                    inner
                } else if body.len() >= 10 {
                    body = parse_ipmb(&body[2..], inner).ok_or(SerialRecvError::InvalidFrame)?;
                    inner
                } else {
                    return Err(SerialRecvError::InvalidFrame);
                }
            } else {
                pending.outer
            };
            let netfn = (expected.netfn >> 2) | 1;
            Response::new(
                Message::new_raw(netfn, expected.cmd, body),
                expected.seq as i64,
            )
            .ok_or(SerialRecvError::InvalidFrame)
        })();
        if response.is_err() {
            self.uncertain = true;
        }
        response
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.send(request)?;
        self.recv().map_err(SerialError::OutcomeUnknown)
    }

    fn send_recv_deadline(
        &mut self,
        request: &mut Request,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Response, Self::Error> {
        if cancellation.is_cancelled() {
            return Err(SerialSendError::Cancelled.into());
        }
        if Instant::now() >= deadline {
            return Err(SerialError::Receive(SerialRecvError::Timeout));
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
