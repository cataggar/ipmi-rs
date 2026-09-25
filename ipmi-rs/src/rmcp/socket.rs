use std::{
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

use super::{RmcpHeader, RmcpIpmiReceiveError, RmcpType};
pub use crate::connection::CancellationToken;

type RecvError = RmcpIpmiReceiveError;

pub const MAX_DATAGRAM: usize = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(50);
pub(crate) const MAX_UNRELATED: usize = 32;

pub(crate) fn count_unrelated(unrelated: &mut usize) -> Result<(), RecvError> {
    *unrelated += 1;
    if *unrelated >= MAX_UNRELATED {
        Err(RecvError::TooManyUnrelatedPackets)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TransportPolicy {
    timeout: Duration,
    pub cancellation: CancellationToken,
    pub require_rmcp_plus: bool,
    operation_cancellation: Option<CancellationToken>,
}

impl TransportPolicy {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            cancellation: CancellationToken::default(),
            require_rmcp_plus: false,
            operation_cancellation: None,
        }
    }

    pub fn deadline(&self) -> Instant {
        let now = Instant::now();
        now.checked_add(self.timeout).unwrap_or(now)
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
            || self
                .operation_cancellation
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
    }
}

pub fn recv_datagram(
    socket: &UdpSocket,
    buffer: &mut [u8; MAX_DATAGRAM + 1],
    deadline: Instant,
    policy: &TransportPolicy,
) -> Result<usize, RecvError> {
    loop {
        if policy.is_cancelled() {
            return Err(RecvError::Cancelled);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(RecvError::Timeout)?;
        if remaining.is_zero() {
            return Err(RecvError::Timeout);
        }
        socket
            .set_read_timeout(Some(remaining.min(POLL_INTERVAL)))
            .map_err(RecvError::Io)?;
        match socket.recv(buffer) {
            Ok(n) if n > MAX_DATAGRAM => return Err(RecvError::DatagramTooLarge),
            Ok(n) => return Ok(n),
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(RecvError::Io(e)),
        }
    }
}

#[derive(Debug)]
pub struct RmcpIpmiSocket {
    socket: UdpSocket,
    buffer: Box<[u8; MAX_DATAGRAM + 1]>,
    policy: TransportPolicy,
    activation_deadline: Option<Instant>,
}

impl RmcpIpmiSocket {
    pub(crate) fn begin_bounded(
        &mut self,
        deadline: Instant,
        cancellation: CancellationToken,
    ) -> (Option<Instant>, Option<CancellationToken>) {
        let bounded = deadline.min(self.policy.deadline());
        let bounded = self
            .activation_deadline
            .map_or(bounded, |previous| previous.min(bounded));
        let old_deadline = self.activation_deadline.replace(bounded);
        let old_cancellation = self.policy.operation_cancellation.replace(cancellation);
        (old_deadline, old_cancellation)
    }

    pub(crate) fn end_bounded(&mut self, previous: (Option<Instant>, Option<CancellationToken>)) {
        self.activation_deadline = previous.0;
        self.policy.operation_cancellation = previous.1;
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.peer_addr()
    }

    pub fn new(
        socket: UdpSocket,
        policy: TransportPolicy,
        activation_deadline: Option<Instant>,
    ) -> Self {
        Self {
            socket,
            buffer: Box::new([0u8; MAX_DATAGRAM + 1]),
            policy,
            activation_deadline,
        }
    }

    pub fn clear_activation_deadline(&mut self) {
        self.activation_deadline = None;
    }

    pub fn require_rmcp_plus(&self) -> bool {
        self.policy.require_rmcp_plus
    }

    pub fn deadline(&self) -> Instant {
        self.activation_deadline
            .unwrap_or_else(|| self.policy.deadline())
    }

    /// Bound an IPMI transaction by its caller's absolute operation deadline.
    pub(crate) fn limit_deadline(&mut self, deadline: Instant) -> Option<Instant> {
        self.activation_deadline
            .replace(self.deadline().min(deadline))
    }

    pub(crate) fn restore_deadline(&mut self, previous: Option<Instant>) {
        self.activation_deadline = previous;
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.policy.cancellation.clone()
    }

    /// Allow one bounded deactivation attempt even when the operation's token
    /// was cancelled. Restore the original token before returning to callers.
    pub(crate) fn begin_cleanup(
        &mut self,
        max_wait: Duration,
    ) -> (CancellationToken, Option<Instant>) {
        let token = std::mem::take(&mut self.policy.cancellation);
        let previous_deadline = self.activation_deadline.replace(Instant::now() + max_wait);
        (token, previous_deadline)
    }

    pub(crate) fn end_cleanup(&mut self, previous: (CancellationToken, Option<Instant>)) {
        self.policy.cancellation = previous.0;
        self.activation_deadline = previous.1;
    }

    pub fn recv(&mut self) -> Result<&mut [u8], RmcpIpmiReceiveError> {
        self.recv_until(self.deadline())
    }

    pub fn recv_until(&mut self, deadline: Instant) -> Result<&mut [u8], RmcpIpmiReceiveError> {
        let mut unrelated = 0;
        self.recv_until_with_budget(deadline, &mut unrelated)
    }

    pub fn recv_until_with_budget(
        &mut self,
        deadline: Instant,
        unrelated: &mut usize,
    ) -> Result<&mut [u8], RmcpIpmiReceiveError> {
        loop {
            let received = recv_datagram(&self.socket, &mut self.buffer, deadline, &self.policy)?;

            let is_ipmi = {
                let (header, _) = RmcpHeader::from_bytes(&mut self.buffer[..received])
                    .map_err(RecvError::RmcpHeader)?;
                header.class().ty == RmcpType::Ipmi && !header.class().is_ack
            };
            if is_ipmi {
                return Ok(&mut self.buffer[4..received]);
            }
            count_unrelated(unrelated)?;
        }
    }

    pub fn send<F, E>(&mut self, deadline: Instant, data: F) -> Result<(), E>
    where
        F: FnMut(&mut Vec<u8>) -> Result<(), E>,
        E: From<std::io::Error>,
    {
        let header = RmcpHeader::new_ipmi();

        let data = Zeroizing::new(header.write(data)?);
        if self.policy.is_cancelled() {
            return Err(std::io::Error::new(ErrorKind::Interrupted, "RMCP send cancelled").into());
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(ErrorKind::TimedOut, "RMCP send deadline expired")
            })?;
        self.socket
            .set_write_timeout(Some(remaining.min(POLL_INTERVAL)))
            .map_err(E::from)?;
        let written = self.socket.send(&data).map_err(E::from)?;
        if written != data.len() {
            return Err(
                std::io::Error::new(ErrorKind::WriteZero, "short RMCP datagram send").into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
