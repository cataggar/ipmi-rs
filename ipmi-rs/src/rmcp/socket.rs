use std::{
    io::ErrorKind,
    net::UdpSocket,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use super::{RmcpHeader, RmcpIpmiReceiveError, RmcpType};

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

/// Shared, sticky cancellation signal. Create a new token for a new operation.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Re-arm after the cancelled operation has returned.
    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone)]
pub struct TransportPolicy {
    timeout: Duration,
    pub cancellation: CancellationToken,
    pub require_rmcp_plus: bool,
}

impl TransportPolicy {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            cancellation: CancellationToken::default(),
            require_rmcp_plus: false,
        }
    }

    pub fn deadline(&self) -> Instant {
        let now = Instant::now();
        now.checked_add(self.timeout).unwrap_or(now)
    }
}

pub fn recv_datagram(
    socket: &UdpSocket,
    buffer: &mut [u8; MAX_DATAGRAM + 1],
    deadline: Instant,
    policy: &TransportPolicy,
) -> Result<usize, RecvError> {
    loop {
        if policy.cancellation.is_cancelled() {
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

        let data = header.write(data)?;
        if self.policy.cancellation.is_cancelled() {
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
