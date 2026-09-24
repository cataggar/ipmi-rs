//! SOL session lifecycle. A capture cannot send console characters or controls.

use std::time::{Duration, Instant};

use ipmi_rs_core::app::sol::{
    ActivateSol, DeactivateSol, SolActivation, SolInstance, SolPayloadError,
};

use crate::{Ipmi, IpmiError};

use super::{
    internal::Active, v2_0::State, ActivationError, Rmcp, RmcpIpmiError, RmcpIpmiReceiveError,
    RmcpIpmiSendError, SolFlags, SolFrame,
};

const CLEANUP_WAIT: Duration = Duration::from_millis(250);
const RETRY_WAIT: Duration = Duration::from_millis(150);
const MAX_RETRANSMISSIONS: usize = 2;
const MAX_INPUT_CALL: usize = 4096;

/// Why a SOL stream was interrupted. None of these variants contains console data.
#[derive(Debug)]
pub enum SolInterruptionReason {
    /// A receive failed, including timeout, cancellation, lost or reordered output.
    Receive(RmcpIpmiReceiveError),
    /// A send failed; it may have reached the BMC.
    Send(RmcpIpmiError),
    /// A remote NACK or transfer-unavailable flag.
    RemoteNack,
    /// Too many partial acknowledgments without progress.
    NoProgress,
    /// Deactivation was not acknowledged.
    Deactivation,
    /// Reauthentication or reactivation failed.
    Reconnect,
}

/// The known and unknown outcomes of an interrupted SOL operation.
#[derive(Debug)]
pub struct SolInterruption {
    /// Reason this session stopped.
    pub reason: SolInterruptionReason,
    /// Number of console-input characters explicitly acknowledged in this call.
    pub confirmed_input: usize,
    /// Input might have arrived without an ACK; never automatically replay it on reconnect.
    pub input_delivery_uncertain: bool,
    /// Console output may have been lost. All reconnects introduce a gap.
    pub output_delivery_uncertain: bool,
    /// A successful remote Deactivate Payload could not be confirmed.
    pub remote_close_unconfirmed: bool,
}

/// An error opening, operating, or closing SOL.
#[derive(Debug)]
pub enum SolError {
    /// No active RMCP+ session; IPMI 1.5 is not permitted for SOL.
    RmcpPlusRequired,
    /// Bad limit, instance, or operation on an already stopped session.
    InvalidOperation,
    /// Activate Payload failed.
    Activation(IpmiError<RmcpIpmiError, SolPayloadError>),
    /// Activation may have succeeded; cleanup was attempted, but the remote
    /// deactivation outcome must be checked before reusing the instance.
    ActivationUncertain {
        /// The activation failure.
        source: IpmiError<RmcpIpmiError, SolPayloadError>,
        /// Deactivate Payload also failed or was not acknowledged.
        remote_close_unconfirmed: bool,
    },
    /// Routing to the negotiated UDP port or VLAN is unsupported.
    UnsupportedRoute {
        /// Negotiated UDP port.
        port: u16,
        /// Negotiated VLAN.
        vlan: u16,
        /// Deactivation also failed, so the remote payload may still be active.
        remote_close_unconfirmed: bool,
    },
    /// Operation stopped; examine uncertain outcomes before retrying.
    Interrupted(SolInterruption),
}

/// Explicit evidence of a discontinuity after reconnection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureGap {
    /// Remote output during reauthentication may have been lost.
    pub output_missing: bool,
    /// The prior remote payload's deactivation was not confirmed.
    pub previous_remote_close_unconfirmed: bool,
    /// Number of attempted *fresh* RMCP+ session handshakes.
    pub attempts: u8,
}

/// A read-only SOL session. Protocol ACKs are sent, never console input or
/// control characters. Closing this handle consumes it and deactivates SOL.
pub struct SolCapture<'a>(SolSession<'a>);

/// An explicitly interactive SOL session with bounded console input and
/// separate, explicitly invoked serial controls.
pub struct SolInteractive<'a>(SolSession<'a>);

struct SolSession<'a> {
    connection: &'a mut Rmcp,
    instance: SolInstance,
    active: bool,
    remote_close_unconfirmed: bool,
}

fn state(connection: &mut Rmcp) -> Result<&mut State, SolError> {
    match connection
        .active_state
        .as_mut()
        .map(|active| active.state_mut())
    {
        Some(Active::V2_0(state)) => Ok(state),
        _ => Err(SolError::RmcpPlusRequired),
    }
}

fn deactivate_bounded(
    connection: &mut Rmcp,
    instance: SolInstance,
) -> Result<(), IpmiError<RmcpIpmiError, SolPayloadError>> {
    let old_policy = match state(connection) {
        Ok(state) => state.socket.begin_cleanup(CLEANUP_WAIT),
        Err(_) => return Err(IpmiError::Connection(RmcpIpmiError::NotActive)),
    };
    let result = Ipmi::new(&mut *connection).send_recv(DeactivateSol { instance });
    if let Ok(state) = state(connection) {
        state.socket.end_cleanup(old_policy);
        state.sol_close();
    }
    result
}

impl Rmcp {
    fn activate_sol(&mut self, instance: SolInstance) -> Result<(), SolError> {
        let active = state(self)?;
        active.sol_open();
        let activated = Ipmi::new(&mut *self).send_recv(ActivateSol { instance });
        let SolActivation {
            max_input,
            max_output,
            port,
            vlan,
            ..
        } = match activated {
            Ok(value) => value,
            Err(error) => {
                // A response declaring another session's payload active is not
                // ours to deactivate. A lost/malformed response is uncertain.
                let possibly_activated = !matches!(
                    &error,
                    IpmiError::Command {
                        error: SolPayloadError::AlreadyActive
                            | SolPayloadError::Disabled
                            | SolPayloadError::LimitReached
                            | SolPayloadError::EncryptionUnavailable
                            | SolPayloadError::EncryptionRequired,
                        ..
                    } | IpmiError::Failed { .. }
                        | IpmiError::Connection(
                            RmcpIpmiError::NotActive
                                | RmcpIpmiError::Send(
                                    RmcpIpmiSendError::Cancelled
                                        | RmcpIpmiSendError::DeadlineExpired
                                        | RmcpIpmiSendError::RequestPending
                                        | RmcpIpmiSendError::IpmbSequenceExhausted
                                        | RmcpIpmiSendError::SessionSequenceExhausted
                                        | RmcpIpmiSendError::UnsupportedTarget
                                        | RmcpIpmiSendError::InvalidNetfn(_)
                                )
                        )
                );
                if possibly_activated {
                    let remote_close_unconfirmed = deactivate_bounded(self, instance).is_err();
                    return Err(SolError::ActivationUncertain {
                        source: error,
                        remote_close_unconfirmed,
                    });
                } else {
                    state(self)?.sol_close();
                }
                return Err(SolError::Activation(error));
            }
        };
        let address = self.unbound_state.address();
        if port != address.port() || vlan != 0 {
            let remote_close_unconfirmed = deactivate_bounded(self, instance).is_err();
            return Err(SolError::UnsupportedRoute {
                port,
                vlan,
                remote_close_unconfirmed,
            });
        }
        state(self)?.sol_limits(max_input, max_output);
        Ok(())
    }

    /// Activate an already authenticated RMCP+ connection for read-only SOL.
    /// Never changes SOL configuration or user access.
    pub fn open_sol_capture(&mut self, instance: SolInstance) -> Result<SolCapture<'_>, SolError> {
        self.activate_sol(instance)?;
        Ok(SolCapture(SolSession {
            connection: self,
            instance,
            active: true,
            remote_close_unconfirmed: false,
        }))
    }

    /// Activate an already authenticated RMCP+ connection for explicit input.
    pub fn open_sol_interactive(
        &mut self,
        instance: SolInstance,
    ) -> Result<SolInteractive<'_>, SolError> {
        self.activate_sol(instance)?;
        Ok(SolInteractive(SolSession {
            connection: self,
            instance,
            active: true,
            remote_close_unconfirmed: false,
        }))
    }
}

impl SolSession<'_> {
    fn interrupted(
        &mut self,
        reason: SolInterruptionReason,
        confirmed_input: usize,
        input_delivery_uncertain: bool,
    ) -> SolError {
        let remote_close_unconfirmed = if self.active {
            self.active = false;
            deactivate_bounded(self.connection, self.instance).is_err()
        } else {
            true
        };
        self.remote_close_unconfirmed = remote_close_unconfirmed;
        SolError::Interrupted(SolInterruption {
            reason,
            confirmed_input,
            input_delivery_uncertain,
            output_delivery_uncertain: true,
            remote_close_unconfirmed,
        })
    }

    fn read_until(&mut self, output: &mut [u8], deadline: Instant) -> Result<usize, SolError> {
        if !self.active {
            return Err(SolError::InvalidOperation);
        }
        if self.connection.cancellation_token().is_cancelled() {
            return Err(self.interrupted(
                SolInterruptionReason::Receive(RmcpIpmiReceiveError::Cancelled),
                0,
                false,
            ));
        }
        if output.is_empty() {
            return Ok(0);
        }
        let active = state(self.connection)?;
        let count = active.sol_flow().read(output);
        if count > 0 {
            return Ok(count);
        }
        let deadline = deadline.min(active.socket.deadline());
        match active.poll_sol(deadline, false) {
            Ok(()) => Ok(active.sol_flow().read(output)),
            Err(err) => Err(self.interrupted(SolInterruptionReason::Receive(err), 0, false)),
        }
    }

    fn close_inner(&mut self) -> Result<(), SolError> {
        if !self.active {
            return if self.remote_close_unconfirmed {
                Err(SolError::Interrupted(SolInterruption {
                    reason: SolInterruptionReason::Deactivation,
                    confirmed_input: 0,
                    input_delivery_uncertain: false,
                    output_delivery_uncertain: true,
                    remote_close_unconfirmed: true,
                }))
            } else {
                Ok(())
            };
        }
        self.active = false;
        self.remote_close_unconfirmed = deactivate_bounded(self.connection, self.instance).is_err();
        if self.remote_close_unconfirmed {
            return Err(SolError::Interrupted(SolInterruption {
                reason: SolInterruptionReason::Deactivation,
                confirmed_input: 0,
                input_delivery_uncertain: false,
                output_delivery_uncertain: true,
                remote_close_unconfirmed: true,
            }));
        }
        Ok(())
    }
}

impl Drop for SolSession<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.close_inner();
        }
    }
}

impl SolCapture<'_> {
    /// Read console output using the RMCP transport's bounded operation timeout.
    /// A timeout or cancellation ends the capture with an explicit interruption.
    pub fn read(&mut self, output: &mut [u8]) -> Result<usize, SolError> {
        let deadline = state(self.0.connection)?.socket.deadline();
        self.0.read_until(output, deadline)
    }

    /// Read until the earlier of this deadline and the RMCP operation timeout.
    pub fn read_until(&mut self, output: &mut [u8], deadline: Instant) -> Result<usize, SolError> {
        self.0.read_until(output, deadline)
    }

    /// Explicitly deactivate SOL. Check the result rather than relying on Drop.
    pub fn close(mut self) -> Result<(), SolError> {
        self.0.close_inner()
    }

    /// Retry with at most three fresh authenticated RMCP+ sessions, returning
    /// an explicit capture gap. A live capture is first deactivated. The
    /// cancellation token must be reset explicitly before reconnecting.
    pub fn reconnect(
        &mut self,
        username: &str,
        password: &[u8],
        max_attempts: u8,
    ) -> Result<CaptureGap, SolError> {
        if !(1..=3).contains(&max_attempts) {
            return Err(SolError::InvalidOperation);
        }
        let previous_remote_close_unconfirmed = if self.0.active {
            self.0.close_inner().is_err()
        } else {
            self.0.remote_close_unconfirmed
        };
        if self.0.connection.cancellation_token().is_cancelled() {
            return Err(SolError::Interrupted(SolInterruption {
                reason: SolInterruptionReason::Reconnect,
                confirmed_input: 0,
                input_delivery_uncertain: false,
                output_delivery_uncertain: true,
                remote_close_unconfirmed: previous_remote_close_unconfirmed,
            }));
        }
        self.0.connection.require_rmcp_plus(true);
        let mut remote_close_unconfirmed = previous_remote_close_unconfirmed;
        for attempts in 1..=max_attempts {
            let activated = self
                .0
                .connection
                .activate(true, Some(username), Some(password));
            if activated.is_ok() {
                match self.0.connection.activate_sol(self.0.instance) {
                    Ok(()) => {
                        self.0.active = true;
                        return Ok(CaptureGap {
                            output_missing: true,
                            previous_remote_close_unconfirmed: remote_close_unconfirmed,
                            attempts,
                        });
                    }
                    Err(
                        SolError::ActivationUncertain {
                            remote_close_unconfirmed: unconfirmed,
                            ..
                        }
                        | SolError::UnsupportedRoute {
                            remote_close_unconfirmed: unconfirmed,
                            ..
                        },
                    ) => remote_close_unconfirmed |= unconfirmed,
                    Err(_) => {}
                }
            }
            if matches!(
                activated,
                Err(ActivationError::PongReceive(
                    RmcpIpmiReceiveError::Cancelled
                ))
            ) {
                break;
            }
        }
        Err(SolError::Interrupted(SolInterruption {
            reason: SolInterruptionReason::Reconnect,
            confirmed_input: 0,
            input_delivery_uncertain: false,
            output_delivery_uncertain: true,
            remote_close_unconfirmed,
        }))
    }
}

impl SolInteractive<'_> {
    /// Read output without implicitly sending console input.
    pub fn read(&mut self, output: &mut [u8]) -> Result<usize, SolError> {
        let deadline = state(self.0.connection)?.socket.deadline();
        self.0.read_until(output, deadline)
    }

    /// Read output until the earlier of this deadline and the RMCP timeout.
    pub fn read_until(&mut self, output: &mut [u8], deadline: Instant) -> Result<usize, SolError> {
        self.0.read_until(output, deadline)
    }

    /// Send at most 4096 explicit console-input bytes, in negotiated-size
    /// packets. A missing ACK is retransmitted only in this same session with
    /// its original SOL sequence; uncertain input is never replayed on reconnect.
    pub fn send_input(&mut self, input: &[u8]) -> Result<usize, SolError> {
        if input.len() > MAX_INPUT_CALL {
            return Err(SolError::InvalidOperation);
        }
        if !self.0.active {
            return Err(SolError::InvalidOperation);
        }
        if self.0.connection.cancellation_token().is_cancelled() {
            return Err(self.0.interrupted(
                SolInterruptionReason::Receive(RmcpIpmiReceiveError::Cancelled),
                0,
                false,
            ));
        }
        let active = state(self.0.connection)?;
        let chunk_size = active.sol_flow().max_input.saturating_sub(4);
        if chunk_size == 0 {
            return Err(SolError::InvalidOperation);
        }
        let deadline = active.socket.deadline();
        let mut confirmed = 0;
        for chunk in input.chunks(chunk_size) {
            let mut remaining = chunk;
            let mut partials = 0;
            while !remaining.is_empty() {
                let seq = state(self.0.connection)?.sol_flow().next_sequence();
                let frame = SolFrame {
                    sequence: seq,
                    ack: 0,
                    accepted: 0,
                    flags: SolFlags::default(),
                    data: remaining.to_vec(),
                };
                let ack = self.transmit(frame, deadline, confirmed)?;
                if ack.accepted as usize > remaining.len() {
                    return Err(self.0.interrupted(
                        SolInterruptionReason::Receive(RmcpIpmiReceiveError::Sol(
                            super::SolFrameError::InvalidAck,
                        )),
                        confirmed,
                        true,
                    ));
                }
                confirmed += ack.accepted as usize;
                remaining = &remaining[ack.accepted as usize..];
                if ack.unavailable {
                    return Err(self.0.interrupted(
                        SolInterruptionReason::RemoteNack,
                        confirmed,
                        !remaining.is_empty(),
                    ));
                }
                partials += 1;
                if partials > MAX_RETRANSMISSIONS + 1 && !remaining.is_empty() {
                    return Err(self.0.interrupted(
                        if ack.nack {
                            SolInterruptionReason::RemoteNack
                        } else {
                            SolInterruptionReason::NoProgress
                        },
                        confirmed,
                        true,
                    ));
                }
            }
        }
        Ok(confirmed)
    }

    fn transmit(
        &mut self,
        frame: SolFrame,
        deadline: Instant,
        confirmed: usize,
    ) -> Result<super::v2_0::sol::InputAck, SolError> {
        let active = state(self.0.connection)?;
        active.sol_flow().waiting_for_ack = Some(frame.sequence);
        active.sol_flow().input_ack = None;
        for attempt in 0..=MAX_RETRANSMISSIONS {
            if let Err(error) = state(self.0.connection)?.send_sol_frame(&frame, deadline) {
                let uncertain = attempt != 0
                    || !matches!(
                        &error,
                        RmcpIpmiError::Send(
                            RmcpIpmiSendError::Cancelled | RmcpIpmiSendError::DeadlineExpired
                        )
                    );
                return Err(self.0.interrupted(
                    SolInterruptionReason::Send(error),
                    confirmed,
                    uncertain,
                ));
            }
            let wait_until = deadline.min(Instant::now() + RETRY_WAIT);
            match state(self.0.connection)?.poll_sol(wait_until, true) {
                Ok(()) => {
                    let active = state(self.0.connection)?;
                    active.sol_flow().waiting_for_ack = None;
                    return Ok(active
                        .sol_flow()
                        .input_ack
                        .take()
                        .expect("ACK was observed"));
                }
                Err(RmcpIpmiReceiveError::Timeout)
                    if attempt < MAX_RETRANSMISSIONS && Instant::now() < deadline => {}
                Err(error) => {
                    return Err(self.0.interrupted(
                        SolInterruptionReason::Receive(error),
                        confirmed,
                        true,
                    ));
                }
            }
        }
        Err(self
            .0
            .interrupted(SolInterruptionReason::NoProgress, confirmed, true))
    }

    fn send_control(&mut self, flags: SolFlags) -> Result<(), SolError> {
        if !self.0.active {
            return Err(SolError::InvalidOperation);
        }
        let active = state(self.0.connection)?;
        let deadline = active.socket.deadline();
        let sequence = active.sol_flow().next_sequence();
        let ack = self.transmit(
            SolFrame {
                sequence,
                ack: 0,
                accepted: 0,
                flags,
                data: Vec::new(),
            },
            deadline,
            0,
        )?;
        if ack.nack || ack.unavailable || ack.accepted != 0 {
            return Err(self
                .0
                .interrupted(SolInterruptionReason::RemoteNack, 0, true));
        }
        Ok(())
    }

    /// Send an explicit serial break.
    pub fn send_break(&mut self) -> Result<(), SolError> {
        self.send_control(SolFlags {
            generate_break: true,
            ..SolFlags::default()
        })
    }

    /// Explicitly flush buffered BMC-to-console serial output.
    pub fn flush_inbound(&mut self) -> Result<(), SolError> {
        self.send_control(SolFlags {
            flush_inbound: true,
            ..SolFlags::default()
        })
    }

    /// Explicitly flush buffered console-to-BMC serial input.
    pub fn flush_outbound(&mut self) -> Result<(), SolError> {
        self.send_control(SolFlags {
            flush_outbound: true,
            ..SolFlags::default()
        })
    }

    /// Deactivate the remote SOL payload.
    pub fn close(mut self) -> Result<(), SolError> {
        self.0.close_inner()
    }
}
