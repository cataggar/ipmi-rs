// LE = least significant byte first = IPMI
// BE = most significant byte first = RMCP/ASF

use std::{
    io::ErrorKind,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    time::{Duration, Instant},
};

use crate::{
    app::auth::{CipherSuite, GetChannelAuthenticationCapabilities, GetChannelCipherSuites},
    connection::{
        Address, Channel, IpmbTarget, IpmiConnection, LogicalUnit, Request, RequestTargetAddress,
        Response,
    },
};

use super::{
    checksum::Checksum,
    socket::{count_unrelated, recv_datagram, TransportPolicy},
    v1_5::State as V1_5State,
    v2_0::State as V2_0State,
    ASFMessage, ASFMessageType, ActivationError, CipherSuiteListError, CipherSuitePolicy,
    RmcpHeader, RmcpIpmiError, RmcpIpmiReceiveError, RmcpIpmiSendError, RmcpType, SessionConfig,
};

#[derive(Debug, Clone, Copy)]
struct ExpectedReply {
    sequence: u8,
    netfn: u8,
    cmd: u8,
    responder_addr: u8,
    responder_lun: LogicalUnit,
    requestor_addr: u8,
    requestor_lun: LogicalUnit,
}

#[derive(Debug, Clone)]
pub struct PendingRequest {
    final_reply: ExpectedReply,
    send_acks: [Option<ExpectedReply>; 2],
    acked: [bool; 2],
    poll: Option<ExpectedReply>,
    deferred: Option<Response>,
    queue_channel: u8,
    queue_available: bool,
    pub deadline: Instant,
}

#[derive(Debug, Clone)]
pub struct IpmbState {
    pub ipmb_sequence: u8,
    pub responder_addr: u8,
    pub requestor_addr: u8,
    pub requestor_lun: LogicalUnit,
    pub pending: Option<PendingRequest>,
    // Never reuse a sequence within this session: late IPMB replies can arrive
    // after a request has timed out, even if a different request is pending.
    retired_sequences: [bool; 64],
    get_message_supported: bool,
}

impl Default for IpmbState {
    fn default() -> Self {
        Self {
            responder_addr: 0x20,
            requestor_addr: 0x81,
            requestor_lun: LogicalUnit::Zero,
            ipmb_sequence: 0,
            pending: None,
            retired_sequences: [false; 64],
            get_message_supported: true,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct Unbound {
    address: SocketAddr,
    policy: TransportPolicy,
}

#[derive(Debug)]
pub struct Inactive {
    socket: UdpSocket,
    policy: TransportPolicy,
}

#[derive(Debug)]
pub enum Active {
    V1_5(V1_5State),
    V2_0(V2_0State),
}

#[derive(Debug, Clone)]
pub(super) struct RmcpWithState<T>(T);

impl RmcpWithState<Active> {
    pub(super) fn is_rmcp_plus(&self) -> bool {
        matches!(self.state(), Active::V2_0(_))
    }
}

impl Active {
    pub(super) fn socket_mut(&mut self) -> &mut super::socket::RmcpIpmiSocket {
        match self {
            Active::V1_5(state) => state.socket_mut(),
            Active::V2_0(state) => &mut state.socket,
        }
    }
}

impl<T> RmcpWithState<T> {
    fn state(&self) -> &T {
        &self.0
    }

    pub(super) fn state_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

#[cfg(test)]
impl RmcpWithState<Active> {
    pub(super) fn from_active(state: Active) -> Self {
        Self(state)
    }
}

impl RmcpWithState<Unbound> {
    pub(super) fn address(&self) -> SocketAddr {
        self.0.address
    }

    pub fn new<R: ToSocketAddrs + core::fmt::Debug>(
        remote: R,
        timeout: Duration,
    ) -> std::io::Result<Self> {
        let address = remote.to_socket_addrs()?.next().ok_or_else(|| {
            std::io::Error::new(
                ErrorKind::NotFound,
                format!("Could not resolve any addresses for {remote:?}"),
            )
        })?;

        Ok(Self(Unbound {
            address,
            policy: TransportPolicy::new(timeout),
        }))
    }

    pub fn bind(&self) -> Result<RmcpWithState<Inactive>, std::io::Error> {
        let addr = &self.state().address;

        log::debug!("Binding socket...");
        let socket = UdpSocket::bind("[::]:0")?;
        socket.set_write_timeout(Some(
            self.state()
                .policy
                .deadline()
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250))
                .max(Duration::from_millis(1)),
        ))?;
        log::debug!("Opening connection to {:?}", addr);
        socket.connect(addr)?;

        Ok(RmcpWithState(Inactive {
            socket,
            policy: self.state().policy.clone(),
        }))
    }

    pub fn policy(&self) -> &TransportPolicy {
        &self.0.policy
    }

    pub fn policy_mut(&mut self) -> &mut TransportPolicy {
        &mut self.0.policy
    }
}

impl RmcpWithState<Inactive> {
    pub fn activate(
        self,
        rmcp_plus: bool,
        suite_policy: Option<CipherSuitePolicy>,
        config: SessionConfig<'_>,
    ) -> Result<RmcpWithState<Active>, ActivationError> {
        let SessionConfig {
            username,
            password,
            kg,
            privilege: privilege_level,
            provider,
            ..
        } = config;
        let message_tag = 0xC8;

        let ping_header = RmcpHeader::new_asf(0xFF);

        let ping = ASFMessage {
            message_tag,
            message_type: ASFMessageType::Ping,
        };

        log::debug!("Starting RMCP activation sequence");

        let Inactive { socket, policy } = self.0;
        let deadline = policy.deadline();
        if policy.cancellation.is_cancelled() {
            return Err(ActivationError::PongReceive(
                RmcpIpmiReceiveError::Cancelled,
            ));
        }

        // NOTE(unwrap): This cannot fail.
        let ping_bytes = ping_header.write_infallible(|buffer| {
            ping.write_data(buffer);
        });

        socket
            .send(&ping_bytes)
            .map_err(ActivationError::PingSend)?;

        let mut buf = [0u8; super::socket::MAX_DATAGRAM + 1];
        let received = recv_datagram(&socket, &mut buf, deadline, &policy)
            .map_err(ActivationError::PongReceive)?;

        let (pong_header, pong_data) =
            RmcpHeader::from_bytes(&mut buf[..received]).map_err(|_| ActivationError::PongRead)?;

        let (supported_entities, _) = if pong_header.class().ty == RmcpType::Asf {
            let message = ASFMessage::from_bytes(pong_data).ok_or(ActivationError::PongRead)?;

            if message.message_tag != message_tag {
                return Err(ActivationError::PongRead);
            }

            if let ASFMessageType::Pong {
                supported_entities,
                supported_interactions,
                ..
            } = message.message_type
            {
                (supported_entities, supported_interactions)
            } else {
                return Err(ActivationError::PongRead);
            }
        } else {
            return Err(ActivationError::PongRead);
        };

        if !supported_entities.ipmi {
            return Err(ActivationError::IpmiNotSupported);
        }

        let new_state = V1_5State::new(socket, policy, Some(deadline));

        let mut ipmi = crate::Ipmi::new(new_state);

        log::debug!("Obtaining channel authentication capabilities");

        let authentication_caps = match ipmi.send_recv(GetChannelAuthenticationCapabilities::new(
            Channel::Current,
            privilege_level,
        )) {
            Ok(v) => v,
            Err(e) => return Err(ActivationError::GetChannelAuthenticationCapabilities(e)),
        };

        log::debug!("Authentication capabilities: {:?}", authentication_caps);

        if authentication_caps.ipmi2_connections_supported && rmcp_plus {
            let suite = match suite_policy {
                Some(CipherSuitePolicy::Exact(suite)) => suite,
                Some(CipherSuitePolicy::BestAvailable) => {
                    let mut records = Vec::new();
                    for index in 0..64 {
                        let block = ipmi
                            .send_recv(
                                GetChannelCipherSuites::new(Channel::Current, index)
                                    .expect("index is within the protocol limit"),
                            )
                            .map_err(ActivationError::GetChannelCipherSuites)?;
                        let last_page = block.len() < 16;
                        records.extend_from_slice(&block);
                        if last_page {
                            break;
                        }
                        if index == 63 {
                            return Err(ActivationError::InvalidCipherSuiteList(
                                CipherSuiteListError::IncompleteList,
                            ));
                        }
                    }
                    super::cipher_policy::select_best(&records)
                        .map_err(ActivationError::InvalidCipherSuiteList)?
                        .ok_or(ActivationError::NoSupportedCipherSuite)?
                }
                None => CipherSuite::Id3,
            };
            let username = username.unwrap_or("");
            if username.len() > 16 {
                return Err(ActivationError::InvalidUsername);
            }
            let username =
                super::v2_0::Username::new(username).ok_or(ActivationError::InvalidUsername)?;

            let socket = ipmi.release();

            let res = V2_0State::activate(
                socket,
                Some(privilege_level),
                &username,
                password.unwrap_or(&[]),
                kg,
                suite,
                provider,
            )?;

            Ok(RmcpWithState(Active::V2_0(res)))
        } else if suite_policy.is_some() {
            Err(ActivationError::RequiredRmcpPlusNotSupported)
        } else if authentication_caps.ipmi15_connections_supported {
            if rmcp_plus && ipmi.inner_mut().require_rmcp_plus() {
                return Err(ActivationError::RmcpPlusRequired);
            }
            let activated = ipmi.release().activate(
                &authentication_caps,
                privilege_level,
                username,
                password,
            )?;

            Ok(RmcpWithState(Active::V1_5(activated)))
        } else {
            Err(ActivationError::NoSupportedIpmiLANVersions)
        }
    }
}

impl IpmiConnection for RmcpWithState<Active> {
    type SendError = RmcpIpmiError;

    type RecvError = RmcpIpmiReceiveError;

    type Error = RmcpIpmiError;

    fn send(&mut self, request: &mut crate::connection::Request) -> Result<(), Self::SendError> {
        match self.state_mut() {
            Active::V1_5(state) => state
                .send(request)
                .map_err(RmcpIpmiSendError::into_operation_error)?,
            Active::V2_0(state) => state.send(request)?,
        }

        Ok(())
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        match self.state_mut() {
            Active::V1_5(state) => state.recv(),
            Active::V2_0(state) => state.recv(),
        }
    }

    fn send_recv(
        &mut self,
        request: &mut crate::connection::Request,
    ) -> Result<Response, Self::Error> {
        match self.state_mut() {
            Active::V1_5(state) => state.send_recv(request),
            Active::V2_0(state) => state.send_recv(request),
        }
    }
}

pub fn validate_ipmb_checksums(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }

    let first_checksum = Checksum::from_iter([data[0], data[1]]);

    if first_checksum != data[2] {
        return false;
    }

    let second_checksum = Checksum::from_iter(data[3..data.len() - 1].iter().copied());

    second_checksum == data[data.len() - 1]
}

pub(super) fn record_unrelated(
    error: RmcpIpmiReceiveError,
    first_mismatch: &mut Option<RmcpIpmiReceiveError>,
    unrelated: &mut usize,
) -> Result<(), RmcpIpmiReceiveError> {
    if first_mismatch.is_none() {
        *first_mismatch = Some(error);
    }
    count_unrelated(unrelated)
}

const APP_NETFN: u8 = 6;
const SEND_MESSAGE: u8 = 0x34;
const GET_MESSAGE: u8 = 0x33;
const GET_MESSAGE_FLAGS: u8 = 0x31;
const TRACK_REQUEST: u8 = 0x40;

fn ipmb_request(expected: ExpectedReply, data: &[u8]) -> Vec<u8> {
    let first = [
        expected.responder_addr,
        ((expected.netfn - 1) << 2) | expected.responder_lun.value(),
    ];
    let second = [
        expected.requestor_addr,
        (expected.sequence << 2) | expected.requestor_lun.value(),
        expected.cmd,
    ];
    let mut result = Vec::with_capacity(7 + data.len());
    result.extend_from_slice(&first);
    result.push(Checksum::from_iter(first));
    result.extend_from_slice(&second);
    result.extend_from_slice(data);
    result.push(Checksum::from_iter(
        second.into_iter().chain(data.iter().copied()),
    ));
    result
}

fn valid_hop(hop: IpmbTarget) -> bool {
    hop.address.0 >= 2
        && hop.address.0 & 1 == 0
        && matches!(hop.channel, Channel::Primary | Channel::Numbered(_))
}

fn correlate(data: &[u8], expected: ExpectedReply) -> Result<Response, RmcpIpmiReceiveError> {
    if data.len() < 8 {
        return Err(RmcpIpmiReceiveError::NotEnoughData);
    }
    if !validate_ipmb_checksums(data) {
        return Err(RmcpIpmiReceiveError::IpmbChecksumFailed);
    }
    if data[0] != expected.requestor_addr
        || data[1] & 3 != expected.requestor_lun.value()
        || data[3] != expected.responder_addr
        || data[4] & 3 != expected.responder_lun.value()
        || data[4] >> 2 != expected.sequence
        || data[1] >> 2 != expected.netfn
        || data[5] != expected.cmd
    {
        return Err(RmcpIpmiReceiveError::IpmbResponseMismatch);
    }
    Response::new(
        crate::connection::Message::new_raw(
            data[1] >> 2,
            data[5],
            data[6..data.len() - 1].to_vec(),
        ),
        i64::from(expected.sequence),
    )
    .ok_or(RmcpIpmiReceiveError::EmptyMessage)
}

impl IpmbState {
    pub fn retire_pending(&mut self) {
        self.pending = None;
    }

    fn next_reply(
        &mut self,
        netfn: u8,
        cmd: u8,
        responder_addr: u8,
        responder_lun: LogicalUnit,
        requestor_addr: u8,
    ) -> ExpectedReply {
        let sequence = self.ipmb_sequence & 0x3f;
        self.ipmb_sequence = (sequence + 1) & 0x3f;
        self.retired_sequences[sequence as usize] = true;
        ExpectedReply {
            sequence,
            netfn: netfn + 1,
            cmd,
            responder_addr,
            responder_lun,
            requestor_addr,
            requestor_lun: self.requestor_lun,
        }
    }

    pub fn begin(
        &mut self,
        request: &Request,
        deadline: Instant,
    ) -> Result<Vec<u8>, RmcpIpmiSendError> {
        if self.pending.is_some() {
            return Err(RmcpIpmiSendError::RequestPending);
        }
        let (target, transit) = match request.target() {
            RequestTargetAddress::Bmc(lun) => (None, Some(lun)),
            RequestTargetAddress::BmcOrIpmb(Address(addr), channel, lun)
                if addr == self.responder_addr
                    && matches!(channel, Channel::Current | Channel::Primary) =>
            {
                (None, Some(lun))
            }
            RequestTargetAddress::BmcOrIpmb(address, channel, lun) => {
                (Some((IpmbTarget::new(address, channel, lun), None)), None)
            }
            RequestTargetAddress::Bridged { target, transit } => (Some((target, transit)), None),
        };
        if request.netfn().request_value() > 0x3e {
            return Err(RmcpIpmiSendError::InvalidNetfn(request.netfn_raw()));
        }
        if let Some((target, transit)) = target {
            if !valid_hop(target)
                || transit.is_some_and(|hop| {
                    !valid_hop(hop)
                        || hop.address == target.address && hop.channel == target.channel
                        || hop.address.0 == self.responder_addr
                })
            {
                return Err(RmcpIpmiSendError::InvalidBridgeTarget);
            }
            let len = 7 + request.data().len() + 8 * (1 + usize::from(transit.is_some()));
            if len > u8::MAX as usize {
                return Err(RmcpIpmiSendError::BridgePayloadTooLarge(len));
            }
        }
        let needed = if let Some((_, transit)) = target {
            2 + usize::from(transit.is_some())
        } else {
            1
        };
        if (0..needed).any(|i| self.retired_sequences[(self.ipmb_sequence as usize + i) & 0x3f]) {
            return Err(RmcpIpmiSendError::IpmbSequenceExhausted);
        }
        let (payload, final_reply, send_acks, queue_channel) = if let Some((target, transit)) =
            target
        {
            let bmc_ack = self.next_reply(
                APP_NETFN,
                SEND_MESSAGE,
                self.responder_addr,
                LogicalUnit::Zero,
                self.requestor_addr,
            );
            let transit_ack = transit.map(|hop| {
                self.next_reply(
                    APP_NETFN,
                    SEND_MESSAGE,
                    hop.address.0,
                    hop.lun,
                    self.requestor_addr,
                )
            });
            let final_reply = self.next_reply(
                request.netfn().request_value(),
                request.cmd(),
                target.address.0,
                target.lun,
                if transit.is_some() {
                    self.responder_addr
                } else {
                    self.requestor_addr
                },
            );
            let mut inner = ipmb_request(final_reply, request.data());
            if let Some(ack) = transit_ack {
                let mut body = Vec::with_capacity(1 + inner.len());
                body.push(TRACK_REQUEST | target.channel.value());
                body.extend_from_slice(&inner);
                inner = ipmb_request(ack, &body);
            }
            let mut body = Vec::with_capacity(1 + inner.len());
            body.push(
                TRACK_REQUEST | transit.map_or(target.channel.value(), |hop| hop.channel.value()),
            );
            body.extend_from_slice(&inner);
            (
                ipmb_request(bmc_ack, &body),
                final_reply,
                [Some(bmc_ack), transit_ack],
                transit.map_or(target.channel.value(), |hop| hop.channel.value()),
            )
        } else {
            let reply = self.next_reply(
                request.netfn().request_value(),
                request.cmd(),
                self.responder_addr,
                transit.expect("local LUN"),
                self.requestor_addr,
            );
            (ipmb_request(reply, request.data()), reply, [None, None], 0)
        };
        self.pending = Some(PendingRequest {
            final_reply,
            send_acks,
            acked: [false; 2],
            poll: None,
            deferred: None,
            queue_channel,
            queue_available: false,
            deadline,
        });
        Ok(payload)
    }

    pub fn needs_poll(&self) -> bool {
        self.pending.as_ref().is_some_and(|p| {
            self.get_message_supported && p.send_acks[0].is_some() && p.acked[0] && p.poll.is_none()
        })
    }

    pub fn queue_available(&self) -> bool {
        self.pending.as_ref().is_some_and(|p| p.queue_available)
    }

    pub fn stop_polling(&mut self) {
        self.get_message_supported = false;
    }

    pub fn poll_message(&mut self) -> Result<Vec<u8>, RmcpIpmiSendError> {
        if !self.needs_poll() {
            return Err(RmcpIpmiSendError::RequestPending);
        }
        let seq = self.ipmb_sequence as usize;
        if self.retired_sequences[seq] {
            return Err(RmcpIpmiSendError::IpmbSequenceExhausted);
        }
        let reply = self.next_reply(
            APP_NETFN,
            if self.queue_available() {
                GET_MESSAGE
            } else {
                GET_MESSAGE_FLAGS
            },
            self.responder_addr,
            LogicalUnit::Zero,
            self.requestor_addr,
        );
        self.pending.as_mut().expect("needs_poll").poll = Some(reply);
        Ok(ipmb_request(reply, &[]))
    }

    pub fn receive(&mut self, data: &[u8]) -> Result<Option<Response>, RmcpIpmiReceiveError> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(RmcpIpmiReceiveError::NoPendingRequest)?;
        let response = Self::receive_nested(pending, data, 0, &mut self.get_message_supported)?;
        if response.is_some() {
            self.pending = None;
        }
        Ok(response)
    }

    fn receive_nested(
        pending: &mut PendingRequest,
        data: &[u8],
        depth: u8,
        get_message_supported: &mut bool,
    ) -> Result<Option<Response>, RmcpIpmiReceiveError> {
        if depth > 2 {
            return Err(RmcpIpmiReceiveError::IpmbResponseMismatch);
        }
        if let Some(poll) = pending.poll {
            if correlate(data, poll).is_ok() {
                let response = correlate(data, poll)?;
                pending.poll = None;
                match response.cc() {
                    0 => {}
                    0x80 if poll.cmd == GET_MESSAGE => {
                        pending.queue_available = false;
                        return Ok(None);
                    }
                    0xc1 | 0xc2 | 0xd6 => {
                        *get_message_supported = false;
                        return Ok(None);
                    }
                    // Retry only read-only queue probes, never the original command.
                    0xc0 | 0xc3 | 0xce | 0xd0..=0xd2 | 0xd5 => {
                        pending.queue_available = false;
                        return Ok(None);
                    }
                    code => {
                        return Err(RmcpIpmiReceiveError::BridgeQueueCompletion {
                            command: poll.cmd,
                            code,
                        });
                    }
                }
                if poll.cmd == GET_MESSAGE_FLAGS {
                    if response.data().len() != 1 {
                        return Err(RmcpIpmiReceiveError::NotEnoughData);
                    }
                    pending.queue_available = response.data()[0] & 1 != 0;
                    return Ok(None);
                }
                pending.queue_available = false;
                let body = response.data();
                if body.len() < 8 {
                    return Err(RmcpIpmiReceiveError::NotEnoughData);
                }
                if body[0] != pending.queue_channel {
                    return Err(RmcpIpmiReceiveError::IpmbResponseMismatch);
                }
                let queued = &body[1..];
                // Get Message on some BMCs omits the destination address
                // (the first IPMB byte). Its checksum still covers that byte.
                let packet = if validate_ipmb_checksums(queued) {
                    queued.to_vec()
                } else {
                    let mut full = Vec::with_capacity(queued.len() + 1);
                    full.push(0u8.wrapping_sub(queued[0].wrapping_add(queued[1])));
                    full.extend_from_slice(queued);
                    if !validate_ipmb_checksums(&full) {
                        return Err(RmcpIpmiReceiveError::IpmbChecksumFailed);
                    }
                    full
                };
                return Self::receive_nested(pending, &packet, depth + 1, get_message_supported);
            }
        }
        for hop in 0..2 {
            if let Some(expected) = pending.send_acks[hop] {
                if correlate(data, expected).is_ok() {
                    if pending.acked[hop] {
                        return Err(RmcpIpmiReceiveError::IpmbResponseMismatch);
                    }
                    let response = correlate(data, expected)?;
                    if response.cc() != 0 {
                        return Err(RmcpIpmiReceiveError::BridgeCompletion {
                            hop: hop as u8,
                            code: response.cc(),
                        });
                    }
                    pending.acked[hop] = true;
                    if !response.data().is_empty() {
                        return Self::receive_nested(
                            pending,
                            response.data(),
                            depth + 1,
                            get_message_supported,
                        );
                    }
                    if pending.acked[0] && (pending.send_acks[1].is_none() || pending.acked[1]) {
                        return Ok(pending.deferred.take());
                    }
                    return Ok(None);
                }
            }
        }
        let response = correlate(data, pending.final_reply)?;
        if (pending.acked[0] || pending.send_acks[0].is_none())
            && (pending.send_acks[1].is_none() || pending.acked[1])
        {
            return Ok(Some(response));
        }
        if pending.deferred.is_some() {
            return Err(RmcpIpmiReceiveError::IpmbResponseMismatch);
        }
        pending.deferred = Some(response);
        Ok(None)
    }
}

#[test]
fn ipmb_message_test() {
    use crate::connection::Message;

    let data = IpmbState::default()
        .begin(
            &crate::connection::Request::new(
                Message::new_raw(0x0D, 0x0B, vec![0x01, 0x02, 0x03]),
                crate::connection::RequestTargetAddress::Bmc(crate::connection::LogicalUnit::One),
            ),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();

    let expected = vec![0x20, 0x31, 0xAF, 0x81, 0x00, 0x0B, 0x01, 0x02, 0x03, 0x6E];

    assert_eq!(expected, data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{Address, Message, NetFn};

    fn hop(address: u8, channel: u8, lun: LogicalUnit) -> IpmbTarget {
        IpmbTarget::new(Address(address), Channel::new(channel).unwrap(), lun)
    }

    fn bridge(transit: Option<IpmbTarget>) -> Request {
        Request::new(
            Message::new_request(NetFn::Chassis, 2, vec![0x01]),
            RequestTargetAddress::Bridged {
                target: hop(0x52, 2, LogicalUnit::Three),
                transit,
            },
        )
    }

    fn answer(expected: ExpectedReply, cc: u8, body: &[u8]) -> Vec<u8> {
        let first = [
            expected.requestor_addr,
            (expected.netfn << 2) | expected.requestor_lun.value(),
        ];
        let second = [
            expected.responder_addr,
            (expected.sequence << 2) | expected.responder_lun.value(),
            expected.cmd,
            cc,
        ];
        let mut result = vec![first[0], first[1], Checksum::from_iter(first)];
        result.extend_from_slice(&second);
        result.extend_from_slice(body);
        result.push(Checksum::from_iter(
            second.into_iter().chain(body.iter().copied()),
        ));
        result
    }

    fn poll_available(state: &mut IpmbState) -> ExpectedReply {
        let flags = state.poll_message().unwrap();
        assert_eq!(flags[5], GET_MESSAGE_FLAGS);
        let expected = state.pending.as_ref().unwrap().poll.unwrap();
        assert!(state.receive(&answer(expected, 0, &[1])).unwrap().is_none());
        assert!(state.queue_available());
        let get = state.poll_message().unwrap();
        assert_eq!(get[5], GET_MESSAGE);
        state.pending.as_ref().unwrap().poll.unwrap()
    }

    fn request() -> Request {
        Request::new(
            Message::new_request(NetFn::Chassis, 2, vec![0x01]),
            RequestTargetAddress::Bmc(LogicalUnit::One),
        )
    }

    fn reply(sequence: u8) -> Vec<u8> {
        let mut data = vec![0x81, 0x04, 0, 0x20, (sequence << 2) | 1, 2, 0];
        data[2] = Checksum::from_iter(data[..2].iter().copied());
        data.push(Checksum::from_iter(data[3..].iter().copied()));
        data
    }

    #[test]
    fn response_correlation_and_both_checksums() {
        let mut state = IpmbState::default();
        let deadline = Instant::now() + Duration::from_secs(1);
        let req = request();
        state.begin(&req, deadline).unwrap();
        assert!(matches!(
            state.begin(&req, deadline),
            Err(RmcpIpmiSendError::RequestPending)
        ));
        assert_eq!(state.receive(&reply(0)).unwrap().unwrap().seq(), 0);
        for (index, value) in [(0, 0x82), (1, 0x08), (3, 0x21), (4, 0x05), (5, 0x03)] {
            state.begin(&req, deadline).unwrap();
            let mut bad = reply((state.ipmb_sequence.wrapping_sub(1)) & 0x3f);
            bad[index] = value;
            bad[2] = Checksum::from_iter(bad[..2].iter().copied());
            let last = bad.len() - 1;
            bad[last] = Checksum::from_iter(bad[3..last].iter().copied());
            assert!(
                matches!(
                    state.receive(&bad),
                    Err(RmcpIpmiReceiveError::IpmbResponseMismatch)
                ),
                "index {index}"
            );
            state.retire_pending();
        }
        for index in [2, 7] {
            state.begin(&req, deadline).unwrap();
            let mut bad = reply((state.ipmb_sequence.wrapping_sub(1)) & 0x3f);
            bad[index] ^= 1;
            assert!(matches!(
                state.receive(&bad),
                Err(RmcpIpmiReceiveError::IpmbChecksumFailed)
            ));
            state.retire_pending();
        }
        state.begin(&req, deadline).unwrap();
        let short = &reply((state.ipmb_sequence.wrapping_sub(1)) & 0x3f)[..7];
        assert!(matches!(
            state.receive(short),
            Err(RmcpIpmiReceiveError::NotEnoughData)
        ));
        state.retire_pending();
        let failed_sequence = (state.ipmb_sequence - 1) & 0x3f;
        state.ipmb_sequence = failed_sequence;
        assert!(matches!(
            state.begin(&req, deadline),
            Err(RmcpIpmiSendError::IpmbSequenceExhausted)
        ));
        state.ipmb_sequence = 63;
        let data = state.begin(&req, deadline).unwrap();
        assert_eq!(data[4] >> 2, 63);
        assert_eq!(state.receive(&reply(63)).unwrap().unwrap().seq(), 63);
        assert_eq!(state.ipmb_sequence, 0);
    }

    #[test]
    fn bridged_target_is_not_silently_addressed_as_bmc() {
        let mut state = IpmbState::default();
        let bridged = Request::new(
            Message::new_request(NetFn::Chassis, 2, vec![]),
            RequestTargetAddress::BmcOrIpmb(Address(0x22), Channel::Primary, LogicalUnit::Zero),
        );
        let wire = state.begin(&bridged, Instant::now()).unwrap();
        assert_eq!((wire[0], wire[1], wire[5]), (0x20, 0x18, 0x34));
        assert_eq!(wire[6], 0x40);
        assert_eq!((wire[7], wire[8]), (0x22, 0x00));
        state.retire_pending();
        let local = Request::new(
            Message::new_request(NetFn::Chassis, 2, vec![]),
            RequestTargetAddress::BmcOrIpmb(Address(0x20), Channel::Current, LogicalUnit::Zero),
        );
        assert!(state.begin(&local, Instant::now()).is_ok());
    }

    #[test]
    fn single_hop_wire_and_tracked_get_message() {
        let mut state = IpmbState::default();
        let wire = state.begin(&bridge(None), Instant::now()).unwrap();
        assert!(validate_ipmb_checksums(&wire));
        assert_eq!(&wire[..7], &[0x20, 0x18, 0xc8, 0x81, 0, 0x34, 0x42]);
        assert_eq!(
            (wire[7], wire[8], wire[10], wire[11], wire[12], wire[13]),
            (0x52, 0x03, 0x81, 0x04, 2, 1)
        );
        assert!(validate_ipmb_checksums(&wire[7..wire.len() - 1]));
        let pending = state.pending.as_ref().unwrap();
        let ack = answer(pending.send_acks[0].unwrap(), 0, &[]);
        let final_reply = answer(pending.final_reply, 0, &[0xab]);
        assert!(state.receive(&ack).unwrap().is_none());
        assert!(state.needs_poll());
        let poll = poll_available(&mut state);
        assert_eq!(poll.sequence, 3);
        assert!(state.receive(&answer(poll, 0x80, &[])).unwrap().is_none());
        assert!(state.needs_poll());
        assert!(!state.queue_available());
        let poll = poll_available(&mut state);
        let mut wrong = final_reply.clone();
        wrong[4] ^= 4;
        let last = wrong.len() - 1;
        wrong[last] = Checksum::from_iter(wrong[3..last].iter().copied());
        assert!(matches!(
            state.receive(&wrong),
            Err(RmcpIpmiReceiveError::IpmbResponseMismatch)
        ));
        let mut body = vec![2];
        body.extend_from_slice(&final_reply[1..]);
        let response = state.receive(&answer(poll, 0, &body)).unwrap().unwrap();
        assert_eq!(
            (response.seq(), response.cc(), response.data()),
            (1, 0, &[0xab][..])
        );
        assert!(matches!(
            state.receive(&final_reply),
            Err(RmcpIpmiReceiveError::NoPendingRequest)
        ));
    }

    #[test]
    fn get_message_full_ipmb_and_corrupted_queued_checksum() {
        let mut state = IpmbState::default();
        state.begin(&bridge(None), Instant::now()).unwrap();
        let p = state.pending.as_ref().unwrap();
        let ack = answer(p.send_acks[0].unwrap(), 0, &[]);
        let final_reply = answer(p.final_reply, 0, &[]);
        state.receive(&ack).unwrap();
        let poll = poll_available(&mut state);
        let mut bad = final_reply.clone();
        let checksum = bad.len() - 1;
        bad[checksum] ^= 1;
        let mut body = vec![2];
        body.extend_from_slice(&bad[1..]);
        assert!(matches!(
            state.receive(&answer(poll, 0, &body)),
            Err(RmcpIpmiReceiveError::IpmbChecksumFailed)
        ));
        state.retire_pending();

        state.begin(&bridge(None), Instant::now()).unwrap();
        let p = state.pending.as_ref().unwrap();
        let ack = answer(p.send_acks[0].unwrap(), 0, &[]);
        let final_reply = answer(p.final_reply, 0, &[]);
        state.receive(&ack).unwrap();
        let poll = poll_available(&mut state);
        let mut body = vec![2];
        body.extend_from_slice(&final_reply);
        assert!(state.receive(&answer(poll, 0, &body)).unwrap().is_some());
    }

    #[test]
    fn unsupported_queue_commands_switch_to_pushed_replies_for_the_session() {
        for unsupported in [GET_MESSAGE_FLAGS, GET_MESSAGE] {
            let mut state = IpmbState::default();
            state.begin(&bridge(None), Instant::now()).unwrap();
            let pending = state.pending.as_ref().unwrap();
            let ack = answer(pending.send_acks[0].unwrap(), 0, &[]);
            let target = answer(pending.final_reply, 0, &[0xa5]);
            state.receive(&ack).unwrap();
            let poll = if unsupported == GET_MESSAGE_FLAGS {
                state.poll_message().unwrap();
                state.pending.as_ref().unwrap().poll.unwrap()
            } else {
                poll_available(&mut state)
            };
            assert_eq!(poll.cmd, unsupported);
            assert!(state.receive(&answer(poll, 0xc1, &[])).unwrap().is_none());
            assert!(state.pending.is_some());
            assert!(!state.needs_poll());
            assert_eq!(state.receive(&target).unwrap().unwrap().data(), &[0xa5]);

            state.begin(&bridge(None), Instant::now()).unwrap();
            let ack = state.pending.as_ref().unwrap().send_acks[0].unwrap();
            state.receive(&answer(ack, 0, &[])).unwrap();
            assert!(!state.needs_poll());
            state.retire_pending();
        }
    }

    #[test]
    fn transient_queue_busy_rechecks_flags_without_resending_target() {
        for busy_command in [GET_MESSAGE_FLAGS, GET_MESSAGE] {
            let mut state = IpmbState::default();
            state.begin(&bridge(None), Instant::now()).unwrap();
            let p = state.pending.as_ref().unwrap();
            let ack = answer(p.send_acks[0].unwrap(), 0, &[]);
            let final_reply = answer(p.final_reply, 0, &[0x55]);
            state.receive(&ack).unwrap();
            let busy = if busy_command == GET_MESSAGE_FLAGS {
                state.poll_message().unwrap();
                state.pending.as_ref().unwrap().poll.unwrap()
            } else {
                poll_available(&mut state)
            };
            assert_eq!(busy.cmd, busy_command);
            assert!(state.receive(&answer(busy, 0xc0, &[])).unwrap().is_none());
            assert!(state.needs_poll());
            assert!(!state.queue_available());
            let poll = poll_available(&mut state);
            assert_ne!(busy.sequence, poll.sequence);
            let mut body = vec![2];
            body.extend_from_slice(&final_reply[1..]);
            assert_eq!(
                state
                    .receive(&answer(poll, 0, &body))
                    .unwrap()
                    .unwrap()
                    .data(),
                &[0x55]
            );
            assert!(state.get_message_supported);
        }
    }

    #[test]
    fn dual_hop_nested_and_out_of_order_replies() {
        let transit = hop(0x30, 1, LogicalUnit::One);
        let mut state = IpmbState::default();
        let wire = state.begin(&bridge(Some(transit)), Instant::now()).unwrap();
        assert!(validate_ipmb_checksums(&wire));
        assert_eq!(
            (wire[6], wire[7], wire[8], wire[10], wire[11], wire[12], wire[13]),
            (0x41, 0x30, 0x19, 0x81, 0x04, 0x34, 0x42)
        );
        assert_eq!(
            (wire[14], wire[15], wire[17], wire[18]),
            (0x52, 0x03, 0x20, 0x08)
        );
        assert!(validate_ipmb_checksums(&wire[7..wire.len() - 1]));
        assert!(validate_ipmb_checksums(&wire[14..wire.len() - 2]));
        let p = state.pending.as_ref().unwrap();
        let final_reply = answer(p.final_reply, 0, &[0xdd]);
        let transit_ack = answer(p.send_acks[1].unwrap(), 0, &final_reply);
        let outer_ack = answer(p.send_acks[0].unwrap(), 0, &transit_ack);
        assert_eq!(state.receive(&outer_ack).unwrap().unwrap().data(), &[0xdd]);

        state.begin(&bridge(Some(transit)), Instant::now()).unwrap();
        let p = state.pending.as_ref().unwrap();
        let final_reply = answer(p.final_reply, 0, &[]);
        let transit_ack = answer(p.send_acks[1].unwrap(), 0, &[]);
        let outer_ack = answer(p.send_acks[0].unwrap(), 0, &[]);
        assert!(state.receive(&final_reply).unwrap().is_none());
        assert!(state.receive(&transit_ack).unwrap().is_none());
        assert!(!state.needs_poll());
        assert!(state.receive(&outer_ack).unwrap().is_some());
        assert!(state.pending.is_none());
    }

    #[test]
    fn dual_hop_queued_replies_and_correlation_failures() {
        let mut state = IpmbState::default();
        state
            .begin(
                &bridge(Some(hop(0x30, 1, LogicalUnit::One))),
                Instant::now(),
            )
            .unwrap();
        let p = state.pending.as_ref().unwrap();
        let outer = answer(p.send_acks[0].unwrap(), 0, &[]);
        let transit = answer(p.send_acks[1].unwrap(), 0, &[]);
        let final_reply = answer(p.final_reply, 0, &[]);
        let mut corrupted = outer.clone();
        corrupted[2] ^= 1;
        assert!(matches!(
            state.receive(&corrupted),
            Err(RmcpIpmiReceiveError::IpmbChecksumFailed)
        ));
        let mut wrong_lun = transit.clone();
        wrong_lun[4] ^= 1;
        let last = wrong_lun.len() - 1;
        wrong_lun[last] = Checksum::from_iter(wrong_lun[3..last].iter().copied());
        assert!(matches!(
            state.receive(&wrong_lun),
            Err(RmcpIpmiReceiveError::IpmbResponseMismatch)
        ));
        assert!(state.receive(&outer).unwrap().is_none());
        let poll = poll_available(&mut state);
        let unrelated = answer(
            ExpectedReply {
                responder_addr: 0x54,
                ..state.pending.as_ref().unwrap().final_reply
            },
            0,
            &[],
        );
        let mut body = vec![1];
        body.extend_from_slice(&unrelated[1..]);
        assert!(matches!(
            state.receive(&answer(poll, 0, &body)),
            Err(RmcpIpmiReceiveError::IpmbResponseMismatch)
        ));
        let poll = poll_available(&mut state);
        let mut body = vec![2]; // target channel is 2; BMC receive queue is on transit channel 1
        body.extend_from_slice(&transit[1..]);
        assert!(matches!(
            state.receive(&answer(poll, 0, &body)),
            Err(RmcpIpmiReceiveError::IpmbResponseMismatch)
        ));
        body[0] = 1;
        let poll = poll_available(&mut state);
        assert!(state.receive(&answer(poll, 0, &body)).unwrap().is_none());
        assert!(matches!(
            state.receive(&transit),
            Err(RmcpIpmiReceiveError::IpmbResponseMismatch)
        ));
        let poll = poll_available(&mut state);
        body.truncate(1);
        body.extend_from_slice(&final_reply[1..]);
        assert!(state.receive(&answer(poll, 0, &body)).unwrap().is_some());
    }

    #[test]
    fn bridge_errors_fail_closed_without_resending() {
        let mut state = IpmbState::default();
        let req = bridge(None);
        let wire = state.begin(&req, Instant::now()).unwrap();
        assert!(matches!(
            state.begin(&req, Instant::now()),
            Err(RmcpIpmiSendError::RequestPending)
        ));
        let p = state.pending.as_ref().unwrap();
        assert!(matches!(
            state.receive(&answer(p.send_acks[0].unwrap(), 0xc1, &[])),
            Err(RmcpIpmiReceiveError::BridgeCompletion { hop: 0, code: 0xc1 })
        ));
        state.retire_pending();
        assert_eq!(wire[4] >> 2, 0);
        let invalid = Request::new(
            Message::new_request(NetFn::Chassis, 2, vec![]),
            RequestTargetAddress::Bridged {
                target: hop(0x53, 0, LogicalUnit::Zero),
                transit: None,
            },
        );
        assert!(matches!(
            state.begin(&invalid, Instant::now()),
            Err(RmcpIpmiSendError::InvalidBridgeTarget)
        ));
        let too_large = Request::new(
            Message::new_request(NetFn::Chassis, 2, vec![0; 241]),
            RequestTargetAddress::Bridged {
                target: hop(0x52, 0, LogicalUnit::Zero),
                transit: None,
            },
        );
        assert!(matches!(
            state.begin(&too_large, Instant::now()),
            Err(RmcpIpmiSendError::BridgePayloadTooLarge(_))
        ));
    }

    #[test]
    fn each_bridge_hop_rejects_wrong_address_lun_sequence_netfn_and_command() {
        for hop in 0..3 {
            for field in [0, 1, 3, 4, 5] {
                let mut state = IpmbState::default();
                state
                    .begin(
                        &bridge(Some(hop_target())),
                        Instant::now() + Duration::from_secs(1),
                    )
                    .unwrap();
                let p = state.pending.as_ref().unwrap();
                let expected = match hop {
                    0 => p.send_acks[0].unwrap(),
                    1 => p.send_acks[1].unwrap(),
                    _ => p.final_reply,
                };
                let mut bad = answer(expected, 0, &[]);
                bad[field] ^= if field == 4 { 4 } else { 1 };
                bad[2] = Checksum::from_iter(bad[..2].iter().copied());
                let last = bad.len() - 1;
                bad[last] = Checksum::from_iter(bad[3..last].iter().copied());
                assert!(
                    matches!(
                        state.receive(&bad),
                        Err(RmcpIpmiReceiveError::IpmbResponseMismatch)
                    ),
                    "hop {hop} field {field}"
                );
            }
        }
    }

    fn hop_target() -> IpmbTarget {
        hop(0x30, 1, LogicalUnit::One)
    }

    #[test]
    fn queued_bridge_error_and_sequence_budget_are_bounded() {
        let mut state = IpmbState::default();
        state.begin(&bridge(None), Instant::now()).unwrap();
        let ack = state.pending.as_ref().unwrap().send_acks[0].unwrap();
        state.receive(&answer(ack, 0, &[])).unwrap();
        let mut polls = 0;
        loop {
            match state.poll_message() {
                Ok(_) => {
                    polls += 1;
                    let reply = state.pending.as_ref().unwrap().poll.unwrap();
                    assert_eq!(reply.cmd, GET_MESSAGE_FLAGS);
                    assert!(state.receive(&answer(reply, 0, &[0])).unwrap().is_none());
                }
                Err(RmcpIpmiSendError::IpmbSequenceExhausted) => break,
                other => panic!("unexpected poll result: {other:?}"),
            }
        }
        assert_eq!(polls, 62);
        state.stop_polling();
        assert!(!state.needs_poll());
        let target = answer(state.pending.as_ref().unwrap().final_reply, 0, &[0xa5]);
        assert_eq!(state.receive(&target).unwrap().unwrap().data(), &[0xa5]);
        assert!(matches!(
            state.begin(&bridge(None), Instant::now()),
            Err(RmcpIpmiSendError::IpmbSequenceExhausted)
        ));

        let mut state = IpmbState::default();
        state
            .begin(&bridge(Some(hop_target())), Instant::now())
            .unwrap();
        let p = state.pending.as_ref().unwrap();
        let outer = answer(p.send_acks[0].unwrap(), 0, &[]);
        let transit_error = answer(p.send_acks[1].unwrap(), 0xc1, &[]);
        state.receive(&outer).unwrap();
        assert!(matches!(
            state.receive(&transit_error),
            Err(RmcpIpmiReceiveError::BridgeCompletion { hop: 1, code: 0xc1 })
        ));
        state.retire_pending();

        let mut state = IpmbState::default();
        state.begin(&bridge(None), Instant::now()).unwrap();
        let ack = state.pending.as_ref().unwrap().send_acks[0].unwrap();
        state.receive(&answer(ack, 0, &[])).unwrap();
        let poll = poll_available(&mut state);
        assert!(matches!(
            state.receive(&answer(poll, 0xcc, &[])),
            Err(RmcpIpmiReceiveError::BridgeQueueCompletion {
                command: GET_MESSAGE,
                code: 0xcc
            })
        ));
        state.retire_pending();
        state.begin(&bridge(None), Instant::now()).unwrap();
        let ack = state.pending.as_ref().unwrap().send_acks[0].unwrap();
        state.receive(&answer(ack, 0, &[])).unwrap();
        state.poll_message().unwrap();
        let flags = state.pending.as_ref().unwrap().poll.unwrap();
        assert!(matches!(
            state.receive(&answer(flags, 0xcc, &[])),
            Err(RmcpIpmiReceiveError::BridgeQueueCompletion {
                command: GET_MESSAGE_FLAGS,
                code: 0xcc
            })
        ));
    }
}
