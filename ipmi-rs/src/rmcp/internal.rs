// LE = least significant byte first = IPMI
// BE = most significant byte first = RMCP/ASF

use std::{
    io::ErrorKind,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    time::{Duration, Instant},
};

use crate::{
    app::auth::{CipherSuite, GetChannelAuthenticationCapabilities, PrivilegeLevel},
    connection::{Channel, IpmiConnection, LogicalUnit, Request, RequestTargetAddress, Response},
};

use super::{
    checksum::Checksum,
    socket::{recv_datagram, TransportPolicy},
    v1_5::State as V1_5State,
    v2_0::State as V2_0State,
    ASFMessage, ASFMessageType, ActivationError, RmcpHeader, RmcpIpmiError, RmcpIpmiReceiveError,
    RmcpIpmiSendError, RmcpType,
};

#[derive(Debug, Clone, Copy)]
pub struct PendingRequest {
    sequence: u8,
    netfn: u8,
    cmd: u8,
    responder_addr: u8,
    responder_lun: LogicalUnit,
    requestor_addr: u8,
    requestor_lun: LogicalUnit,
    pub deadline: Instant,
}

#[derive(Debug, Clone)]
pub struct IpmbState {
    pub ipmb_sequence: u8,
    pub responder_addr: u8,
    pub requestor_addr: u8,
    pub requestor_lun: LogicalUnit,
    pub pending: Option<PendingRequest>,
    retired_sequences: [bool; 64],
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

impl<T> RmcpWithState<T> {
    fn state(&self) -> &T {
        &self.0
    }

    fn state_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl RmcpWithState<Unbound> {
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
        required_suite: Option<CipherSuite>,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<RmcpWithState<Active>, ActivationError> {
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

        let privilege_level = PrivilegeLevel::Administrator;

        let authentication_caps = match ipmi.send_recv(GetChannelAuthenticationCapabilities::new(
            Channel::Current,
            privilege_level,
        )) {
            Ok(v) => v,
            Err(e) => return Err(ActivationError::GetChannelAuthenticationCapabilities(e)),
        };

        log::debug!("Authentication capabilities: {:?}", authentication_caps);

        if authentication_caps.ipmi2_connections_supported && rmcp_plus {
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
                required_suite.unwrap_or(CipherSuite::Id3),
            )?;

            Ok(RmcpWithState(Active::V2_0(res)))
        } else if required_suite.is_some() {
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
            Active::V1_5(state) => state.send(request)?,
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

// TODO: `ExactSizeIterator` to avoid/postpone allocation?
pub fn next_ipmb_message(
    request: &Request,
    ipmb_state: &mut IpmbState,
) -> Result<Vec<u8>, RmcpIpmiSendError> {
    if ipmb_state.pending.is_some() {
        return Err(RmcpIpmiSendError::RequestPending);
    }
    let local_target = match request.target() {
        RequestTargetAddress::Bmc(_) => true,
        RequestTargetAddress::BmcOrIpmb(crate::connection::Address(addr), channel, _) => {
            addr == ipmb_state.responder_addr
                && matches!(channel, Channel::Current | Channel::Primary)
        }
    };
    if !local_target {
        return Err(RmcpIpmiSendError::UnsupportedTarget);
    }
    if request.netfn().request_value() > 0x3e {
        return Err(RmcpIpmiSendError::InvalidNetfn(request.netfn_raw()));
    }
    if ipmb_state.retired_sequences[(ipmb_state.ipmb_sequence & 0x3f) as usize] {
        return Err(RmcpIpmiSendError::IpmbSequenceExhausted);
    }
    let IpmbState {
        ipmb_sequence,
        responder_addr: rs_addr,
        requestor_addr,
        requestor_lun,
        ..
    } = ipmb_state;

    let data = request.data();

    let mut all_data = Vec::with_capacity(7 + data.len());

    let netfn_rslun: u8 = (request.netfn().request_value() << 2) | request.target().lun().value();
    let first_part = [*rs_addr, netfn_rslun];

    all_data.extend(first_part);
    all_data.push(Checksum::from_iter(first_part));

    let req_addr = *requestor_addr;

    let ipmb_sequence_val = *ipmb_sequence & 0x3f;
    *ipmb_sequence = (ipmb_sequence_val + 1) & 0x3f;

    let reqseq_lun = (ipmb_sequence_val << 2) | requestor_lun.value();
    let cmd = request.cmd();

    let second_start = [req_addr, reqseq_lun, cmd];
    let second_end = request.data().iter().copied();
    let second_part_chk = Checksum::from_iter(second_start.into_iter().chain(second_end.clone()));

    all_data.extend(second_start);
    all_data.extend(second_end);
    all_data.push(second_part_chk);

    Ok(all_data)
}

impl IpmbState {
    pub fn retire_pending(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.retired_sequences[pending.sequence as usize] = true;
        }
    }

    pub fn begin(
        &mut self,
        request: &Request,
        deadline: Instant,
    ) -> Result<Vec<u8>, RmcpIpmiSendError> {
        let payload = next_ipmb_message(request, self)?;
        self.pending = Some(PendingRequest {
            sequence: (self.ipmb_sequence.wrapping_sub(1)) & 0x3f,
            netfn: request.netfn().response_value(),
            cmd: request.cmd(),
            responder_addr: self.responder_addr,
            responder_lun: request.target().lun(),
            requestor_addr: self.requestor_addr,
            requestor_lun: self.requestor_lun,
            deadline,
        });
        Ok(payload)
    }

    pub fn receive(&mut self, data: &[u8]) -> Result<Response, RmcpIpmiReceiveError> {
        let pending = self.pending.ok_or(RmcpIpmiReceiveError::NoPendingRequest)?;
        let result = self.correlate(data, pending);
        if result.is_err() {
            self.retire_pending();
        } else {
            self.pending = None;
        }
        result
    }

    fn correlate(
        &self,
        data: &[u8],
        pending: PendingRequest,
    ) -> Result<Response, RmcpIpmiReceiveError> {
        if data.len() < 8 {
            return Err(RmcpIpmiReceiveError::NotEnoughData);
        }
        if !validate_ipmb_checksums(data) {
            return Err(RmcpIpmiReceiveError::IpmbChecksumFailed);
        }
        if data[0] != pending.requestor_addr
            || data[1] & 3 != pending.requestor_lun.value()
            || data[3] != pending.responder_addr
            || data[4] & 3 != pending.responder_lun.value()
            || data[4] >> 2 != pending.sequence
            || data[1] >> 2 != pending.netfn
            || data[5] != pending.cmd
        {
            return Err(RmcpIpmiReceiveError::IpmbResponseMismatch);
        }
        Response::new(
            crate::connection::Message::new_raw(
                data[1] >> 2,
                data[5],
                data[6..data.len() - 1].to_vec(),
            ),
            i64::from(pending.sequence),
        )
        .ok_or(RmcpIpmiReceiveError::EmptyMessage)
    }
}

#[test]
fn ipmb_message_test() {
    use crate::connection::Message;

    let data = next_ipmb_message(
        &crate::connection::Request::new(
            Message::new_raw(0x0D, 0x0B, vec![0x01, 0x02, 0x03]),
            crate::connection::RequestTargetAddress::Bmc(crate::connection::LogicalUnit::One),
        ),
        &mut IpmbState::default(),
    )
    .unwrap();

    let expected = vec![0x20, 0x31, 0xAF, 0x81, 0x00, 0x0B, 0x01, 0x02, 0x03, 0x6E];

    assert_eq!(expected, data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{Address, Message, NetFn};

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
        assert_eq!(state.receive(&reply(0)).unwrap().seq(), 0);
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
        }
        for index in [2, 7] {
            state.begin(&req, deadline).unwrap();
            let mut bad = reply((state.ipmb_sequence.wrapping_sub(1)) & 0x3f);
            bad[index] ^= 1;
            assert!(matches!(
                state.receive(&bad),
                Err(RmcpIpmiReceiveError::IpmbChecksumFailed)
            ));
        }
        state.begin(&req, deadline).unwrap();
        let short = &reply((state.ipmb_sequence.wrapping_sub(1)) & 0x3f)[..7];
        assert!(matches!(
            state.receive(short),
            Err(RmcpIpmiReceiveError::NotEnoughData)
        ));
        let failed_sequence = (state.ipmb_sequence - 1) & 0x3f;
        state.ipmb_sequence = failed_sequence;
        assert!(matches!(
            state.begin(&req, deadline),
            Err(RmcpIpmiSendError::IpmbSequenceExhausted)
        ));
        state.ipmb_sequence = 63;
        let data = state.begin(&req, deadline).unwrap();
        assert_eq!(data[4] >> 2, 63);
        assert_eq!(state.receive(&reply(63)).unwrap().seq(), 63);
        assert_eq!(state.ipmb_sequence, 0);
    }

    #[test]
    fn bridged_target_is_not_silently_addressed_as_bmc() {
        let mut state = IpmbState::default();
        let bridged = Request::new(
            Message::new_request(NetFn::Chassis, 2, vec![]),
            RequestTargetAddress::BmcOrIpmb(Address(0x22), Channel::Primary, LogicalUnit::Zero),
        );
        assert!(matches!(
            state.begin(&bridged, Instant::now()),
            Err(RmcpIpmiSendError::UnsupportedTarget)
        ));
        assert_eq!(state.ipmb_sequence, 0);
        let local = Request::new(
            Message::new_request(NetFn::Chassis, 2, vec![]),
            RequestTargetAddress::BmcOrIpmb(Address(0x20), Channel::Current, LogicalUnit::Zero),
        );
        assert!(state.begin(&local, Instant::now()).is_ok());
    }
}
