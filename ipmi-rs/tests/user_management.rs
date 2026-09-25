use ipmi_rs::{
    app::{
        ChannelAccessSettings, ChannelAccessType, ChannelPrivilegeLevel, GetChannelAccess,
        GetUserAccess, GetUserName, GetUserSummary, PasswordLength, SetChannelAccess,
        SetChannelAccessError, SetChannelAccessMode, SetUserAccess, SetUserName, SetUserPassword,
        SetUserPrivilege, UserAccess, UserEnableStatus, UserId, UserList, UserPassword,
        UserPrivilege, UserRequestError, UserResponseError, UserTextError,
    },
    connection::{
        Channel, CompletionErrorCode, IpmiCommand, IpmiConnection, LogicalUnit, Message, NetFn,
        Request, RequestTargetAddress, Response,
    },
    Ipmi, IpmiError,
};

fn id(value: u8) -> UserId {
    UserId::new(value).unwrap()
}

fn channel() -> Channel {
    Channel::Current
}

fn wire<C: IpmiCommand>(cmd: C, code: u8, bytes: &[u8]) {
    let msg: Message = cmd.into();
    assert_eq!(msg.netfn_raw(), 6);
    assert_eq!(msg.cmd(), code);
    assert_eq!(msg.data(), bytes);
}

#[test]
fn user_id_channel_privilege_and_text_validation() {
    assert!(UserId::new(0).is_none());
    assert_eq!(id(1).value(), 1);
    assert_eq!(id(63).value(), 63);
    assert!(UserId::new(64).is_none());
    for raw in [0, 1, 11, 14, 15] {
        assert!(Channel::new(raw).is_some());
    }
    for raw in [12, 13, 16, 255] {
        assert!(Channel::new(raw).is_none());
    }
    for raw in [1, 2, 3, 4, 5, 15] {
        assert_eq!(UserPrivilege::new(raw).unwrap().value(), raw);
    }
    for raw in [0, 6, 14, 16, 255] {
        assert!(UserPrivilege::new(raw).is_none());
    }
    assert_eq!(
        SetUserAccess::new(channel(), id(1), false, true, true, UserPrivilege::User, 16)
            .unwrap_err(),
        UserRequestError::InvalidSessionLimit
    );
    assert!(
        SetUserAccess::new(channel(), id(1), false, true, true, UserPrivilege::User, 15).is_ok()
    );
    for invalid in ["\n", "a\0b", "é", "a\tb"] {
        assert_eq!(
            SetUserName::new(id(1), invalid).unwrap_err(),
            UserTextError::InvalidEncoding
        );
        assert_eq!(
            UserPassword::new(invalid, PasswordLength::Bytes20).unwrap_err(),
            UserTextError::InvalidEncoding
        );
    }
    assert_eq!(
        SetUserName::new(id(1), &"x".repeat(17)).unwrap_err(),
        UserTextError::TooLong
    );
    assert_eq!(
        UserPassword::new(&"x".repeat(17), PasswordLength::Bytes16).unwrap_err(),
        UserTextError::TooLong
    );
    assert!(UserPassword::new(&"x".repeat(20), PasswordLength::Bytes20).is_ok());
    assert_eq!(
        UserPassword::new(&"x".repeat(21), PasswordLength::Bytes20).unwrap_err(),
        UserTextError::TooLong
    );
}

#[test]
fn summary_list_and_user_access_are_independent_reads() {
    wire(GetUserSummary::new(channel()), 0x44, &[0x0e, 1]);
    wire(GetUserAccess::new(channel(), id(63)), 0x44, &[0x0e, 63]);
    wire(GetUserName::new(id(2)), 0x46, &[2]);

    let access = GetUserAccess::parse_success_response(&[0xc3, 0x82, 0xc1, 0xff]).unwrap();
    assert_eq!(
        access,
        UserAccess {
            summary: GetUserSummary::parse_success_response(&[0xc3, 0x82, 0xc1, 0xff]).unwrap(),
            callback_only: true,
            link_auth: true,
            ipmi_messaging: true,
            privilege_limit: 15,
        }
    );
    assert_eq!(access.summary.max_user_ids, 3);
    assert_eq!(access.summary.enabled_user_ids, 2);
    assert_eq!(access.summary.fixed_user_ids, 1);
    assert_eq!(access.summary.enable_status, UserEnableStatus::Disabled);
    let listed = UserList::new(channel(), access.summary)
        .map(|(user, access, name)| {
            (
                user.value(),
                Message::from(access).data().to_vec(),
                Message::from(name).data().to_vec(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        listed,
        [
            (1, vec![14, 1], vec![1]),
            (2, vec![14, 2], vec![2]),
            (3, vec![14, 3], vec![3])
        ]
    );
    assert_eq!(
        UserAccess::parse(&[3, 0x40, 0, 0x0e])
            .unwrap()
            .privilege_limit,
        14
    );
    assert_eq!(
        UserAccess::parse(&[3, 0xc0, 0, 0])
            .unwrap()
            .summary
            .enable_status,
        UserEnableStatus::Reserved
    );
    assert_eq!(
        UserAccess::parse(&[3, 0x00, 0, 0])
            .unwrap()
            .summary
            .enable_status,
        UserEnableStatus::Unknown
    );
    assert_eq!(
        UserList::new(
            channel(),
            GetUserSummary::parse_success_response(&[0, 0, 0, 0]).unwrap()
        )
        .count(),
        0
    );
}

#[test]
fn usernames_preserve_unknown_raw_bytes_and_reject_bad_lengths() {
    let mut bytes = [0; 16];
    bytes[..5].copy_from_slice(b"admin");
    let name = GetUserName::parse_success_response(&bytes).unwrap();
    assert_eq!(name.as_str(), Some("admin"));
    assert_eq!(name.raw(), &bytes);
    bytes[0] = 0xff;
    assert_eq!(
        GetUserName::parse_success_response(&bytes)
            .unwrap()
            .as_str(),
        None
    );
    for size in [0, 15, 17] {
        assert_eq!(
            GetUserName::parse_success_response(&vec![0; size]),
            Err(UserResponseError::Length {
                expected: 16,
                actual: size,
            })
        );
    }
    for size in [0, 3, 5] {
        assert_eq!(
            GetUserSummary::parse_success_response(&vec![0; size]),
            Err(UserResponseError::Length {
                expected: 4,
                actual: size,
            })
        );
    }
    let mut request = vec![2];
    request.extend_from_slice(b"admin");
    request.extend_from_slice(&[0; 11]);
    wire(SetUserName::new(id(2), "admin").unwrap(), 0x45, &request);
    assert_eq!(SetUserName::parse_success_response(&[]), Ok(()));
    assert_eq!(
        SetUserName::parse_success_response(&[0]),
        Err(UserResponseError::Length {
            expected: 0,
            actual: 1
        })
    );
}

#[test]
fn user_access_privilege_and_password_operations_match_ipmitool_wire() {
    wire(
        SetUserAccess::new(
            channel(),
            id(2),
            true,
            true,
            true,
            UserPrivilege::Administrator,
            3,
        )
        .unwrap(),
        0x43,
        &[0xfe, 2, 4, 3],
    );
    wire(
        SetUserPrivilege::new(channel(), id(2), UserPrivilege::NoAccess),
        0x43,
        &[14, 2, 15, 0],
    );
    wire(
        SetUserPassword::disable(id(2)),
        0x47,
        &[&[2, 0][..], &[0; 16]].concat(),
    );
    wire(
        SetUserPassword::enable(id(2)),
        0x47,
        &[&[2, 1][..], &[0; 16]].concat(),
    );
    let mut short = vec![2, 2];
    short.extend_from_slice(b"p@ss");
    short.extend_from_slice(&[0; 12]);
    wire(
        SetUserPassword::set(
            id(2),
            UserPassword::new("p@ss", PasswordLength::Bytes16).unwrap(),
        ),
        0x47,
        &short,
    );
    let mut long = vec![0x82, 3];
    long.extend_from_slice(b"0123456789abcdefGHIJ");
    wire(
        SetUserPassword::test(
            id(2),
            UserPassword::new("0123456789abcdefGHIJ", PasswordLength::Bytes20).unwrap(),
        ),
        0x47,
        &long,
    );
    for data in [&[][..], &[0, 0][..]] {
        assert_eq!(
            SetUserPassword::parse_success_response(data),
            if data.is_empty() {
                Ok(())
            } else {
                Err(UserResponseError::Length {
                    expected: 0,
                    actual: 2,
                })
            }
        );
    }
    assert_eq!(
        SetUserPrivilege::parse_success_response(&[1]),
        Err(UserResponseError::Length {
            expected: 0,
            actual: 1
        })
    );
    assert_eq!(SetUserAccess::parse_success_response(&[]), Ok(()));
}

#[test]
fn channel_access_options_are_independent_and_explicit() {
    let settings = ChannelAccessSettings {
        mode: SetChannelAccessMode::AlwaysAvailable,
        alerting_disabled: true,
        per_msg_auth_disabled: false,
        user_level_auth_disabled: true,
    };
    wire(
        SetChannelAccess::new(
            channel(),
            Some((ChannelAccessType::Volatile, settings)),
            Some((ChannelAccessType::NonVolatile, UserPrivilege::Administrator)),
        )
        .unwrap(),
        0x40,
        &[0x0e, 0xaa, 0x44],
    );
    wire(
        SetChannelAccess::new(
            channel(),
            None,
            Some((ChannelAccessType::Volatile, UserPrivilege::NoAccess)),
        )
        .unwrap(),
        0x40,
        &[0x0e, 0, 0x8f],
    );
    wire(
        SetChannelAccess::new(
            channel(),
            Some((ChannelAccessType::NonVolatile, settings)),
            None,
        )
        .unwrap(),
        0x40,
        &[0x0e, 0x6a, 0],
    );
    assert_eq!(
        SetChannelAccess::new(channel(), None, None).unwrap_err(),
        SetChannelAccessError::NoChanges
    );
    assert_eq!(SetChannelAccess::parse_success_response(&[]), Ok(()));
    assert_eq!(
        SetChannelAccess::parse_success_response(&[0]),
        Err(SetChannelAccessError::ResponseLength(1))
    );
    assert_eq!(
        GetChannelAccess::parse_success_response(&[0x02, 0x0f])
            .unwrap()
            .privilege_level_limit,
        ChannelPrivilegeLevel::NoAccess
    );
    assert_eq!(
        GetChannelAccess::parse_success_response(&[0x07, 0x0e])
            .unwrap()
            .privilege_level_limit,
        ChannelPrivilegeLevel::Unknown(14)
    );
}

#[test]
fn password_debug_never_contains_secret_even_in_message() {
    let pw = UserPassword::new("distinct-secret", PasswordLength::Bytes16).unwrap();
    assert!(!format!("{pw:?}").contains("distinct-secret"));
    let cmd = SetUserPassword::set(id(2), pw);
    assert!(!format!("{cmd:?}").contains("distinct-secret"));
    let message = Message::from(cmd);
    assert!(!format!("{message:?}").contains("distinct-secret"));
    assert!(!format!("{:?}", message.clone()).contains("distinct-secret"));
    assert_eq!(&message.data()[2..17], b"distinct-secret");
    assert!(format!("{:?}", Message::from(GetUserName::new(id(2)))).contains("2"));
    let reply = Message::new_response(NetFn::App, 0x47, b"distinct-secret".to_vec());
    assert!(!format!("{reply:?}").contains("distinct-secret"));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportError {
    Timeout,
}

struct Fixture {
    response: Option<Result<Response, TransportError>>,
    calls: Vec<(u8, u8, Vec<u8>, RequestTargetAddress)>,
}

impl Fixture {
    fn reply(cmd: u8, cc: u8, body: &[u8]) -> Self {
        let mut data = vec![cc];
        data.extend_from_slice(body);
        Self {
            response: Some(Ok(Response::new(
                Message::new_response(NetFn::App, cmd, data),
                1,
            )
            .unwrap())),
            calls: vec![],
        }
    }
}

impl IpmiConnection for Fixture {
    type SendError = TransportError;
    type RecvError = TransportError;
    type Error = TransportError;

    fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
        Err(TransportError::Timeout)
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        Err(TransportError::Timeout)
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.calls.push((
            request.netfn_raw(),
            request.cmd(),
            request.data().to_vec(),
            request.target(),
        ));
        self.response.take().unwrap_or(Err(TransportError::Timeout))
    }
}

#[test]
fn rejected_and_malformed_responses_preserve_completion_codes() {
    let mut ipmi = Ipmi::new(Fixture::reply(0x44, 0xd4, &[]));
    assert!(matches!(
        ipmi.send_recv(GetUserAccess::new(channel(), id(1))),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::InsufficientPrivilege,
            ..
        })
    ));
    assert_eq!(ipmi.inner_mut().calls.len(), 1);
    let mut ipmi = Ipmi::new(Fixture::reply(0x43, 0xd4, &[]));
    assert!(matches!(
        ipmi.send_recv(SetUserPrivilege::new(
            channel(),
            id(1),
            UserPrivilege::Operator
        )),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::InsufficientPrivilege,
            ..
        })
    ));
    let mut ipmi = Ipmi::new(Fixture::reply(0x47, 0x80, &[]));
    assert!(matches!(
        ipmi.send_recv(SetUserPassword::test(
            id(1),
            UserPassword::new("guess", PasswordLength::Bytes16).unwrap()
        )),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::CommandSpecific(0x80),
            ..
        })
    ));
    let mut ipmi = Ipmi::new(Fixture::reply(0x47, 0x81, &[]));
    assert!(matches!(
        ipmi.send_recv(SetUserPassword::test(
            id(1),
            UserPassword::new("guess", PasswordLength::Bytes16).unwrap()
        )),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::CommandSpecific(0x81),
            ..
        })
    ));
    let mut ipmi = Ipmi::new(Fixture::reply(0x47, 0x80, b"secret-echo"));
    let err = ipmi
        .send_recv(SetUserPassword::test(
            id(1),
            UserPassword::new("secret-echo", PasswordLength::Bytes16).unwrap(),
        ))
        .unwrap_err();
    assert!(matches!(
        err,
        IpmiError::Failed {
            completion_code: CompletionErrorCode::CommandSpecific(0x80),
            ref data,
            ..
        } if data.is_empty()
    ));
    assert!(!format!("{err:?}").contains("secret-echo"));
    let mut ipmi = Ipmi::new(Fixture::reply(0x47, 0, b"secret-echo"));
    let err = ipmi
        .send_recv(SetUserPassword::set(
            id(1),
            UserPassword::new("secret-echo", PasswordLength::Bytes16).unwrap(),
        ))
        .unwrap_err();
    assert!(matches!(
        err,
        IpmiError::Command {
            error: UserResponseError::Length { expected: 0, actual: 11 },
            completion_code: None,
            ref data,
            ..
        } if data.is_empty()
    ));
    assert!(!format!("{err:?}").contains("secret-echo"));
    let mut ipmi = Ipmi::new(Fixture::reply(0x40, 0x83, &[]));
    assert!(matches!(
        ipmi.send_recv(
            SetChannelAccess::new(
                channel(),
                None,
                Some((ChannelAccessType::Volatile, UserPrivilege::User))
            )
            .unwrap()
        ),
        Err(IpmiError::Failed {
            completion_code: CompletionErrorCode::CommandSpecific(0x83),
            ..
        })
    ));
    let mut ipmi = Ipmi::new(Fixture::reply(0x46, 0, b"short"));
    assert!(matches!(
        ipmi.send_recv(GetUserName::new(id(1))),
        Err(IpmiError::Command {
            error: UserResponseError::Length {
                expected: 16,
                actual: 5
            },
            completion_code: None,
            ..
        })
    ));
    let mut ipmi = Ipmi::new(Fixture::reply(0x45, 0, &[]));
    assert_eq!(
        ipmi.send_recv(SetUserName::new(id(2), "admin").unwrap()),
        Ok(())
    );
}

#[test]
fn uncertain_writes_are_single_shot_and_never_confused_with_host_control() {
    let commands = [
        Message::from(SetUserName::new(id(2), "user").unwrap()),
        Message::from(
            SetUserAccess::new(channel(), id(2), false, true, true, UserPrivilege::User, 0)
                .unwrap(),
        ),
        Message::from(SetUserPrivilege::new(channel(), id(2), UserPrivilege::User)),
        Message::from(SetUserPassword::set(
            id(2),
            UserPassword::new("secret", PasswordLength::Bytes16).unwrap(),
        )),
        Message::from(SetUserPassword::disable(id(2))),
        Message::from(
            SetChannelAccess::new(
                channel(),
                None,
                Some((ChannelAccessType::NonVolatile, UserPrivilege::User)),
            )
            .unwrap(),
        ),
    ];
    for msg in commands {
        let (netfn, cmd, bytes) = (msg.netfn_raw(), msg.cmd(), msg.data().to_vec());
        struct Raw(Message);
        impl From<Raw> for Message {
            fn from(raw: Raw) -> Message {
                raw.0
            }
        }
        impl IpmiCommand for Raw {
            type Output = ();
            type Error = ();
            fn parse_success_response(_: &[u8]) -> Result<(), ()> {
                Ok(())
            }
        }
        let mut ipmi = Ipmi::new(Fixture {
            response: None,
            calls: vec![],
        });
        assert!(matches!(
            ipmi.send_recv(Raw(msg)),
            Err(IpmiError::Connection(TransportError::Timeout))
        ));
        assert_eq!(
            ipmi.release().calls,
            [(
                netfn,
                cmd,
                bytes,
                RequestTargetAddress::Bmc(LogicalUnit::Zero)
            )]
        );
    }
}
