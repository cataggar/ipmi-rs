//! Multi-step LAN configuration writes without retrying ambiguous mutations.

use crate::connection::Channel;

use super::{
    Ipv6Router, LanConfigError, LanConfigParameter, LanConfigParameterRequest, LanSetInProgress,
    SetLanConfigParameters,
};

/// Apply one LAN configuration transaction: begin, ordered writes, commit, cleanup.
///
/// All requests are validated *before* begin. Failed begin is followed only by
/// cleanup; failed write stops subsequent writes and skips commit. Every path
/// after begin attempts Set Complete, including uncertain connection failures.
/// A failed cleanup is returned alongside the primary error. No command is
/// retried. Applications must confirm network-disruptive changes separately.
pub fn lan_write_guarded<E: core::fmt::Debug>(
    mut send: impl FnMut(SetLanConfigParameters) -> Result<(), E>,
    channel: Channel,
    writes: &[(LanConfigParameter, LanConfigParameterRequest)],
) -> Result<(), LanWriteError<E>> {
    let mut validated = Vec::with_capacity(writes.len());
    for (parameter, request) in writes {
        if *parameter == LanConfigParameter::SetInProgress {
            return Err(LanWriteError::Validation(
                LanConfigError::MismatchedParameter,
            ));
        }
        if let Some(associated) = request.parameter() {
            if associated != *parameter {
                return Err(LanWriteError::Validation(
                    LanConfigError::MismatchedParameter,
                ));
            }
        }
        let bytes = request.try_to_bytes().map_err(LanWriteError::Validation)?;
        validated.push(SetLanConfigParameters::new(channel, *parameter, bytes));
    }
    if validated.is_empty() {
        return Ok(());
    }
    let status = |value| {
        SetLanConfigParameters::checked(channel, LanConfigParameterRequest::SetState(value))
            .expect("valid state")
    };
    if let Err(error) = send(status(LanSetInProgress::InProgress)) {
        let cleanup = send(status(LanSetInProgress::Complete)).err();
        return Err(LanWriteError::Begin { error, cleanup });
    }
    for (index, command) in validated.into_iter().enumerate() {
        if let Err(error) = send(command) {
            let cleanup = send(status(LanSetInProgress::Complete)).err();
            return Err(LanWriteError::Uncertain {
                write: Some((index, error)),
                commit: None,
                cleanup,
            });
        }
    }
    let commit = send(status(LanSetInProgress::CommitWrite)).err();
    let cleanup = send(status(LanSetInProgress::Complete)).err();
    if commit.is_none() && cleanup.is_none() {
        Ok(())
    } else {
        Err(LanWriteError::Uncertain {
            write: None,
            commit,
            cleanup,
        })
    }
}

/// Transaction failure; an unacknowledged write or cleanup may have succeeded.
#[derive(Debug)]
pub enum LanWriteError<E> {
    /// Invalid requests: nothing was sent.
    Validation(LanConfigError),
    /// Begin failed, and a cleanup was still attempted.
    Begin { error: E, cleanup: Option<E> },
    /// Write, commit, or cleanup failed; inspect each outcome. Never retry blindly.
    Uncertain {
        write: Option<(usize, E)>,
        commit: Option<E>,
        cleanup: Option<E>,
    },
}

/// Return four independently addressable static IPv6 router writes.
///
/// Static router selectors 1 and 2 use distinct parameters; no set selector
/// byte is present in their write payloads.
pub fn ipv6_static_router_writes(
    router_number: u8,
    router: Ipv6Router,
) -> Result<Vec<(LanConfigParameter, LanConfigParameterRequest)>, LanConfigError> {
    router.validate()?;
    use LanConfigParameter as P;
    use LanConfigParameterRequest as R;
    Ok(match router_number {
        1 => vec![
            (
                P::Ipv6StaticRouter1Address,
                R::Ipv6StaticRouter1Address(router.address),
            ),
            (P::Ipv6StaticRouter1Mac, R::Ipv6StaticRouter1Mac(router.mac)),
            (
                P::Ipv6StaticRouter1PrefixLength,
                R::Ipv6StaticRouter1PrefixLength(router.prefix_length),
            ),
            (
                P::Ipv6StaticRouter1Prefix,
                R::Ipv6StaticRouter1Prefix(router.prefix),
            ),
        ],
        2 => vec![
            (
                P::Ipv6StaticRouter2Address,
                R::Ipv6StaticRouter2Address(router.address),
            ),
            (P::Ipv6StaticRouter2Mac, R::Ipv6StaticRouter2Mac(router.mac)),
            (
                P::Ipv6StaticRouter2PrefixLength,
                R::Ipv6StaticRouter2PrefixLength(router.prefix_length),
            ),
            (
                P::Ipv6StaticRouter2Prefix,
                R::Ipv6StaticRouter2Prefix(router.prefix),
            ),
        ],
        value => return Err(LanConfigError::InvalidValue(value)),
    })
}
