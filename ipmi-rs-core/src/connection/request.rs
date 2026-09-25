use crate::connection::{Address, Channel, LogicalUnit, NetFn};

use super::Message;

/// An IPMI request message.
pub struct Request {
    target: RequestTargetAddress,
    message: Message,
}

impl Request {
    /// Create a new IPMI request message.
    ///
    /// The netfn for `request` should be of the `request` variant, see [`Message::new_request`].
    // TODO: don't accept `Message` directly (could be malformed?)
    pub const fn new(request: Message, target: RequestTargetAddress) -> Self {
        Self {
            target,
            message: request,
        }
    }

    /// Get the netfn for the request.
    pub fn netfn(&self) -> NetFn {
        self.message.netfn()
    }

    /// Get the raw value of the netfn for the request.
    pub fn netfn_raw(&self) -> u8 {
        self.message.netfn_raw()
    }

    /// Get the command value for the request.
    pub fn cmd(&self) -> u8 {
        self.message.cmd
    }

    /// Get a shared reference to the data of the request (does not include netfn or command).
    pub fn data(&self) -> &[u8] {
        self.message.data()
    }

    /// Get a mutable reference to the data of the request (does not include netfn or command).
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.message.data_mut()
    }

    /// Get the target for the request.
    pub fn target(&self) -> RequestTargetAddress {
        self.target
    }
}

/// The target address of a request.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RequestTargetAddress {
    /// A logical unit on the BMC (Board Management Controller).
    Bmc(LogicalUnit),
    /// An address on the BMC or IPMB.
    BmcOrIpmb(Address, Channel, LogicalUnit),
    /// Route through the BMC to an IPMB target, optionally via a second controller.
    ///
    /// Unlike `BmcOrIpmb`, this route always uses Send Message, even if the
    /// target's address is the BMC's own address.
    Bridged {
        /// Destination of the original command.
        target: IpmbTarget,
        /// Optional first hop; it forwards to `target` on `target.channel`.
        transit: Option<IpmbTarget>,
    },
}

/// An IPMB address, outgoing channel, and responder LUN for one bridge hop.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct IpmbTarget {
    /// Even, unicast IPMB slave address.
    pub address: Address,
    /// IPMB channel used to reach this hop (primary or numbered).
    pub channel: Channel,
    /// Responder LUN for this hop.
    pub lun: LogicalUnit,
}

impl IpmbTarget {
    /// Construct a bridge hop without choosing a transport.
    pub const fn new(address: Address, channel: Channel, lun: LogicalUnit) -> Self {
        Self {
            address,
            channel,
            lun,
        }
    }
}

impl RequestTargetAddress {
    /// Get the logical unit for the target address.
    pub fn lun(&self) -> LogicalUnit {
        match self {
            RequestTargetAddress::Bmc(lun) | RequestTargetAddress::BmcOrIpmb(_, _, lun) => *lun,
            RequestTargetAddress::Bridged { target, .. } => target.lun,
        }
    }
}
