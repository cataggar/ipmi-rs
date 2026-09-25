//! Explicit, bounded remote reads of SPD EEPROM pages.

use crate::{
    app::{
        i2c::{I2cAddress, I2cBus, I2cError, MasterWriteRead, MAX_TRANSFER},
        spd::{SpdError, SpdPage, PAGE_SIZE},
    },
    connection::IpmiConnection,
    Ipmi, IpmiError,
};

/// An SPD read validation or transport error.
#[derive(Debug)]
pub enum SpdReadError<CON> {
    /// SPD EEPROMs are at 8-bit write addresses A0h through AEh.
    InvalidAddress(u8),
    /// Chunk size must be between 1 and the I2C maximum (64).
    InvalidChunkSize(usize),
    /// An invalid page was requested.
    InvalidPage(SpdError),
    /// I2C command or connection failure; the read stops immediately.
    Transfer(IpmiError<CON, I2cError>),
}

impl<CON: IpmiConnection> Ipmi<CON> {
    /// Read one full 256-byte SPD page with bounded I2C transfers.
    ///
    /// `LegacyBase` does not select a page (suitable for DDR3 and earlier).
    /// `Ddr4(0/1)` first performs an address-only write to the volatile page
    /// selector (6Ch/6Eh), then reads the requested page. Page selection and
    /// register-pointer writes change transient I2C state, not SPD EEPROM
    /// contents. The method never retries any transfer after an error.
    /// Controllers not directly reachable via this connection need bridged
    /// routing (issue #13).
    pub fn read_spd_page(
        &mut self,
        bus: I2cBus,
        address: I2cAddress,
        page: SpdPage,
        chunk_size: usize,
    ) -> Result<[u8; PAGE_SIZE], SpdReadError<CON::Error>> {
        if !(0xa0..=0xae).contains(&address.wire_value()) {
            return Err(SpdReadError::InvalidAddress(address.wire_value()));
        }
        if !(1..=MAX_TRANSFER).contains(&chunk_size) {
            return Err(SpdReadError::InvalidChunkSize(chunk_size));
        }
        let selector = page.selector().map_err(SpdReadError::InvalidPage)?;
        if let Some(address) = selector {
            let select = MasterWriteRead::new(bus, I2cAddress::new(address).unwrap(), [], 0)
                .expect("zero-byte page select is within transfer limits");
            self.send_recv(select).map_err(SpdReadError::Transfer)?;
        }
        let mut result = [0; PAGE_SIZE];
        for offset in (0..PAGE_SIZE).step_by(chunk_size) {
            let count = chunk_size.min(PAGE_SIZE - offset);
            let read = MasterWriteRead::new(bus, address, [offset as u8], count)
                .expect("chunk size was validated");
            let bytes = self.send_recv(read).map_err(SpdReadError::Transfer)?;
            result[offset..offset + count].copy_from_slice(&bytes);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{IpmiConnection, Message, NetFn, Request, Response};

    struct Mock {
        requests: Vec<Vec<u8>>,
        fail_on: Option<usize>,
        completion: u8,
    }

    impl IpmiConnection for Mock {
        type SendError = std::io::Error;
        type RecvError = std::io::Error;
        type Error = std::io::Error;

        fn send(&mut self, _: &mut Request) -> Result<(), Self::SendError> {
            unreachable!()
        }

        fn recv(&mut self) -> Result<Response, Self::RecvError> {
            unreachable!()
        }

        fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
            assert_eq!(request.netfn(), NetFn::App);
            assert_eq!(request.cmd(), 0x52);
            let data = request.data().to_vec();
            self.requests.push(data.clone());
            let failing = self.fail_on == Some(self.requests.len());
            let cc = if failing { self.completion } else { 0 };
            let bytes = if cc != 0 || data[2] == 0 {
                vec![]
            } else {
                vec![data[3]; usize::from(data[2]) - usize::from(failing)]
            };
            let message =
                Message::new_response(NetFn::App, 0x52, std::iter::once(cc).chain(bytes).collect());
            Ok(Response::new(message, 0).unwrap())
        }
    }

    #[test]
    fn read_both_pages_with_selection_and_final_short_chunk() {
        let bus = I2cBus::new(2, crate::app::i2c::I2cBusKind::Private(1)).unwrap();
        let address = I2cAddress::new(0xa0).unwrap();
        let mut ipmi = Ipmi::new(Mock {
            requests: vec![],
            fail_on: None,
            completion: 0,
        });
        let base = ipmi
            .read_spd_page(bus, address, SpdPage::LegacyBase, 63)
            .unwrap();
        assert_eq!(&base[..63], &[0; 63]);
        assert_eq!(base[63], 63);
        assert_eq!(ipmi.inner_mut().requests[4], vec![0x23, 0xa0, 4, 252]);
        assert_eq!(ipmi.inner_mut().requests.len(), 5);
        let upper = ipmi
            .read_spd_page(bus, address, SpdPage::ddr4(1).unwrap(), 64)
            .unwrap();
        assert_eq!(upper[64], 64);
        assert_eq!(ipmi.inner_mut().requests[5], vec![0x23, 0x6e, 0]);
        assert_eq!(ipmi.inner_mut().requests[6], vec![0x23, 0xa0, 64, 0]);
        assert_eq!(ipmi.inner_mut().requests.len(), 10);
    }

    #[test]
    fn stop_on_short_read_or_i2c_error_without_retry() {
        let bus = I2cBus::new(0, crate::app::i2c::I2cBusKind::Public).unwrap();
        let address = I2cAddress::new(0xa0).unwrap();
        let mut ipmi = Ipmi::new(Mock {
            requests: vec![],
            fail_on: Some(2),
            completion: 0,
        });
        assert!(matches!(
            ipmi.read_spd_page(bus, address, SpdPage::LegacyBase, 64),
            Err(SpdReadError::Transfer(IpmiError::Command {
                error: I2cError::InvalidLength {
                    expected: 64,
                    actual: 63
                },
                ..
            }))
        ));
        assert_eq!(ipmi.inner_mut().requests.len(), 2);

        let mut ipmi = Ipmi::new(Mock {
            requests: vec![],
            fail_on: Some(1),
            completion: 0x84,
        });
        assert!(matches!(
            ipmi.read_spd_page(bus, address, SpdPage::Ddr4(1), 64),
            Err(SpdReadError::Transfer(IpmiError::Command {
                error: I2cError::TruncatedRead,
                ..
            }))
        ));
        assert_eq!(ipmi.inner_mut().requests, vec![vec![0, 0x6e, 0]]);
        assert!(matches!(
            ipmi.read_spd_page(bus, I2cAddress::new(0x6c).unwrap(), SpdPage::LegacyBase, 64),
            Err(SpdReadError::InvalidAddress(0x6c))
        ));
        assert!(matches!(
            ipmi.read_spd_page(bus, address, SpdPage::LegacyBase, 0),
            Err(SpdReadError::InvalidChunkSize(0))
        ));
        assert_eq!(ipmi.inner_mut().requests.len(), 1);
    }
}
