//! Generic Device Locator Record (SDR Type 10h)
//!
//! Reference: IPMI 2.0 Specification, Table 43-6 "SDR Type 10h - Generic Device Locator Record"

use crate::app::i2c::{I2cAddress, I2cBus, I2cBusKind, I2cValidationError, MasterWriteRead};
use crate::connection::LogicalUnit;
use crate::connection::{Address, Channel};
use crate::storage::sdr::record::{SensorId, TypeLengthRaw};

use super::{IdentifiableSensor, ParseError};
use std::num::NonZeroU8;

/// Record key for Generic Device Locator Record (SDR Type 10h).
///
/// Reference: IPMI 2.0 Specification, Table 43-6, bytes 6-8
/// (record data offsets 0-2).
#[derive(Debug, Clone)]
pub struct GenericDeviceRecordKey {
    /// 7-bit I2C Slave Address of device on the channel.
    pub device_access_address: u8,
    /// 7-bit I2C Slave Address on the device's bus.
    pub device_slave_address: u8,
    /// Channel number for the management controller used to access the device.
    pub channel_number: u8,
    /// Access LUN for Master Write-Read command.
    pub access_lun: LogicalUnit,
    /// Private bus ID if bus is private, None if device directly on IPMB.
    pub private_bus_id: Option<NonZeroU8>,
}

/// Generic Device Locator Record (SDR Type 10h).
///
/// This record is used to store the location and type information for devices
/// on the IPMB or management controller private busses that are neither IPMI
/// FRU devices nor IPMI management controllers.
///
/// Reference: IPMI 2.0 Specification, Section 43.7 and Table 43-6
#[derive(Debug, Clone)]
pub struct GenericDeviceLocator {
    /// Record key data.
    pub record_key: GenericDeviceRecordKey,
    /// Address span (number of addresses device occupies - 1).
    pub address_span: u8,
    /// Device Type code per IPMI Device Type Codes table.
    ///
    /// Reference: IPMI 2.0 Specification, Table 43-12 "Device Type Codes"
    pub device_type: u8,
    /// Device Type Modifier.
    ///
    /// Reference: IPMI 2.0 Specification, Table 43-6
    pub device_type_modifier: u8,
    /// Entity ID for the device.
    ///
    /// Reference: IPMI 2.0 Specification, Table 43-13 "Entity ID Codes"
    pub entity_id: u8,
    /// Entity Instance.
    ///
    /// Note: The IPMI spec only labels this as "Entity Instance" (Table 43-6)
    /// without the sensor SDR bit layout, so we keep it as a raw `u8`.
    pub entity_instance: u8,
    /// OEM reserved field.
    pub oem_reserved: u8,
    /// Device ID string.
    pub id_string: SensorId,
}

impl IdentifiableSensor for GenericDeviceLocator {
    fn id_string(&self) -> &SensorId {
        &self.id_string
    }

    fn entity_id(&self) -> u8 {
        self.entity_id
    }
}

impl GenericDeviceLocator {
    /// Build a bounded register read for a device at the locator's first address.
    ///
    /// The offset write changes the device's address pointer, not its inventory
    /// contents. Merely parsing/enumerating locators never sends a command.
    pub fn read(&self, offset: u8, count: usize) -> Result<MasterWriteRead, I2cValidationError> {
        self.read_at_address(0, offset, count)
    }

    /// Build a register read at one of the locator's addresses.
    pub fn read_at_address(
        &self,
        address_index: u8,
        offset: u8,
        count: usize,
    ) -> Result<MasterWriteRead, I2cValidationError> {
        self.read_raw_at_address(address_index, &[offset], count)
    }

    /// Build a read with a device-specific write prefix, which may be empty.
    /// Not all generic devices use a one-byte register offset.
    pub fn read_raw(
        &self,
        write_prefix: &[u8],
        count: usize,
    ) -> Result<MasterWriteRead, I2cValidationError> {
        self.read_raw_at_address(0, write_prefix, count)
    }

    /// Build a device-specific read at one of the locator's addresses.
    pub fn read_raw_at_address(
        &self,
        address_index: u8,
        write_prefix: &[u8],
        count: usize,
    ) -> Result<MasterWriteRead, I2cValidationError> {
        if count == 0 {
            return Err(I2cValidationError::EmptyRead);
        }
        self.command(address_index, write_prefix, count)
    }

    /// Build an explicit register write. No write happens until the caller
    /// sends this command; do not retry it if its outcome is uncertain.
    pub fn write(&self, offset: u8, data: &[u8]) -> Result<MasterWriteRead, I2cValidationError> {
        self.write_at_address(0, offset, data)
    }

    /// Build an explicit register write at one of the locator's addresses.
    pub fn write_at_address(
        &self,
        address_index: u8,
        offset: u8,
        data: &[u8],
    ) -> Result<MasterWriteRead, I2cValidationError> {
        if data.is_empty() {
            return Err(I2cValidationError::EmptyWrite);
        }
        let mut write = Vec::with_capacity(1 + data.len());
        write.push(offset);
        write.extend_from_slice(data);
        self.write_raw_at_address(address_index, &write)
    }

    /// Build an explicit device-specific write without assuming a register
    /// offset. The caller must decide whether it is safe to send.
    pub fn write_raw(&self, bytes: &[u8]) -> Result<MasterWriteRead, I2cValidationError> {
        self.write_raw_at_address(0, bytes)
    }

    /// Build an explicit device-specific write at a locator address.
    pub fn write_raw_at_address(
        &self,
        address_index: u8,
        bytes: &[u8],
    ) -> Result<MasterWriteRead, I2cValidationError> {
        if bytes.is_empty() {
            return Err(I2cValidationError::EmptyWrite);
        }
        self.command(address_index, bytes, 0)
    }

    fn command(
        &self,
        address_index: u8,
        write: &[u8],
        read: usize,
    ) -> Result<MasterWriteRead, I2cValidationError> {
        if address_index > self.address_span || address_index > 7 {
            return Err(I2cValidationError::AddressOutsideSpan(address_index));
        }
        let key = &self.record_key;
        let address = key
            .device_slave_address
            .checked_add(address_index)
            .ok_or(I2cValidationError::InvalidAddress(key.device_slave_address))?;
        let address = I2cAddress::from_7bit(address)?;
        let controller = I2cAddress::from_7bit(key.device_access_address)?;
        let channel = Channel::new(key.channel_number)
            .ok_or(I2cValidationError::InvalidChannel(key.channel_number))?;
        let bus = I2cBus::new(
            key.channel_number,
            key.private_bus_id
                .map_or(I2cBusKind::Public, |id| I2cBusKind::Private(id.get())),
        )?;
        let command = MasterWriteRead::new(bus, address, write.to_vec(), read)?;
        if controller.wire_value() == 0x20 && key.channel_number == 0 {
            // This is the local BMC; its LUN can still be nonzero.
            Ok(command.with_local_lun(key.access_lun))
        } else {
            Ok(command.with_controller(Address(controller.wire_value()), channel, key.access_lun))
        }
    }

    /// Parse a Generic Device Locator Record from raw SDR record data.
    ///
    /// The record data layout is defined in IPMI 2.0 Specification, Table 43-6.
    /// Offsets below are relative to the record data payload (table bytes 6+).
    ///
    /// | Offset | Field                              |
    /// |--------|-----------------------------------|
    /// | 0      | Device Access Address \[7:1\], \[0\] reserved |
    /// | 1      | Device Slave Address, channel ms-bit in \[0\] |
    /// | 2      | \[7:5\] Channel Number (ls-3 bits), \[4:3\] Access LUN, \[2:0\] Private Bus ID |
    /// | 3      | \[7:3\] reserved, \[2:0\] Address Span |
    /// | 4      | Reserved                          |
    /// | 5      | Device Type (Table 43-12)         |
    /// | 6      | Device Type Modifier (Table 43-12)|
    /// | 7      | Entity ID (Table 43-13)           |
    /// | 8      | Entity Instance                   |
    /// | 9      | OEM                               |
    /// | 10     | Device ID String Type/Length      |
    /// | 11+    | Device ID String bytes            |
    pub fn parse(record_data: &[u8]) -> Result<Self, ParseError> {
        if record_data.len() < 11 {
            return Err(ParseError::NotEnoughData);
        }

        // Byte 0: Device Access Address
        // [7:1] = 7-bit I2C slave address of device on channel
        // [0] = reserved
        //
        // Reference: IPMI 2.0 Spec, Table 43-6
        let device_access_address = record_data[0] >> 1;

        // Byte 1: Device Slave Address / Device ID
        //
        // Reference: IPMI 2.0 Spec, Table 43-6
        let device_slave_address = record_data[1] >> 1;

        // Byte 2: Access LUN / Bus ID
        // [7:5] = Channel Number (ls-3 bits)
        // [4:3] = LUN for Master Write-Read command
        // [2:0] = Private bus ID (0 if device directly on IPMB)
        //
        // Reference: IPMI 2.0 Spec, Table 43-6
        let access_lun = LogicalUnit::from_low_bits(record_data[2] >> 3);
        let private_bus_id = NonZeroU8::new(record_data[2] & 0b111);
        let channel_number = ((record_data[1] & 0b1) << 3) | (record_data[2] >> 5);

        // Byte 3: Address Span
        // [7:3] = reserved
        // [2:0] = Address span (number of addresses device uses - 1)
        //
        // Reference: IPMI 2.0 Spec, Table 43-6
        let address_span = record_data[3] & 0b111;

        // Byte 4: Reserved
        //
        // Reference: IPMI 2.0 Spec, Table 43-6

        // Byte 5: Device Type
        // Device type code per Table 43-12 "Device Type Codes"
        //
        // Reference: IPMI 2.0 Spec, Table 43-6 and Table 43-12
        let device_type = record_data[5];

        // Byte 6: Device Type Modifier
        //
        // Reference: IPMI 2.0 Spec, Table 43-6
        let device_type_modifier = record_data[6];

        // Byte 7: Entity ID
        //
        // Reference: IPMI 2.0 Spec, Table 43-6 and Table 43-13
        let entity_id = record_data[7];

        // Byte 8: Entity Instance
        //
        // Reference: IPMI 2.0 Spec, Table 43-6
        let entity_instance = record_data[8];

        // Byte 9: OEM
        // Reserved for OEM use
        //
        // Reference: IPMI 2.0 Spec, Table 43-6
        let oem_reserved = record_data[9];

        // Byte 10: Device ID String Type/Length
        // [7:6] = Type code (00=Unicode, 01=BCD+, 10=6-bit ASCII, 11=8-bit ASCII+Latin1)
        // [4:0] = Length of string in bytes
        // Byte 11+: Device ID String bytes
        //
        // Reference: IPMI 2.0 Spec, Table 43-6 and Section 43.15 "Type/Length Byte Format"
        let id_string_type_len = record_data[10];
        let id_string_bytes = &record_data[11..];
        let id_string = TypeLengthRaw::new(id_string_type_len, id_string_bytes).try_into()?;

        let record_key = GenericDeviceRecordKey {
            device_access_address,
            device_slave_address,
            channel_number,
            access_lun,
            private_bus_id,
        };

        Ok(Self {
            record_key,
            address_span,
            device_type,
            device_type_modifier,
            entity_id,
            entity_instance,
            oem_reserved,
            id_string,
        })
    }

    pub fn id_string(&self) -> &SensorId {
        &self.id_string
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::i2c::I2cValidationError;
    use crate::connection::{IpmiCommand, Message};

    fn locator(access: u8, slave: u8, channel_bus_lun: u8) -> GenericDeviceLocator {
        let data = [
            access,
            slave,
            channel_bus_lun,
            1,
            0,
            0x09,
            0,
            7,
            1,
            0,
            0xc3,
            b'M',
            b'E',
            b'M',
        ];
        GenericDeviceLocator::parse(&data).unwrap()
    }

    fn fixture(text: &str) -> GenericDeviceLocator {
        let data: Vec<u8> = text
            .split_ascii_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect();
        GenericDeviceLocator::parse(&data).unwrap()
    }

    #[test]
    fn private_and_public_locators_and_explicit_writes() {
        let local = fixture(include_str!(
            "../../../../tests/fixtures/locators/private.hex"
        ));
        let read = local.read_at_address(1, 0x70, 64).unwrap();
        assert_eq!(read.target(), None);
        assert_eq!(read.target_lun(), LogicalUnit::One);
        let message: Message = read.into();
        assert_eq!(message.data(), &[7, 0xa2, 64, 0x70]);
        assert_eq!(
            local.read_at_address(2, 0, 1).unwrap_err(),
            I2cValidationError::AddressOutsideSpan(2)
        );
        assert_eq!(local.read(0, 0).unwrap_err(), I2cValidationError::EmptyRead);
        assert_eq!(
            local.write(0, &[]).unwrap_err(),
            I2cValidationError::EmptyWrite
        );
        assert!(matches!(
            local.write(0, &[0; 64]),
            Err(I2cValidationError::TransferTooLong { write: 65, read: 0 })
        ));
        let write: Message = local.write(0x40, &[0xa5; 63]).unwrap().into();
        assert_eq!(write.data()[..4], [7, 0xa0, 0, 0x40]);
        assert_eq!(write.data().len(), 67);
        let read: Message = local.read_raw(&[], 1).unwrap().into();
        assert_eq!(read.data(), &[7, 0xa0, 1]);
        let read: Message = local.read_raw(&[0, 0x40], 2).unwrap().into();
        assert_eq!(read.data(), &[7, 0xa0, 2, 0, 0x40]);
        let write: Message = local.write_raw(&[0x55]).unwrap().into();
        assert_eq!(write.data(), &[7, 0xa0, 0, 0x55]);
        assert_eq!(
            local.write_raw(&[]).unwrap_err(),
            I2cValidationError::EmptyWrite
        );

        let remote = fixture(include_str!(
            "../../../../tests/fixtures/locators/public.hex"
        ));
        let read = remote.read(0, 1).unwrap();
        assert_eq!(
            read.target(),
            Some((Address(0x22), Channel::new(2).unwrap()))
        );
        assert_eq!(read.target_lun(), LogicalUnit::Zero);
        let message: Message = read.into();
        assert_eq!(message.data(), &[0x20, 0xb0, 1, 0]);
        assert_eq!(remote.device_type, 0x09);
        assert_eq!(
            locator(0x20, 0xa0, 0x80).read(0, 1).unwrap().target(),
            Some((Address(0x20), Channel::new(4).unwrap()))
        );
    }

    #[test]
    fn reject_bad_locator_addresses_and_channel() {
        assert_eq!(
            locator(0x20, 0, 0).read(0, 1).unwrap_err(),
            I2cValidationError::InvalidAddress(0)
        );
        assert_eq!(
            locator(0, 0xa0, 0).read(0, 1).unwrap_err(),
            I2cValidationError::InvalidAddress(0)
        );
        // Channel 12 is reserved in the connection API; its high bit is in
        // the low bit of the locator's slave-address byte.
        assert_eq!(
            locator(0x20, 0xa1, 0x80).read(0, 1).unwrap_err(),
            I2cValidationError::InvalidChannel(12)
        );
    }
}
