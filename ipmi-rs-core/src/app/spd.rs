//! Read-only Serial Presence Detect (SPD) image decoding.
//!
//! Image lengths are complete 256-byte pages. Unknown bytes and unsupported
//! generations remain available in [`Spd::raw`]. This decoder never sends
//! commands or changes device contents.

/// Bytes in one SPD EEPROM page.
pub const PAGE_SIZE: usize = 256;

/// Which SPD page to read from an I2C EEPROM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpdPage {
    /// Legacy (DDR3 or earlier) page 0, without a page-select transaction.
    LegacyBase,
    /// DDR4 page 0 or 1, with an explicit volatile page-select transaction.
    Ddr4(u8),
}

impl SpdPage {
    /// Validated DDR4 page number.
    pub fn ddr4(page: u8) -> Result<Self, SpdError> {
        if page > 1 {
            Err(SpdError::InvalidPage(page))
        } else {
            Ok(Self::Ddr4(page))
        }
    }

    /// Return the DDR4 page-select device write address, if required.
    pub fn selector(self) -> Result<Option<u8>, SpdError> {
        match self {
            Self::LegacyBase => Ok(None),
            Self::Ddr4(0) => Ok(Some(0x6c)),
            Self::Ddr4(1) => Ok(Some(0x6e)),
            Self::Ddr4(other) => Err(SpdError::InvalidPage(other)),
        }
    }
}

/// SPD memory generation. Unrecognized codes retain their byte value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpdMemoryType {
    /// DDR SDRAM (07h).
    Ddr,
    /// DDR2 SDRAM (08h).
    Ddr2,
    /// DDR3 SDRAM (0Bh).
    Ddr3,
    /// DDR4 SDRAM (0Ch).
    Ddr4,
    /// Any other or future memory type.
    Other(u8),
}

impl From<u8> for SpdMemoryType {
    fn from(value: u8) -> Self {
        match value {
            0x07 => Self::Ddr,
            0x08 => Self::Ddr2,
            0x0b => Self::Ddr3,
            0x0c => Self::Ddr4,
            other => Self::Other(other),
        }
    }
}

/// Error validating an SPD page or image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpdError {
    /// A page number other than DDR4 page 0 or 1.
    InvalidPage(u8),
    /// The image does not consist of one or two complete 256-byte pages.
    InvalidLength(usize),
    /// A second page was provided for a generation without DDR4 page selection.
    UnexpectedPage,
    /// DDR4's header declares a 512-byte device, but page 1 was omitted.
    MissingPage,
}

/// Decoded SPD fields; unsupported or invalid values are left as `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpdDetails {
    /// Raw module type byte (JEDEC generation-specific).
    pub module_type: Option<u8>,
    /// Module capacity in MiB, if its density and bus/device widths are valid.
    pub capacity_mib: Option<u32>,
    /// Optional eight-bit ECC extension width, when the field is recognized.
    pub ecc_width_bits: Option<u8>,
    /// Raw JEDEC manufacturer ID, including the continuation count.
    pub manufacturer_jedec_id: Option<[u8; 2]>,
    /// Four raw serial-number bytes.
    pub serial_number: Option<[u8; 4]>,
    /// Raw fixed-width part-number field; spaces and unknown bytes are retained.
    pub part_number: Option<Vec<u8>>,
}

/// SPD image and safely decoded metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spd {
    /// All unmodified bytes, including unknown/vendor-defined fields.
    pub raw: Vec<u8>,
    /// JEDEC memory type with unknown codes preserved.
    pub memory_type: SpdMemoryType,
    /// Recognized DDR3/DDR4 metadata (other generations keep their raw image).
    pub details: SpdDetails,
}

impl Spd {
    /// Decode one or two complete pages. DDR4 headers advertising two pages
    /// require both before decoding; older generations only accept one.
    pub fn decode(raw: impl Into<Vec<u8>>) -> Result<Self, SpdError> {
        let raw = raw.into();
        if raw.len() != PAGE_SIZE && raw.len() != PAGE_SIZE * 2 {
            return Err(SpdError::InvalidLength(raw.len()));
        }
        let memory_type = SpdMemoryType::from(raw[2]);
        match memory_type {
            SpdMemoryType::Ddr4 if (raw[0] >> 4) & 7 == 2 && raw.len() == PAGE_SIZE => {
                return Err(SpdError::MissingPage)
            }
            SpdMemoryType::Ddr | SpdMemoryType::Ddr2 | SpdMemoryType::Ddr3
                if raw.len() != PAGE_SIZE =>
            {
                return Err(SpdError::UnexpectedPage)
            }
            _ => {}
        }
        let mut details = SpdDetails::default();
        match memory_type {
            SpdMemoryType::Ddr3 => {
                details.module_type = Some(raw[3] & 0x0f);
                details.capacity_mib =
                    module_capacity(raw[4] & 0x0f, raw[8] & 7, raw[7] & 7, (raw[7] >> 3) & 7, 6);
                details.ecc_width_bits = ecc_width((raw[8] >> 3) & 3);
                details.manufacturer_jedec_id = Some([raw[117], raw[118]]);
                details.serial_number = Some(raw[122..126].try_into().unwrap());
                details.part_number = Some(raw[128..146].to_vec());
            }
            SpdMemoryType::Ddr4 => {
                details.module_type = Some(raw[3] & 0x0f);
                let ranks = (raw[12] >> 3) & 7;
                let ranks = if raw[6] & 3 == 2 {
                    (u32::from(ranks) + 1) * (u32::from((raw[6] >> 4) & 7) + 1)
                } else {
                    u32::from(ranks) + 1
                };
                details.capacity_mib =
                    module_capacity_with_ranks(raw[4] & 0x0f, raw[13] & 7, raw[12] & 7, ranks, 9);
                details.ecc_width_bits = ecc_width((raw[13] >> 3) & 3);
                if raw.len() == PAGE_SIZE * 2 {
                    details.manufacturer_jedec_id = Some([raw[320], raw[321]]);
                    details.serial_number = Some(raw[325..329].try_into().unwrap());
                    details.part_number = Some(raw[329..349].to_vec());
                }
            }
            _ => {}
        }
        Ok(Self {
            raw,
            memory_type,
            details,
        })
    }
}

fn ecc_width(code: u8) -> Option<u8> {
    match code {
        0 => Some(0),
        1 => Some(8),
        _ => None,
    }
}

fn module_capacity(
    density: u8,
    bus: u8,
    device: u8,
    ranks_minus_one: u8,
    max_density: u8,
) -> Option<u32> {
    module_capacity_with_ranks(
        density,
        bus,
        device,
        u32::from(ranks_minus_one) + 1,
        max_density,
    )
}

fn module_capacity_with_ranks(
    density: u8,
    bus: u8,
    device: u8,
    ranks: u32,
    max_density: u8,
) -> Option<u32> {
    if density > max_density || bus > 3 || device > 3 {
        return None;
    }
    let density_mbit = match density {
        8 if max_density == 9 => 12 * 1024,
        9 if max_density == 9 => 24 * 1024,
        _ => 256_u32.checked_shl(u32::from(density))?,
    };
    let bus_width = 8_u32.checked_shl(u32::from(bus))?;
    let device_width = 4_u32.checked_shl(u32::from(device))?;
    if device_width > bus_width {
        return None;
    }
    (density_mbit / 8)
        .checked_mul(bus_width / device_width)?
        .checked_mul(ranks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(text: &str, size: usize) -> Vec<u8> {
        let mut data = vec![0; size];
        for line in text.lines().filter(|line| !line.is_empty()) {
            let (index, value) = line.split_once(' ').unwrap();
            data[index.parse::<usize>().unwrap()] = u8::from_str_radix(value, 16).unwrap();
        }
        data
    }

    #[test]
    fn generations_and_unknown_fields() {
        let ddr2 = Spd::decode(fixture(
            include_str!("../../tests/fixtures/spd/ddr2.hex"),
            256,
        ))
        .unwrap();
        assert_eq!(ddr2.memory_type, SpdMemoryType::Ddr2);
        assert_eq!(ddr2.raw[17], 0x42);
        assert_eq!(ddr2.details.capacity_mib, None);

        let ddr3 = Spd::decode(fixture(
            include_str!("../../tests/fixtures/spd/ddr3.hex"),
            256,
        ))
        .unwrap();
        assert_eq!(ddr3.memory_type, SpdMemoryType::Ddr3);
        assert_eq!(ddr3.details.capacity_mib, Some(8192));
        assert_eq!(ddr3.details.ecc_width_bits, Some(8));
        assert_eq!(ddr3.details.manufacturer_jedec_id, Some([0x80, 0x2c]));
        assert_eq!(ddr3.raw[200], 0xaa);

        let ddr4 = Spd::decode(fixture(
            include_str!("../../tests/fixtures/spd/ddr4.hex"),
            512,
        ))
        .unwrap();
        assert_eq!(ddr4.memory_type, SpdMemoryType::Ddr4);
        assert_eq!(ddr4.details.capacity_mib, Some(16384));
        assert_eq!(ddr4.details.serial_number, Some([0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(ddr4.raw[400], 0x55);

        let mut unknown = ddr2.raw;
        unknown[2] = 0x12;
        unknown[10] = 0xf4;
        let decoded = Spd::decode(unknown.clone()).unwrap();
        assert_eq!(decoded.memory_type, SpdMemoryType::Other(0x12));
        assert_eq!(decoded.raw, unknown);
    }

    #[test]
    fn page_and_image_validation() {
        let ddr4 = fixture(include_str!("../../tests/fixtures/spd/ddr4.hex"), 512);
        assert_eq!(Spd::decode(&ddr4[..256]), Err(SpdError::MissingPage));
        assert_eq!(Spd::decode(&ddr4[..255]), Err(SpdError::InvalidLength(255)));
        let mut ddr3 = vec![0; 512];
        ddr3[2] = 0x0b;
        assert_eq!(Spd::decode(ddr3), Err(SpdError::UnexpectedPage));
        assert_eq!(SpdPage::ddr4(2), Err(SpdError::InvalidPage(2)));
        assert_eq!(
            SpdPage::Ddr4(255).selector(),
            Err(SpdError::InvalidPage(255))
        );
        assert_eq!(SpdPage::ddr4(1).unwrap().selector(), Ok(Some(0x6e)));
        assert_eq!(SpdPage::LegacyBase.selector(), Ok(None));
    }

    #[test]
    fn malformed_density_preserves_raw_and_avoids_overflow() {
        let mut bytes = fixture(include_str!("../../tests/fixtures/spd/ddr3.hex"), 256);
        bytes[4] = 0xff;
        let spd = Spd::decode(bytes.clone()).unwrap();
        assert_eq!(spd.details.capacity_mib, None);
        assert_eq!(spd.raw, bytes);
    }

    #[test]
    fn ddr4_non_power_of_two_densities() {
        let mut bytes = fixture(include_str!("../../tests/fixtures/spd/ddr4.hex"), 512);
        for (density_code, capacity_mib) in [(8, 24_576), (9, 49_152)] {
            bytes[4] = density_code;
            let spd = Spd::decode(bytes.clone()).unwrap();
            assert_eq!(spd.details.capacity_mib, Some(capacity_mib));
            assert_eq!(spd.raw, bytes);
        }
        bytes[4] = 0x0a;
        assert_eq!(Spd::decode(bytes).unwrap().details.capacity_mib, None);
    }
}
