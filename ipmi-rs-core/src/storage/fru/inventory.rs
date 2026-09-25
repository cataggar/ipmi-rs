//! Checked decoding of a complete FRU inventory image.

/// A malformed inventory image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FruParseError {
    /// The image or an area/record/field ends prematurely.
    Truncated,
    /// Unknown or invalid FRU format version.
    Version,
    /// The common header, an area, or a multirecord failed its checksum.
    Checksum,
    /// An area offset or length overlaps another area or is outside the image.
    Layout,
    /// Area/record metadata, required fields, or a field terminator is invalid.
    Field,
}

/// Offsets from the checked common header, expressed as byte offsets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FruHeader {
    /// Internal use area.
    pub internal_use: Option<usize>,
    /// Chassis information area.
    pub chassis: Option<usize>,
    /// Board information area.
    pub board: Option<usize>,
    /// Product information area.
    pub product: Option<usize>,
    /// Multirecord area.
    pub multirecord: Option<usize>,
}

impl FruHeader {
    fn parse(image: &[u8]) -> Result<Self, FruParseError> {
        if image.len() < 8 {
            return Err(FruParseError::Truncated);
        }
        if image[0] != 1 || image[6] != 0 {
            return Err(FruParseError::Version);
        }
        check_sum(&image[..8])?;
        let mut offsets = [None; 5];
        for (slot, raw) in image[1..6].iter().enumerate() {
            if *raw != 0 {
                let offset = *raw as usize * 8;
                if offset >= image.len() || offsets.contains(&Some(offset)) {
                    return Err(FruParseError::Layout);
                }
                offsets[slot] = Some(offset);
            }
        }
        Ok(Self {
            internal_use: offsets[0],
            chassis: offsets[1],
            board: offsets[2],
            product: offsets[3],
            multirecord: offsets[4],
        })
    }

    fn offsets(&self) -> [Option<usize>; 5] {
        [
            self.internal_use,
            self.chassis,
            self.board,
            self.product,
            self.multirecord,
        ]
    }
}

fn check_sum(bytes: &[u8]) -> Result<(), FruParseError> {
    if bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0 {
        Ok(())
    } else {
        Err(FruParseError::Checksum)
    }
}

/// FRU type/length byte's encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldEncoding {
    /// Binary, OEM, or unspecified bytes; never decoded as text.
    Binary,
    /// BCD plus characters.
    BcdPlus,
    /// Six-bit packed ASCII.
    SixBitAscii,
    /// Eight-bit ASCII/Latin-1, decoded only for English language codes.
    EightBitAscii,
}

/// One checked type/length field. `raw` is always preserved verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FruField {
    /// The wire encoding.
    pub encoding: FieldEncoding,
    /// Original field bytes.
    pub raw: Vec<u8>,
    /// Decoded text when the encoding and language permit it.
    pub text: Option<String>,
}

fn parse_fields(
    area: &[u8],
    start: usize,
    min_fields: usize,
    language: Option<u8>,
) -> Result<Vec<FruField>, FruParseError> {
    let mut pos = start;
    let end = area.len() - 1;
    let mut fields = Vec::new();
    loop {
        let descriptor = *area
            .get(pos)
            .filter(|_| pos < end)
            .ok_or(FruParseError::Field)?;
        pos += 1;
        if descriptor == 0xc1 {
            break;
        }
        let len = (descriptor & 0x3f) as usize;
        if len > end - pos {
            return Err(FruParseError::Truncated);
        }
        let raw = area[pos..pos + len].to_vec();
        pos += len;
        let (encoding, text) = match descriptor >> 6 {
            0 => (FieldEncoding::Binary, None),
            1 => {
                const BCD: &[u8; 16] = b"0123456789 -.:,_";
                let chars: String = raw
                    .iter()
                    .flat_map(|b| {
                        [
                            BCD[(b >> 4) as usize] as char,
                            BCD[(b & 0x0f) as usize] as char,
                        ]
                    })
                    .collect();
                (FieldEncoding::BcdPlus, Some(chars))
            }
            2 => {
                let mut chars = String::new();
                for group in raw.chunks(3) {
                    let bits = group
                        .iter()
                        .enumerate()
                        .fold(0u32, |v, (i, b)| v | ((*b as u32) << (i * 8)));
                    for index in 0..(group.len() * 8 / 6) {
                        chars.push(((0x20 + ((bits >> (index * 6)) & 0x3f)) as u8) as char);
                    }
                }
                (FieldEncoding::SixBitAscii, Some(chars))
            }
            3 => {
                let text = if language == Some(0) || language == Some(25) {
                    if !raw.iter().all(|b| *b >= 0x20 && !matches!(*b, 0x7f..=0x9f)) {
                        return Err(FruParseError::Field);
                    }
                    Some(raw.iter().map(|b| char::from(*b)).collect())
                } else {
                    None
                };
                (FieldEncoding::EightBitAscii, text)
            }
            _ => unreachable!(),
        };
        fields.push(FruField {
            encoding,
            raw,
            text,
        });
    }
    if fields.len() < min_fields || area[pos..end].iter().any(|b| *b != 0) {
        return Err(FruParseError::Field);
    }
    Ok(fields)
}

fn area(
    image: &[u8],
    start: usize,
    limit: usize,
    min_len: usize,
) -> Result<(&[u8], usize), FruParseError> {
    let head = image
        .get(start..start + 2)
        .ok_or(FruParseError::Truncated)?;
    if head[0] != 1 {
        return Err(FruParseError::Version);
    }
    let size = head[1] as usize * 8;
    if size < min_len {
        return Err(FruParseError::Layout);
    }
    if start + size > limit {
        return Err(FruParseError::Layout);
    }
    let bytes = image
        .get(start..start + size)
        .ok_or(FruParseError::Truncated)?;
    check_sum(bytes)?;
    Ok((bytes, start + size))
}

/// Checked chassis information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChassisInfo {
    /// Chassis type code.
    pub chassis_type: u8,
    /// Part number.
    pub part_number: FruField,
    /// Serial number.
    pub serial_number: FruField,
    /// Unmodelled extra fields (raw bytes retained).
    pub extra: Vec<FruField>,
}

/// Checked board information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoardInfo {
    /// Language code.
    pub language: u8,
    /// Manufacturing time in minutes since 1996-01-01 00:00 UTC.
    pub manufacturing_minutes: u32,
    /// Manufacturer.
    pub manufacturer: FruField,
    /// Product name.
    pub product_name: FruField,
    /// Serial number.
    pub serial_number: FruField,
    /// Part number.
    pub part_number: FruField,
    /// FRU file ID.
    pub file_id: FruField,
    /// Unmodelled extra fields (raw bytes retained).
    pub extra: Vec<FruField>,
}

/// Checked product information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductInfo {
    /// Language code.
    pub language: u8,
    /// Manufacturer.
    pub manufacturer: FruField,
    /// Product name.
    pub product_name: FruField,
    /// Part/model number.
    pub part_number: FruField,
    /// Product version.
    pub version: FruField,
    /// Serial number.
    pub serial_number: FruField,
    /// Asset tag.
    pub asset_tag: FruField,
    /// FRU file ID.
    pub file_id: FruField,
    /// Unmodelled extra fields (raw bytes retained).
    pub extra: Vec<FruField>,
}

/// Decoded DC output or DC load record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcRecord {
    /// Output number (low four bits of the first byte).
    pub number: u8,
    /// Nominal voltage, 10 mV units.
    pub nominal_voltage_10mv: i16,
    /// Maximum negative deviation (output) or minimum voltage (load), 10 mV units.
    pub minimum_10mv: i16,
    /// Maximum positive deviation (output) or maximum voltage (load), 10 mV units.
    pub maximum_10mv: i16,
    /// Ripple/noise in mV.
    pub ripple_mv: u16,
    /// Minimum current draw, mA.
    pub minimum_current_ma: u16,
    /// Maximum current draw, mA.
    pub maximum_current_ma: u16,
    /// Standby flag for DC output records; false for DC load records.
    pub standby: bool,
}

/// Known multirecord data; OEM/unknown data is retained verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultiRecordData {
    /// DC output (type 0x01).
    DcOutput(DcRecord),
    /// DC load (type 0x02).
    DcLoad(DcRecord),
    /// Management access (type 0x03), subtype and uninterpreted bytes.
    ManagementAccess { subtype: u8, data: Vec<u8> },
    /// OEM extension (type 0xc0 and above), uninterpreted bytes.
    Oem(Vec<u8>),
    /// Other record type, uninterpreted bytes.
    Unknown(Vec<u8>),
}

/// One multirecord with both decoded data and original payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiRecord {
    /// Record type code.
    pub record_type: u8,
    /// Multirecord format version.
    pub format_version: u8,
    /// Whether this record terminates the multirecord chain.
    pub end_of_list: bool,
    /// Original record payload.
    pub raw: Vec<u8>,
    /// Decoded or preserved data.
    pub data: MultiRecordData,
}

fn parse_multirecords(area: &[u8]) -> Result<(Vec<MultiRecord>, usize), FruParseError> {
    let mut records = Vec::new();
    let mut pos = 0;
    loop {
        let header = area.get(pos..pos + 5).ok_or(FruParseError::Truncated)?;
        if header[1] & 0x7f != 2 {
            return Err(FruParseError::Version);
        }
        check_sum(header)?;
        let length = header[2] as usize;
        let payload = area
            .get(pos + 5..pos + 5 + length)
            .ok_or(FruParseError::Truncated)?;
        if payload
            .iter()
            .fold(header[3], |sum, b| sum.wrapping_add(*b))
            != 0
        {
            return Err(FruParseError::Checksum);
        }
        let record_type = header[0];
        let data = match record_type {
            1 | 2 => {
                if payload.len() != 13 {
                    return Err(FruParseError::Field);
                }
                let signed = |offset| i16::from_le_bytes([payload[offset], payload[offset + 1]]);
                let unsigned = |offset| u16::from_le_bytes([payload[offset], payload[offset + 1]]);
                let record = DcRecord {
                    number: payload[0] & 0x0f,
                    standby: record_type == 1 && payload[0] & 0x80 != 0,
                    nominal_voltage_10mv: signed(1),
                    minimum_10mv: signed(3),
                    maximum_10mv: signed(5),
                    ripple_mv: unsigned(7),
                    minimum_current_ma: unsigned(9),
                    maximum_current_ma: unsigned(11),
                };
                if record_type == 1 {
                    MultiRecordData::DcOutput(record)
                } else {
                    MultiRecordData::DcLoad(record)
                }
            }
            3 => {
                let (&subtype, data) = payload.split_first().ok_or(FruParseError::Field)?;
                MultiRecordData::ManagementAccess {
                    subtype,
                    data: data.to_vec(),
                }
            }
            0xc0..=0xff => MultiRecordData::Oem(payload.to_vec()),
            _ => MultiRecordData::Unknown(payload.to_vec()),
        };
        let end_of_list = header[1] & 0x80 != 0;
        records.push(MultiRecord {
            record_type,
            format_version: 2,
            end_of_list,
            raw: payload.to_vec(),
            data,
        });
        pos += 5 + length;
        if end_of_list {
            return Ok((records, pos));
        }
    }
}

/// Parsed, checksum-verified FRU inventory, distinct from an SDR locator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FruInventory {
    /// Checked common header offsets.
    pub header: FruHeader,
    /// Internal-use bytes (layout is implementation-specific).
    pub internal_use: Option<Vec<u8>>,
    /// Chassis information, if present.
    pub chassis: Option<ChassisInfo>,
    /// Board information, if present.
    pub board: Option<BoardInfo>,
    /// Product information, if present.
    pub product: Option<ProductInfo>,
    /// Checked multirecord chain.
    pub multirecords: Vec<MultiRecord>,
    /// Uninterpreted bytes after the multirecord end marker.
    pub multirecord_tail: Vec<u8>,
}

impl FruInventory {
    /// Validate and decode a *complete* inventory image. This function never
    /// changes device contents or fixes bad checksums.
    pub fn parse(image: &[u8]) -> Result<Self, FruParseError> {
        let header = FruHeader::parse(image)?;
        let offsets = header.offsets();
        let limit = |start| {
            offsets
                .iter()
                .flatten()
                .filter(|&&value| value > start)
                .min()
                .copied()
                .unwrap_or(image.len())
        };
        let internal_use = header
            .internal_use
            .map(|start| image[start..limit(start)].to_vec());

        let chassis = if let Some(start) = header.chassis {
            let (area, _) = area(image, start, limit(start), 8)?;
            let fields = parse_fields(area, 3, 2, Some(0))?;
            let mut fields = fields.into_iter();
            Some(ChassisInfo {
                chassis_type: area[2],
                part_number: fields.next().unwrap(),
                serial_number: fields.next().unwrap(),
                extra: fields.collect(),
            })
        } else {
            None
        };
        let board = if let Some(start) = header.board {
            let (area, _) = area(image, start, limit(start), 8)?;
            let fields = parse_fields(area, 6, 5, Some(area[2]))?;
            let mut fields = fields.into_iter();
            Some(BoardInfo {
                language: area[2],
                manufacturing_minutes: u32::from(area[3])
                    | (u32::from(area[4]) << 8)
                    | (u32::from(area[5]) << 16),
                manufacturer: fields.next().unwrap(),
                product_name: fields.next().unwrap(),
                serial_number: fields.next().unwrap(),
                part_number: fields.next().unwrap(),
                file_id: fields.next().unwrap(),
                extra: fields.collect(),
            })
        } else {
            None
        };
        let product = if let Some(start) = header.product {
            let (area, _) = area(image, start, limit(start), 8)?;
            let fields = parse_fields(area, 3, 7, Some(area[2]))?;
            let mut fields = fields.into_iter();
            Some(ProductInfo {
                language: area[2],
                manufacturer: fields.next().unwrap(),
                product_name: fields.next().unwrap(),
                part_number: fields.next().unwrap(),
                version: fields.next().unwrap(),
                serial_number: fields.next().unwrap(),
                asset_tag: fields.next().unwrap(),
                file_id: fields.next().unwrap(),
                extra: fields.collect(),
            })
        } else {
            None
        };
        let (multirecords, multirecord_tail) = if let Some(start) = header.multirecord {
            let raw = &image[start..limit(start)];
            let (records, consumed) = parse_multirecords(raw)?;
            (records, raw[consumed..].to_vec())
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(Self {
            header,
            internal_use,
            chassis,
            board,
            product,
            multirecords,
            multirecord_tail,
        })
    }
}
