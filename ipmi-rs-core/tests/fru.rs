use ipmi_rs_core::{
    connection::{IpmiCommand, LogicalUnit, Message, NetFn},
    storage::{
        fru::{
            discover_fru_devices, FieldEncoding, FruAccess, FruCommandError, FruDevice, FruInfo,
            FruInventory, FruParseError, GetFruInventoryAreaInfo, MultiRecordData, ReadFruData,
            WriteFruData,
        },
        sdr::{record::RecordContents, Record},
    },
};

fn fixture() -> Vec<u8> {
    include_str!("../src/storage/fru/fixtures/inventory.hex")
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

fn checksum(area: &mut [u8]) {
    let last = area.len() - 1;
    area[last] = 0u8.wrapping_sub(area[..last].iter().fold(0u8, |v, b| v.wrapping_add(*b)));
}

#[test]
fn inventory_fixture_decodes_chassis_board_product_and_oem() {
    let image = fixture();
    let inventory = FruInventory::parse(&image).unwrap();
    assert_eq!(inventory.header.chassis, Some(8));
    assert_eq!(inventory.header.board, Some(32));
    assert_eq!(inventory.header.product, Some(72));
    assert_eq!(inventory.header.multirecord, Some(112));
    assert_eq!(inventory.chassis.as_ref().unwrap().chassis_type, 0x17);
    assert_eq!(
        inventory
            .chassis
            .as_ref()
            .unwrap()
            .part_number
            .text
            .as_deref(),
        Some("RACK")
    );
    assert_eq!(
        inventory.chassis.as_ref().unwrap().extra[0].raw,
        [0xab, 0xcd]
    );
    let board = inventory.board.as_ref().unwrap();
    assert_eq!(board.manufacturing_minutes, 0x302010);
    assert_eq!(board.product_name.text.as_deref(), Some("CPU"));
    assert_eq!(board.extra[0].encoding, FieldEncoding::BcdPlus);
    assert_eq!(board.extra[0].text.as_deref(), Some("12"));
    assert_eq!(board.extra[1].encoding, FieldEncoding::SixBitAscii);
    assert_eq!(board.extra[1].text.as_deref(), Some("ABCD"));
    assert_eq!(board.extra[2].raw, [0xfe]);
    let product = inventory.product.as_ref().unwrap();
    assert_eq!(product.product_name.text.as_deref(), Some("BOX"));
    assert_eq!(product.version.text.as_deref(), Some("10"));
    assert_eq!(inventory.multirecords.len(), 1);
    assert!(inventory.multirecords[0].end_of_list);
    assert!(matches!(
        &inventory.multirecords[0].data,
        MultiRecordData::Oem(data) if data == &[0x11, 0x22, 0x33, 0x44]
    ));
    assert_eq!(inventory.multirecord_tail.len(), 7);
}

#[test]
fn invalid_layout_checksums_fields_and_short_areas_are_rejected() {
    let image = fixture();
    let mut bad = image.clone();
    bad[7] ^= 1;
    assert_eq!(FruInventory::parse(&bad), Err(FruParseError::Checksum));
    let mut bad = image.clone();
    bad[3] = 1;
    checksum(&mut bad[..8]);
    assert_eq!(FruInventory::parse(&bad), Err(FruParseError::Layout));
    let mut bad = image.clone();
    bad[9] = 0;
    checksum(&mut bad[8..32]);
    assert_eq!(FruInventory::parse(&bad), Err(FruParseError::Layout));
    let mut bad = image.clone();
    bad[11] = 0xff;
    checksum(&mut bad[8..32]);
    assert_eq!(FruInventory::parse(&bad), Err(FruParseError::Truncated));
    let mut bad = image.clone();
    bad[24] = 0;
    checksum(&mut bad[8..32]);
    assert_eq!(FruInventory::parse(&bad), Err(FruParseError::Field));
    let mut bad = image.clone();
    bad[22] ^= 1;
    assert_eq!(FruInventory::parse(&bad), Err(FruParseError::Checksum));
    let mut bad = image.clone();
    bad[116] ^= 1;
    assert_eq!(FruInventory::parse(&bad), Err(FruParseError::Checksum));
    let mut bad = image.clone();
    bad[120] ^= 1;
    assert_eq!(FruInventory::parse(&bad), Err(FruParseError::Checksum));
    let mut bad = image.clone();
    bad[114] = 30;
    checksum(&mut bad[112..117]);
    assert_eq!(FruInventory::parse(&bad), Err(FruParseError::Truncated));
    let mut bad = image.clone();
    bad[113] &= !0x80;
    checksum(&mut bad[112..117]);
    assert_eq!(FruInventory::parse(&bad), Err(FruParseError::Version));
    assert_eq!(
        FruInventory::parse(&image[..7]),
        Err(FruParseError::Truncated)
    );
}

#[test]
fn non_english_text_is_not_guessed_and_english_latin1_is_decoded() {
    let mut image = fixture();
    image[34] = 0x80;
    image[39] = 0xe9;
    checksum(&mut image[32..72]);
    let board = FruInventory::parse(&image).unwrap().board.unwrap();
    assert_eq!(board.manufacturer.raw, [0xe9, 0x43, 0x4d, 0x45]);
    assert_eq!(board.manufacturer.text, None);
    image[34] = 0;
    checksum(&mut image[32..72]);
    assert_eq!(
        FruInventory::parse(&image)
            .unwrap()
            .board
            .unwrap()
            .manufacturer
            .text
            .as_deref(),
        Some("éCME")
    );
    image[39] = 0x07;
    checksum(&mut image[32..72]);
    assert_eq!(FruInventory::parse(&image), Err(FruParseError::Field));
}

#[test]
fn commands_enforce_wire_offsets_alignment_bounds_and_response_counts() {
    let info = GetFruInventoryAreaInfo::new(7, None, LogicalUnit::Zero);
    let msg: Message = info.into();
    assert_eq!(
        (msg.netfn(), msg.cmd(), msg.data()),
        (NetFn::Storage, 0x10, &[7][..])
    );
    assert_eq!(
        GetFruInventoryAreaInfo::parse_success_response(&[128, 0, 1]),
        Ok(FruInfo {
            size: 128,
            access: FruAccess::Word
        })
    );
    assert_eq!(
        GetFruInventoryAreaInfo::parse_success_response(&[0, 0, 0]),
        Err(FruCommandError::EmptyInventory)
    );
    assert_eq!(
        GetFruInventoryAreaInfo::parse_success_response(&[3]),
        Err(FruCommandError::MalformedResponse)
    );

    let info = FruInfo {
        size: 128,
        access: FruAccess::Word,
    };
    let read = ReadFruData::new(7, None, LogicalUnit::Zero, info, 16, 8).unwrap();
    let msg: Message = read.into();
    assert_eq!((msg.cmd(), msg.data()), (0x11, &[7, 8, 0, 8][..]));
    let response = ReadFruData::parse_success_response(&[4, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    assert_eq!(read.verify(response), Ok(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    let response = ReadFruData::parse_success_response(&[3, 1, 2, 3, 4, 5, 6]).unwrap();
    assert_eq!(read.verify(response), Err(FruCommandError::UnexpectedCount));
    assert_eq!(
        ReadFruData::new(7, None, LogicalUnit::Zero, info, 1, 2).unwrap_err(),
        FruCommandError::Unaligned
    );
    assert_eq!(
        ReadFruData::new(7, None, LogicalUnit::Zero, info, 2, 1).unwrap_err(),
        FruCommandError::Unaligned
    );
    assert_eq!(
        ReadFruData::new(7, None, LogicalUnit::Zero, info, 126, 4).unwrap_err(),
        FruCommandError::OutOfBounds
    );
    assert_eq!(
        ReadFruData::new(7, None, LogicalUnit::Zero, info, 0, 0).unwrap_err(),
        FruCommandError::InvalidLength
    );
    let write = WriteFruData::new(7, None, LogicalUnit::Zero, info, 16, vec![1, 2, 3, 4]).unwrap();
    assert_eq!(write.verify(2), Ok(()));
    assert_eq!(write.verify(4), Err(FruCommandError::UnexpectedCount));
    let msg: Message = write.into();
    assert_eq!((msg.cmd(), msg.data()), (0x12, &[7, 8, 0, 1, 2, 3, 4][..]));
    assert_eq!(
        WriteFruData::parse_success_response(&[2, 1]),
        Err(FruCommandError::MalformedResponse)
    );
    assert_eq!(
        WriteFruData::new(7, None, LogicalUnit::Zero, info, 0, vec![0; 256]).unwrap_err(),
        FruCommandError::InvalidLength
    );
}

#[test]
fn dc_output_multirecord_is_decoded_without_losing_wire_payload() {
    let mut image = vec![1, 0, 0, 0, 0, 1, 0, 0];
    checksum(&mut image);
    let payload = [
        0x81, 0xb8, 0x0b, 0x9c, 0xff, 0x64, 0, 0x32, 0, 0, 0, 0xe8, 0x03,
    ];
    let body_sum = 0u8.wrapping_sub(payload.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)));
    let mut header = vec![1, 0x82, 13, body_sum, 0];
    checksum(&mut header);
    image.extend(header);
    image.extend(payload);
    let inventory = FruInventory::parse(&image).unwrap();
    let record = &inventory.multirecords[0];
    assert_eq!(record.raw, payload);
    assert!(matches!(&record.data, MultiRecordData::DcOutput(dc)
        if dc.number == 1 && dc.standby && dc.nominal_voltage_10mv == 3000
            && dc.minimum_10mv == -100 && dc.maximum_current_ma == 1000));

    let last = image.len() - 1;
    image[last] ^= 1;
    assert_eq!(FruInventory::parse(&image), Err(FruParseError::Checksum));
}

fn locator(id: u8, device_type: u8, modifier: u8, physical: bool) -> Record {
    let mut data = vec![0x40, id, 0x08, 0, 0, device_type, modifier, 7, 1, 0, 0xc0];
    if physical {
        data[1] |= 0x80;
    }
    let mut record = vec![0, 0, 0x51, 0x11, data.len() as u8];
    record.extend(data);
    Record::parse(&record).unwrap()
}

fn mc_locator(supports_fru: bool) -> Record {
    let data = [
        0x42,
        1,
        0,
        if supports_fru { 0x08 } else { 0 },
        0,
        0,
        0,
        7,
        1,
        0,
        0xc0,
    ];
    let mut raw = vec![0, 0, 0x51, 0x12, data.len() as u8];
    raw.extend(data);
    Record::parse(&raw).unwrap()
}

#[test]
fn locators_discover_inventory_ids_not_inventory_contents() {
    let records = [
        locator(2, 0x10, 0, false),
        locator(2, 0x10, 0, false),
        locator(3, 0x10, 0, true),
        locator(4, 0x11, 0, false),
        locator(5, 0x08, 2, false),
        locator(6, 0x08, 1, false),
        mc_locator(true),
        mc_locator(false),
    ];
    assert!(matches!(
        records[0].contents,
        RecordContents::FruDeviceLocator(_)
    ));
    let devices = discover_fru_devices(&records);
    assert_eq!(devices.len(), 4);
    assert_eq!(devices[0], FruDevice::BUILTIN);
    assert_eq!(devices[1].id, 2);
    assert_eq!(devices[1].target.unwrap().0 .0, 0x40);
    assert_eq!(devices[1].lun, LogicalUnit::One);
    assert_eq!(devices[2].id, 5);
    assert_eq!(devices[3].id, 0);
    assert_eq!(devices[3].target.unwrap().0 .0, 0x42);

    for size in 8..11 {
        let mut raw = vec![0, 0, 0x51, 0x11, size as u8];
        raw.extend(&[0; 11][..size]);
        assert!(Record::parse(&raw).is_err());
    }
}
