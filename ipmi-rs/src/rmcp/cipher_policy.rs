use super::CipherSuite;

/// Errors in the channel's advertised cipher-suite records.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherSuiteListError {
    /// A cipher-suite record was split or truncated.
    IncompleteRecord,
    /// The BMC returned an unrecognized record marker.
    UnknownRecord(u8),
    /// A suite ID was advertised with algorithms different from its definition.
    MismatchedAlgorithms(CipherSuite),
    /// The 64-page protocol limit was reached without a final short page.
    IncompleteList,
}

pub(super) fn select_best(data: &[u8]) -> Result<Option<CipherSuite>, CipherSuiteListError> {
    let mut found_3 = false;
    let mut found_17 = false;
    let mut index = 0;
    while index < data.len() {
        let (length, standard) = match data[index] {
            0xc0 => (5, true),
            0xc1 => (8, false),
            other => return Err(CipherSuiteListError::UnknownRecord(other)),
        };
        let record = data
            .get(index..index + length)
            .ok_or(CipherSuiteListError::IncompleteRecord)?;
        if standard {
            let suite = CipherSuite::from_id(record[1]);
            if let Some(suite @ (CipherSuite::Id3 | CipherSuite::Id17)) = suite {
                let algorithms = [record[2] & 0x3f, record[3] & 0x3f, record[4] & 0x3f];
                if algorithms != suite.into_suite() {
                    return Err(CipherSuiteListError::MismatchedAlgorithms(suite));
                }
                found_3 |= suite == CipherSuite::Id3;
                found_17 |= suite == CipherSuite::Id17;
            }
        }
        index += length;
    }
    Ok(if found_17 {
        Some(CipherSuite::Id17)
    } else if found_3 {
        Some(CipherSuite::Id3)
    } else {
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_only_supported_secure_suites() {
        let three = [0xc0, 3, 1, 1, 1];
        let seventeen = [0xc0, 17, 3, 4, 1];
        assert_eq!(select_best(&three), Ok(Some(CipherSuite::Id3)));
        assert_eq!(
            select_best(&[three, seventeen].concat()),
            Ok(Some(CipherSuite::Id17))
        );
        assert_eq!(
            select_best(&[seventeen, three].concat()),
            Ok(Some(CipherSuite::Id17))
        );
        assert_eq!(select_best(&[0xc0, 1, 1, 0, 0]), Ok(None));
        assert_eq!(select_best(&[0xc1, 17, 0, 0, 0, 3, 4, 1]), Ok(None));
    }

    #[test]
    fn malformed_and_substituted_records_fail_closed() {
        assert_eq!(
            select_best(&[0xc0, 17, 1, 4, 1]),
            Err(CipherSuiteListError::MismatchedAlgorithms(
                CipherSuite::Id17
            ))
        );
        assert_eq!(
            select_best(&[0xc0, 3, 1]),
            Err(CipherSuiteListError::IncompleteRecord)
        );
        assert_eq!(
            select_best(&[0xc2]),
            Err(CipherSuiteListError::UnknownRecord(0xc2))
        );
    }
}
