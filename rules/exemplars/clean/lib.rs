//! Treasury transfer frames.  Invented target code for review exercises.
//! Frame layout: 8 bytes recipient, 8 bytes big-endian amount, 8 bytes mac.

#[derive(Debug, PartialEq)]
pub struct Transfer {
    pub to: [u8; 8],
    pub amount: u64,
    pub mac: [u8; 8],
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    TooShort,
}

#[derive(Debug, PartialEq)]
pub enum LedgerError {
    Overflow,
}

pub fn parse_frame(buf: &[u8]) -> Result<Transfer, ParseError> {
    if buf.len() < 24 {
        return Err(ParseError::TooShort);
    }
    let mut to = [0u8; 8];
    to.copy_from_slice(&buf[0..8]);
    let amount = u64::from_be_bytes(buf[8..16].try_into().map_err(|_| ParseError::TooShort)?);
    let mut mac = [0u8; 8];
    mac.copy_from_slice(&buf[16..24]);
    Ok(Transfer { to, amount, mac })
}

/// Convert an amount in base units to the 32-bit field the ledger stores.
pub fn to_ledger_units(amount: u64) -> Result<u32, LedgerError> {
    u32::try_from(amount).map_err(|_| LedgerError::Overflow)
}

/// Returns (equal, bytes_examined).  bytes_examined stands in for timing in tests.
pub fn verify_mac(expected: &[u8], got: &[u8]) -> (bool, usize) {
    if expected.len() != got.len() {
        return (false, 0);
    }
    let mut diff = 0u8;
    for i in 0..expected.len() {
        diff |= expected[i] ^ got[i];
    }
    (diff == 0, expected.len())
}
