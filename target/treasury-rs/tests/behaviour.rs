use treasury::*;

fn frame(amount: u64) -> Vec<u8> {
    let mut v = vec![1u8; 8];
    v.extend_from_slice(&amount.to_be_bytes());
    v.extend_from_slice(&[9u8; 8]);
    v
}

#[test]
fn parses_a_valid_frame() {
    let t = parse_frame(&frame(500)).unwrap();
    assert_eq!(t.amount, 500);
    assert_eq!(t.to, [1u8; 8]);
}

#[test]
fn small_amounts_convert() {
    assert_eq!(to_ledger_units(70_000), Ok(70_000));
}

#[test]
fn equal_macs_verify_and_different_do_not() {
    assert!(verify_mac(&[1, 2, 3], &[1, 2, 3]).0);
    assert!(!verify_mac(&[1, 2, 3], &[1, 2, 4]).0);
}
