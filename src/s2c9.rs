#[test]
fn challenge() {
  use pkcs7;
  const LENGTH: usize = 20;
  const PLAINTEXT: &str = "YELLOW SUBMARINE";
  assert_eq!(
    pkcs7::pad(PLAINTEXT.as_bytes(), LENGTH),
    "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(),
  );
}
