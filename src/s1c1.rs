use b64;
use util;

#[test]
fn challenge() {
  let bytes = util::parse_byte_string("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
  assert_eq!(
    String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"),
    b64::encode(&bytes)
  );
}
