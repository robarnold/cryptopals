use std::str;
use std::string::String;

use b64;
use xor;

fn read_encoded_data() -> Vec<u8> {
  use std::io::BufRead;
  let contents = include_bytes!("s1c6.txt");
  let mut encoded_string = String::new();
  for line in contents.lines() {
    encoded_string.push_str(&line.unwrap());
  }
  b64::decode(encoded_string)
}

#[test]
fn challenge() {
  let encoded_bytes = read_encoded_data();
  let attempt = xor::attempt_rotating_key_decode(&encoded_bytes);
  assert_eq!(true, attempt.is_some());
  let decoded_data = attempt.unwrap().decoded_data;
  let maybe_string = String::from_utf8(decoded_data);
  assert_eq!(true, maybe_string.is_ok());
  let string = maybe_string.unwrap();
  let reference = str::from_utf8(include_bytes!("s1c6_decoded.txt")).unwrap();
  assert_eq!(reference, string);
}