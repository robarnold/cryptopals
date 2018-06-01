#[test]
fn challenge() {
  extern crate time;
  use std::str;
  use std::string::String;

  use util;
  use xor;

  let encoded_bytes = util::read_encoded_data(include_bytes!("s1c6.txt"));
  let start_time = time::precise_time_s();
  let attempt = xor::attempt_rotating_key_decode(&encoded_bytes);
  let duration = time::precise_time_s() - start_time;
  println!("Duration: {}s", duration);
  assert_eq!(true, attempt.is_some());
  let xor::XorRotatingKeyDecodeAttempt {
    key, decoded_data, ..
  } = attempt.unwrap();
  println!("Key: {:?}", key);
  let maybe_string = String::from_utf8(decoded_data);
  assert_eq!(true, maybe_string.is_ok());
  let string = maybe_string.unwrap();
  let reference = str::from_utf8(include_bytes!("s1c6_decoded.txt")).unwrap();
  assert_eq!(reference, string);
}
