#[test]
fn challenge() {
  use std::str;

  use util;
  use xor;

  let encoded_data =
    util::parse_byte_string("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
  let attempt = xor::attempt_single_byte_decode(&encoded_data);
  let decoded_data = xor::buffer(&encoded_data, xor::Key::SingleByte(attempt.key));
  let decoded_text_result = str::from_utf8(&decoded_data);
  println!("{:?}", decoded_text_result);
  assert_eq!(true, decoded_text_result.is_ok());
  let decoded_text = decoded_text_result.unwrap();
  println!("{}", decoded_text);
  assert_eq!(true, decoded_text.len() > 0);
}
