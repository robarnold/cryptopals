use std::string::String;

use util;
use xor;

#[test]
fn challenge() {
  use std::io::BufRead;
  let contents = include_bytes!("s1c4.txt");
  let mut best_attempt = None;
  let mut decoded_string = String::from("");
  for line in contents.lines() {
    let encoded_data = &util::parse_byte_string(&line.unwrap());
    let current_attempt = xor::attempt_single_byte_decode(encoded_data);
    let decode_result =
      String::from_utf8(xor::buffer_single_char(&encoded_data, current_attempt.key));
    if decode_result.is_err() {
      continue;
    }
    match best_attempt.clone() {
      None => {
        decoded_string = decode_result.unwrap();
        println!("{}: {}", current_attempt.score, decoded_string);
        best_attempt = Some(current_attempt);
      }
      Some(attempt) => {
        if attempt.score < current_attempt.score {
          decoded_string = decode_result.unwrap();
          println!("{}: {}", current_attempt.score, decoded_string);
          best_attempt = Some(current_attempt);
        }
      }
    }
  }
  assert_eq!(true, best_attempt.is_some());
  assert_eq!(true, decoded_string.len() > 0);
  println!("{}", decoded_string);
}


