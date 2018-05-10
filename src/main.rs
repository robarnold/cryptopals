fn parse_byte_string(s: &str) -> Vec<u8> {
  let mut v = Vec::with_capacity(s.len() / 2);
  let mut i = 0;
  while i < s.len() {
    v.push(u8::from_str_radix(&s[i..i + 2], 16).unwrap());
    i += 2;
  }
  v
}

macro_rules! bytes {
  ($description:expr) => (
    parse_byte_string($description)
  );
}

fn b64_encode(bytes: &[u8]) -> String {
  let table = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
  ];
  let mut s = String::from("");
  for chunk in bytes.chunks(3) {
    match chunk.len() {
      1 => {
        let b1 = chunk[0];
        let i1 = (b1 >> 2 & 0x3f) as usize;
        let i2 = (b1 << 4 & 0x3f) as usize;
        s.push(table[i1]);
        s.push(table[i2]);
        s.push('=');
        s.push('=');
      }
      2 => {
        let b1 = chunk[0];
        let b2 = chunk[1];
        let i1 = (b1 >> 2 & 0x3f) as usize;
        let i2 = (b1 << 4 & 0x30) as usize | (b2 >> 4 & 0x0f) as usize;
        let i3 = (b2 << 2 & 0x3f) as usize;
        s.push(table[i1]);
        s.push(table[i2]);
        s.push(table[i3]);
        s.push('=');
      }
      3 => {
        let b1 = chunk[0];
        let b2 = chunk[1];
        let b3 = chunk[2];
        let i1 = (b1 >> 2 & 0x3f) as usize;
        let i2 = (b1 << 4 & 0x30) as usize | (b2 >> 4 & 0x0f) as usize;
        let i3 = (b2 << 2 & 0x3f) as usize | (b3 >> 6 & 0x03) as usize;
        let i4 = (b3 & 0x3f) as usize;
        s.push(table[i1]);
        s.push(table[i2]);
        s.push(table[i3]);
        s.push(table[i4]);
      }
      _ => panic!("Chunk size too small"),
    }
  }
  s
}

#[test]
fn base64_one_letter() {
  assert_eq!(String::from("TQ=="), b64_encode(&[0x4d]));
}

#[test]
fn base64_two_letter2() {
  assert_eq!(String::from("TWE="), b64_encode(&[0x4d, 0x61]));
}

#[test]
fn base64_three_letter2() {
  assert_eq!(String::from("TWFu"), b64_encode(&[0x4d, 0x61, 0x6e]));
}

#[test]
fn set_one_challenge_one() {
  let bytes = bytes!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
  assert_eq!(
    String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"),
    b64_encode(&bytes)
  );
}

fn xor_buffer_fixed(data: &[u8], key: &[u8]) -> Vec<u8> {
  use std::ops::BitXor;
  let mut v = Vec::with_capacity(data.len());
  for i in 0..data.len() {
    v.push(data[i].bitxor(key[i]));
  }
  v
}

#[test]
fn set_one_challenge_two() {
  let result = bytes!("746865206b696420646f6e277420706c6179");
  let data = &bytes!("1c0111001f010100061a024b53535009181c");
  let key = &bytes!("686974207468652062756c6c277320657965");
  assert_eq!(result, xor_buffer_fixed(data, key));
}

fn xor_buffer_single_char(data: &[u8], key: u8) -> Vec<u8> {
  use std::ops::BitXor;
  let mut v = Vec::with_capacity(data.len());
  for i in 0..data.len() {
    v.push(data[i].bitxor(key));
  }
  v
}

fn likely_plain_text_score(data: &[u8]) -> u32 {
  let mut alphabetic_chars = 0u32;
  let mut punctuation = 0u32;
  let mut invalid_chars = 0u32;
  for i in data.iter() {
    if i.is_ascii_alphanumeric() || i.is_ascii_whitespace() {
      alphabetic_chars += 1;
    } else if i.is_ascii_punctuation() {
      punctuation += 1;
    } else {
      invalid_chars += 1;
    }
  }
  (3 * alphabetic_chars + punctuation).saturating_sub(invalid_chars)
}

#[derive(Clone)]
struct XorDecodeAttempt {
  key: u8,
  score: u32,
}

fn attempt_xor_decode(data: &[u8]) -> XorDecodeAttempt {
  let mut best_key = 0;
  let mut best_score = 0;
  for key in 0..u8::max_value() {
    let decoded_data = xor_buffer_single_char(data, key);
    let score = likely_plain_text_score(&decoded_data);
    if score > best_score {
      best_key = key;
      best_score = score;
    }
  }
  XorDecodeAttempt {
    key: best_key,
    score: best_score,
  }
}

#[test]
fn set_one_challenge_three() {
  let encoded_data = bytes!("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
  let attempt = attempt_xor_decode(&encoded_data);
  let decoded_data = xor_buffer_single_char(&encoded_data, attempt.key);
  let decoded_text_result = std::str::from_utf8(&decoded_data);
  println!("{:?}", decoded_text_result);
  assert_eq!(true, decoded_text_result.is_ok());
  let decoded_text = decoded_text_result.unwrap();
  println!("{}", decoded_text);
  assert_eq!(true, decoded_text.len() > 0);
}

#[test]
fn set_one_challenge_four() {
  use std::io::BufRead;
  let contents = include_bytes!("s1c4.txt");
  let mut best_attempt = None;
  let mut decoded_string = String::from("");
  for line in contents.lines() {
    let encoded_data = &bytes!(&line.unwrap());
    let current_attempt = attempt_xor_decode(encoded_data);
    let decode_result =
      std::string::String::from_utf8(xor_buffer_single_char(&encoded_data, current_attempt.key));
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
