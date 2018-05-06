fn b64_encode(bytes: &[u8]) -> String {
  let table = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
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
      },
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
      },
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
      },
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
  let bytes = [0x49u8, 0x27u8, 0x6du8, 0x20u8, 0x6bu8, 0x69u8, 0x6cu8, 0x6cu8, 0x69u8, 0x6eu8, 0x67u8, 0x20u8, 0x79u8, 0x6fu8, 0x75u8, 0x72u8, 0x20u8, 0x62u8, 0x72u8, 0x61u8, 0x69u8, 0x6eu8, 0x20u8, 0x6cu8, 0x69u8, 0x6bu8, 0x65u8, 0x20u8, 0x61u8, 0x20u8, 0x70u8, 0x6fu8, 0x69u8, 0x73u8, 0x6fu8, 0x6eu8, 0x6fu8, 0x75u8, 0x73u8, 0x20u8, 0x6du8, 0x75u8, 0x73u8, 0x68u8, 0x72u8, 0x6fu8, 0x6fu8, 0x6du8];
  assert_eq!(String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"), b64_encode(&bytes));
}

fn parse_byte_string(s: &str) -> Vec<u8> {
  let mut v = Vec::with_capacity(s.len() / 2);
  let mut i = 0;
  while i < s.len() {
    v.push(u8::from_str_radix(&s[i..i+2], 16).unwrap());
    i += 2;
  }
  v
}

macro_rules! bytes {
  ($description:expr) => (
    parse_byte_string($description)
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
