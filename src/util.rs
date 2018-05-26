use b64;

pub fn parse_byte_string(s: &str) -> Vec<u8> {
  let mut v = Vec::with_capacity(s.len() / 2);
  let mut i = 0;
  while i < s.len() {
    v.push(u8::from_str_radix(&s[i..i + 2], 16).unwrap());
    i += 2;
  }
  v
}

pub fn read_encoded_data(contents: &[u8]) -> Vec<u8> {
  use std::io::BufRead;
  let mut encoded_string = String::new();
  for line in contents.lines() {
    encoded_string.push_str(&line.unwrap());
  }
  b64::decode(&encoded_string)
}

pub fn read_encoded_data_lines(contents: &[u8]) -> Vec<Vec<u8>> {
  use std::io::BufRead;
  let mut v = Vec::new();
  for line in contents.lines() {
    v.push(b64::decode(&line.unwrap()));
  }
  v
}
