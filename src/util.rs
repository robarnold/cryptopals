pub fn parse_byte_string(s: &str) -> Vec<u8> {
  let mut v = Vec::with_capacity(s.len() / 2);
  let mut i = 0;
  while i < s.len() {
    v.push(u8::from_str_radix(&s[i..i + 2], 16).unwrap());
    i += 2;
  }
  v
}
