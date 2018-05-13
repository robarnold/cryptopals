pub fn likely_plain_text_score(data: &[u8]) -> u32 {
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

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
  use std::ops::BitXor;
  let mut distance = 0;
  for i in 0..a.len() {
    distance += a[i].bitxor(b[i]).count_ones();
  }
  distance
}

#[test]
fn s1c6_example() {
  let s1 = "this is a test";
  let s2 = "wokka wokka!!!";
  assert_eq!(37, hamming_distance(s1.as_bytes(), s2.as_bytes()));
}
