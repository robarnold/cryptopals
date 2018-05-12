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
