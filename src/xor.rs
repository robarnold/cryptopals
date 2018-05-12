use std::ops::BitXor;

use analysis;

pub fn buffer_full_key(data: &[u8], key: &[u8]) -> Vec<u8> {
  let mut v = Vec::with_capacity(data.len());
  for i in 0..data.len() {
    v.push(data[i].bitxor(key[i]));
  }
  v
}

pub fn buffer_single_char(data: &[u8], key: u8) -> Vec<u8> {
  let mut v = Vec::with_capacity(data.len());
  for i in 0..data.len() {
    v.push(data[i].bitxor(key));
  }
  v
}

pub fn buffer_repeating(data: &[u8], key: &[u8]) -> Vec<u8> {
  let mut v = Vec::with_capacity(data.len());
  for i in 0..data.len() {
    v.push(data[i].bitxor(key[i % key.len()]));
  }
  v
}

#[derive(Clone)]
pub struct XorSingleByteDecodeAttempt {
  pub key: u8,
  pub score: u32,
}

pub fn attempt_single_byte_decode(data: &[u8]) -> XorSingleByteDecodeAttempt {
  let mut best_key = 0;
  let mut best_score = 0;
  for key in 0..u8::max_value() {
    let decoded_data = buffer_single_char(data, key);
    let score = analysis::likely_plain_text_score(&decoded_data);
    if score > best_score {
      best_key = key;
      best_score = score;
    }
  }
  XorSingleByteDecodeAttempt {
    key: best_key,
    score: best_score,
  }
}
