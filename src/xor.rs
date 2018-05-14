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

pub enum Key<'a> {
  FullBuffer(&'a [u8]),
  SingleByte(u8),
  RotatingKey(&'a [u8]),
}

pub fn buffer(data: &[u8], key: Key) -> Vec<u8> {
  match key {
    Key::FullBuffer(key) => buffer_full_key(data, key),
    Key::SingleByte(key) => buffer_single_char(data, key),
    Key::RotatingKey(key) => buffer_repeating(data, key),
  }
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

#[derive(Clone, Debug)]
pub struct XorRotatingKeyDecodeAttempt {
  pub key: Vec<u8>,
  pub score: u32,
  pub decoded_data: Vec<u8>,
}

fn attempt_rotating_key_decode_at_size(data: &[u8], size: usize) -> XorRotatingKeyDecodeAttempt {
  let chunks = data.chunks(size);
  let mut rotating_key = Vec::with_capacity(size);
  for i in 0..size {
    let mut transposed_data = Vec::with_capacity(chunks.len());
    for chunk in chunks.clone() {
      if i < chunk.len() {
        transposed_data.push(chunk[i]);
      }
    }
    let attempt = attempt_single_byte_decode(&transposed_data);
    rotating_key.push(attempt.key);
  }
  let decoded_data = buffer_repeating(data, &rotating_key);
  XorRotatingKeyDecodeAttempt {
    key: rotating_key,
    score: analysis::likely_plain_text_score(&decoded_data),
    decoded_data,
  }
}

pub fn attempt_rotating_key_decode(data: &[u8]) -> Option<XorRotatingKeyDecodeAttempt> {
  let sizes = analysis::sort_keysizes_by_probability(data, 2, 40);
  println!("Key sizes: {:?}", sizes);
  let mut best_attempt = None;
  for size in sizes {
    let attempt = attempt_rotating_key_decode_at_size(data, size);
    match best_attempt.clone() {
      None => {
        best_attempt = Some(attempt);
      }
      Some(record_attempt) => {
        if record_attempt.score < attempt.score {
          best_attempt = Some(attempt);
        }
      }
    }
  }
  best_attempt
}
