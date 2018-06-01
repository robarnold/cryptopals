extern crate threadpool;
use std::iter::Iterator;
use std::ops::BitXor;

use analysis;

fn apply_xor<'a, I: Iterator<Item = &'a u8>>(output: &mut Vec<u8>, input: &[u8], mut key: I) {
  for i in 0..input.len() {
    output.push(input[i].bitxor(key.next().unwrap()));
  }
}

fn apply_xor_mut<'a, I: Iterator<Item = &'a u8>>(data: &mut [u8], mut key: I) {
  for i in 0..data.len() {
    data[i] = data[i].bitxor(key.next().unwrap());
  }
}

pub enum Key<'a> {
  FullBuffer(&'a [u8]),
  SingleByte(u8),
  RotatingKey(&'a [u8]),
}

pub fn buffer(data: &[u8], key: Key) -> Vec<u8> {
  let mut v = Vec::with_capacity(data.len());
  match key {
    Key::FullBuffer(buffer) => apply_xor(&mut v, data, buffer.iter()),
    Key::SingleByte(byte) => apply_xor(&mut v, data, [byte].iter().cycle()),
    Key::RotatingKey(buffer) => apply_xor(&mut v, data, buffer.iter().cycle()),
  }
  v
}

pub fn buffer_mut(data: &mut [u8], key: Key) {
  match key {
    Key::FullBuffer(buffer) => apply_xor_mut(data, buffer.iter()),
    Key::SingleByte(byte) => apply_xor_mut(data, [byte].iter().cycle()),
    Key::RotatingKey(buffer) => apply_xor_mut(data, buffer.iter().cycle()),
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
    let decoded_data = buffer(data, Key::SingleByte(key));
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
  let decoded_data = buffer(data, Key::RotatingKey(&rotating_key));
  XorRotatingKeyDecodeAttempt {
    key: rotating_key,
    score: analysis::likely_plain_text_score(&decoded_data),
    decoded_data,
  }
}

pub fn attempt_rotating_key_decode(data: &[u8]) -> Option<XorRotatingKeyDecodeAttempt> {
  use std::sync::mpsc::channel;
  use std::sync::Arc;
  let sizes = analysis::sort_keysizes_by_probability(data, 2, 40);
  println!("Key sizes: {:?}", sizes);
  let pool = threadpool::ThreadPool::default();
  let mut best_attempt: Option<XorRotatingKeyDecodeAttempt> = None;
  let shared_data = Arc::new(data.to_vec());
  let (tx, rx) = channel();
  for size in sizes {
    let job_data = Arc::clone(&shared_data);
    let job_tx = tx.clone();
    pool.execute(move || {
      let attempt = attempt_rotating_key_decode_at_size(&job_data, size);
      job_tx.send(attempt).expect("The channel is active");
    });
  }
  // Need to drop it here so that rx.iter will stop yielding items when the
  // threads are done.
  drop(tx);
  for attempt in rx.iter() {
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
