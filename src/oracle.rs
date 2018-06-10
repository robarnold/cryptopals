use aes;
use pkcs7;
use rand::prelude::*;
use util;

pub struct OracleResult {
  pub data: Vec<u8>,
  pub is_ecb: bool,
}

pub trait Oracle {
  fn encode(&self, input: &[u8]) -> OracleResult;
}

pub fn determine_block_size_and_input_offset(o: &Oracle) -> (usize, usize) {
  let mut buffer = vec![0; 0];
  let initial_length = o.encode(&buffer).data.len();
  for buffer_size in 1..256 {
    buffer.push(0);
    let output_length = o.encode(&buffer).data.len();
    if output_length != initial_length {
      let block_size = output_length - initial_length;
      return (buffer_size, block_size);
    }
  }
  panic!("Unable to find block size");
}

#[test]
fn test_input_offset_detection() {
  for i in 0..34 {
    let o = ConstantPrepend::new(AES128::new(), vec![0; i]);
    let (offset, block_size) = determine_block_size_and_input_offset(&o);
    assert_eq!(i % block_size, block_size - offset);
  }
}

pub fn determine_block_size(o: &Oracle) -> usize {
  determine_block_size_and_input_offset(o).1
}

pub fn is_using_ecb(o: &Oracle) -> bool {
  use analysis;
  let block_size = determine_block_size(o);
  let buffer = vec![0; block_size * 3];
  let encoded_buffer = o.encode(&buffer).data;
  analysis::likely_aes_ecb_score(&encoded_buffer) > 0
}

pub struct Random;

impl Random {
  pub fn new() -> Random {
    Random {}
  }
}

impl Oracle for Random {
  fn encode(&self, input: &[u8]) -> OracleResult {
    let mut rng = thread_rng();
    let key = util::gen_random_bytes(&mut rng, 16);
    let iv = util::gen_random_bytes(&mut rng, 16);
    let is_ecb: bool = rng.gen();
    let cipher_mode = if is_ecb {
      aes::CipherMode::ECB
    } else {
      aes::CipherMode::CBC(&iv)
    };
    let mut noisied_data = Vec::new();
    for _ in 0..rng.gen_range(5, 10) {
      noisied_data.push(rng.gen());
    }
    noisied_data.extend_from_slice(input);
    for _ in 0..rng.gen_range(5, 10) {
      noisied_data.push(rng.gen());
    }
    let data = pkcs7::pad(&noisied_data, 16);
    let encoded_data = aes::perform(&data, &key, aes::Operation::Encrypt, cipher_mode);
    OracleResult {
      data: encoded_data,
      is_ecb,
    }
  }
}

pub struct AES128 {
  key: Vec<u8>,
}

impl AES128 {
  pub fn new() -> AES128 {
    let mut rng = thread_rng();
    let key = util::gen_random_bytes(&mut rng, 16);
    AES128 { key }
  }
  pub fn decode(&self, ciphertext: &[u8]) -> Vec<u8> {
    let mut decoded_data = aes::perform(
      &ciphertext,
      &self.key,
      aes::Operation::Decrypt,
      aes::CipherMode::ECB,
    );
    pkcs7::unpad_mut(&mut decoded_data, 16);
    decoded_data
  }
}

impl Oracle for AES128 {
  fn encode(&self, input: &[u8]) -> OracleResult {
    let data = pkcs7::pad(&input, 16);
    let encoded_data = aes::perform(
      &data,
      &self.key,
      aes::Operation::Encrypt,
      aes::CipherMode::ECB,
    );
    OracleResult {
      data: encoded_data,
      is_ecb: true,
    }
  }
}

pub struct ConstantAppend<O: Oracle> {
  oracle: O,
  suffix: Vec<u8>,
}

impl<O: Oracle + Sized> ConstantAppend<O> {
  pub fn new(oracle: O, suffix: Vec<u8>) -> Self {
    ConstantAppend { oracle, suffix }
  }
}

impl<O: Oracle> Oracle for ConstantAppend<O> {
  fn encode(&self, input: &[u8]) -> OracleResult {
    let mut full_input = input.to_vec();
    full_input.extend(&self.suffix);
    self.oracle.encode(&full_input)
  }
}

pub struct ConstantPrepend<O: Oracle> {
  oracle: O,
  prefix: Vec<u8>,
}

impl<O: Oracle + Sized> ConstantPrepend<O> {
  pub fn new(oracle: O, prefix: Vec<u8>) -> Self {
    ConstantPrepend { oracle, prefix }
  }

  pub fn with_random_bytes(oracle: O) -> Self {
    let mut rng = thread_rng();
    let len = rng.gen_range(1, 69);
    println!("Random byte prefix len is {}", len);
    let bytes = util::gen_random_bytes(&mut rng, len);
    Self::new(oracle, bytes)
  }
}

impl<O: Oracle> Oracle for ConstantPrepend<O> {
  fn encode(&self, input: &[u8]) -> OracleResult {
    let mut full_input = self.prefix.clone();
    full_input.extend(input);
    self.oracle.encode(&full_input)
  }
}
