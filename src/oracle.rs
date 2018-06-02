use aes;
use pkcs7;
use rand::prelude::*;
use util;

pub struct OracleResult {
  pub data: Vec<u8>,
  pub is_ecb: bool,
}

pub trait Oracle {
  fn encode(&mut self, input: &[u8]) -> OracleResult;
}

pub struct Random<R: Rng> {
  rng: R,
}

impl Random<ThreadRng> {
  pub fn new() -> Random<ThreadRng> {
    let rng = thread_rng();
    Random { rng }
  }
}

impl<R: Rng> Oracle for Random<R> {
  fn encode(&mut self, input: &[u8]) -> OracleResult {
    let key = util::gen_random_bytes(&mut self.rng, 16);
    let iv = util::gen_random_bytes(&mut self.rng, 16);
    let is_ecb: bool = self.rng.gen();
    let cipher_mode = if is_ecb {
      aes::CipherMode::ECB
    } else {
      aes::CipherMode::CBC(&iv)
    };
    let mut noisied_data = Vec::new();
    for _ in 0..self.rng.gen_range(5, 10) {
      noisied_data.push(self.rng.gen());
    }
    noisied_data.extend_from_slice(input);
    for _ in 0..self.rng.gen_range(5, 10) {
      noisied_data.push(self.rng.gen());
    }
    let data = pkcs7::pad(&noisied_data, 16);
    let encoded_data = aes::perform(&data, &key, aes::Operation::Encrypt, cipher_mode);
    OracleResult {
      data: encoded_data,
      is_ecb,
    }
  }
}

pub struct AES128Append {
  key: Vec<u8>,
  suffix: Vec<u8>,
}

impl AES128Append {
  pub fn new(suffix: Vec<u8>) -> AES128Append {
    let mut rng = thread_rng();
    let key = util::gen_random_bytes(&mut rng, 16);
    AES128Append { key, suffix }
  }
}

impl Oracle for AES128Append {
  fn encode(&mut self, input: &[u8]) -> OracleResult {
    let mut full_input = input.to_vec();
    full_input.extend(&self.suffix);
    let data = pkcs7::pad(&full_input, 16);
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
