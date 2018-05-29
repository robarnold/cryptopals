struct OracleResult {
  data: Vec<u8>,
  is_ecb: bool,
}

fn oracle(input: &[u8]) -> OracleResult {
  use aes;
  use pkcs7;
  use rand::prelude::*;
  use util;
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

#[test]
fn challenge() {
  use analysis;
  let input = include_bytes!("s1c6_decoded.txt");
  for _ in 0..100 {
    let result = oracle(input);
    let is_likely_ecb = analysis::likely_aes_ecb_score(&result.data) > 0;
    assert_eq!(result.is_ecb, is_likely_ecb);
  }
}
