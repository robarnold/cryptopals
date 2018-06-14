#[test]
fn challenge() {
  use oracle;
  use oracle::{DecodableOracle, Oracle};
  use rand;
  use std::str;
  use util;
  const MAGIC_STRING: &str = ";admin=true;";
  let iv = util::gen_random_bytes(&mut rand::thread_rng(), 16);
  let o = oracle::QuoteBytes::new(
    oracle::ConstantAppend::new(
      oracle::ConstantPrepend::new(
        oracle::AES128::with_cbc(iv),
        "comment1=cooking%20MCs;userdata=".as_bytes().to_vec(),
      ),
      ";comment2=%20like%20a%20pound%20of%20bacon"
        .as_bytes()
        .to_vec(),
    ),
    &[b';', b'&'],
  );

  let validate_ciphertext = |ciphertext: &[u8]| -> bool {
    let plaintext = o.decode(&ciphertext);
    let s = unsafe { str::from_utf8_unchecked(&plaintext) };
    println!("Plaintext is {}", s);
    s.contains(MAGIC_STRING)
  };

  let ciphertext = o.encode(MAGIC_STRING.as_bytes()).data;
  let initial_plaintext = o.decode(&ciphertext);
  println!(
    "Initial plaintext is {}",
    str::from_utf8(&initial_plaintext).unwrap()
  );
  let insertion_index = initial_plaintext.iter().position(|&b| b == b'b').unwrap();
  let insertion_chunk_index = insertion_index / 16;
  let relative_insertion_index = insertion_index % 16;
  assert!(insertion_chunk_index >= 1);
  println!(
    "Data is in chunk {} at offset {}",
    insertion_chunk_index, relative_insertion_index
  );
  let modification_index = 16 * (insertion_chunk_index - 1) + relative_insertion_index;
  let mut modified_ciphertext = ciphertext.clone();
  for &i in [0, MAGIC_STRING.len() - 1].iter() {
    let write_index = modification_index + i;
    let ciphertext_read_index = modification_index + i;
    let target_byte = initial_plaintext[insertion_index + i];
    println!(
      "Goal is to convert {} {:b} into ; ({:b})",
      str::from_utf8(&[target_byte]).unwrap(),
      target_byte,
      b';'
    );
    let modified_src = ciphertext[ciphertext_read_index] ^ target_byte ^ b';';
    modified_ciphertext[write_index] = modified_src;
  }
  assert_eq!(true, validate_ciphertext(&modified_ciphertext));
}
