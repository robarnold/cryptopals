#[test]
fn challenge() {
  use b64;
  use oracle;
  use oracle::Oracle;
  use rayon::prelude::*;

  let secret_plaintext = b64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
  let secret_plaintext_len = secret_plaintext.len();
  let mut o = oracle::AES128Append::new(secret_plaintext);
  let block_size = oracle::determine_block_size(&mut o);
  assert_eq!(16, block_size);
  assert_eq!(true, oracle::is_using_ecb(&mut o));
  let mut known_bytes = Vec::new();
  while known_bytes.len() < secret_plaintext_len {
    let filler_bytes_required = block_size - 1 - (known_bytes.len() % block_size);
    println!(
      "Known string bytes: {}, filler: {}",
      known_bytes.len(),
      filler_bytes_required
    );
    assert!(filler_bytes_required < block_size);
    let mut test_input = vec![0; filler_bytes_required];
    let expected_chunk_index = known_bytes.len() / block_size;
    // Get the encoded string at an offset where only the last byte in a block is unknown
    let encoded_answer = o.encode(&test_input).data;

    // Add the bytes we to do know about
    test_input.extend_from_slice(&known_bytes);
    let last_index = test_input.len();
    test_input.push(0);
    let answer_block = encoded_answer
      .chunks(block_size)
      .nth(expected_chunk_index)
      .unwrap();
    let (last_byte, _) = (0..u8::max_value())
      .into_par_iter()
      .map_with(test_input, |input, i| {
        input[last_index] = i;
        let encoded_input = o.encode(&input).data;
        let is_match = encoded_input
          .chunks(block_size)
          .nth(expected_chunk_index)
          .unwrap() == answer_block;
        (i, is_match)
      })
      .find_any(|(_, is_match)| *is_match)
      .unwrap();
    known_bytes.push(last_byte);
  }
  let string = String::from_utf8(known_bytes).unwrap();
  assert_eq!("Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n", string);
}
