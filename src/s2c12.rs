use oracle::Oracle;

#[allow(dead_code)]
fn determine_block_size(o: &mut Oracle) -> usize {
  let mut buffer = vec![0; 2];
  for i in 1..256 {
    let output = o.encode(&buffer);
    let mut chunks = output.data.chunks(i);
    let first = chunks.next().unwrap();
    let second = chunks.next().unwrap();
    if first == second {
      return i;
    }
    buffer.push(0);
    buffer.push(0);
  }
  panic!("Unable to find block size");
}

#[test]
fn challenge() {
  use b64;
  use oracle;
  let mut o = oracle::AES128Append::new(
    b64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
  );
  let block_size = determine_block_size(&mut o);
  assert_eq!(16, block_size);
}
