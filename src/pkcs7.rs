pub fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
  assert!(block_size > 0);
  assert!(block_size < 256);
  let extra_bytes = block_size - (data.len() % block_size);
  let final_length = data.len() + extra_bytes;
  let mut v = Vec::with_capacity(final_length);
  v.extend_from_slice(data);
  v.resize(final_length, extra_bytes as u8);
  v
}

#[test]
fn pad_aligned_input() {
  const LENGTH: usize = 16;
  const PLAINTEXT: &str = "YELLOW SUBMARINE";
  assert_eq!(
    pad(PLAINTEXT.as_bytes(), LENGTH),
    "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10".as_bytes(),
  );
}

#[test]
fn pad_unaligned_input() {
  const LENGTH: usize = 18;
  const PLAINTEXT: &str = "YELLOW SUBMARINE";
  assert_eq!(
    pad(PLAINTEXT.as_bytes(), LENGTH),
    "YELLOW SUBMARINE\x02\x02".as_bytes(),
  );
}
