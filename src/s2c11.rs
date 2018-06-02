#[test]
fn challenge() {
  use analysis;
  use oracle;
  use oracle::Oracle;
  let input = include_bytes!("s1c6_decoded.txt");
  let mut o = oracle::Random::new();
  for _ in 0..100 {
    let result = o.encode(input);
    let is_likely_ecb = analysis::likely_aes_ecb_score(&result.data) > 0;
    assert_eq!(result.is_ecb, is_likely_ecb);
  }
}
