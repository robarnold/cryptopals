#[test]
fn challenge() {
  use analysis;
  use oracle;
  use oracle::Oracle;
  use rayon::prelude::*;
  let input = include_bytes!("s1c6_decoded.txt");
  let o = oracle::Random::new();
  (0..100).into_par_iter().for_each(|_| {
    let result = o.encode(input);
    let is_likely_ecb = analysis::likely_aes_ecb_score(&result.data) > 0;
    assert_eq!(result.is_ecb, is_likely_ecb);
  });
}
