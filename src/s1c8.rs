#[test]
fn challenge() {
  use analysis;
  use util;
  let data = util::read_encoded_data_lines(include_bytes!("s1c8.txt"));
  let mut best_index = 0;
  let mut best_score = 0;
  for (i, line) in data.iter().enumerate() {
    let score = analysis::likely_aes_ecb_score(line);
    println!("Score for {}: {}", i, score);
    if score > best_score {
      best_score = score;
      best_index = i;
    }
  }
  assert_eq!(132, best_index);
}
