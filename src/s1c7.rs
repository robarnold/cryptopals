#[test]
fn challenge() {
  use std::str;

  use aes;
  use util;

  let encoded_bytes = util::read_encoded_data(include_bytes!("s1c7.txt"));
  println!("encoded len: {}", encoded_bytes.len());
  let decoded_data = aes::perform(
    &encoded_bytes,
    "YELLOW SUBMARINE".as_bytes(),
    aes::Operation::Decrypt,
    aes::CipherMode::ECB,
  );
  let maybe_string = str::from_utf8(&decoded_data);
  match maybe_string {
    Err(e) => {
      let lossy_string = String::from_utf8_lossy(&decoded_data);
      println!("Lossy string {}", lossy_string);
      panic!("Error is {}", e);
    }
    Ok(string) => {
      let reference = str::from_utf8(include_bytes!("s1c7_decoded.txt")).unwrap();
      assert_eq!(reference, string);
    }
  }
}
