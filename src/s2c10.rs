#[test]
fn challenge() {
  use aes;
  use std::str;
  use util;
  let data = util::read_encoded_data(include_bytes!("s2c10.txt"));
  let key = "YELLOW SUBMARINE".as_bytes();
  let decoded_data = aes::perform(
    &data,
    key,
    aes::Operation::Decrypt,
    aes::CipherMode::CBC(&vec![0; 16]),
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

#[test]
fn encrypt() {
  use aes;
  use util;
  let reference = include_bytes!("s1c7_decoded.txt");
  let iv = vec![0; 16];
  let key = "YELLOW SUBMARINE".as_bytes();
  let encoded_data = aes::perform(
    reference,
    key,
    aes::Operation::Encrypt,
    aes::CipherMode::CBC(&iv),
  );
  assert_eq!(
    encoded_data,
    util::read_encoded_data(include_bytes!("s2c10.txt"))
  );
}
