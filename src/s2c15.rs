#[test]
fn challenge() {
  use pkcs7::unpad_mut;
  use std::panic;

  assert_eq!(
    true,
    panic::catch_unwind(|| {
      let mut s = String::from("ICE ICE BABY\x04\x04\x04\x04");
      unsafe {
        unpad_mut(s.as_mut_vec(), 16);
      }
      assert_eq!("ICE ICE BABY", &s);
    }).is_ok()
  );

  assert_eq!(
    true,
    panic::catch_unwind(|| {
      let mut s = String::from("ICE ICE BABY\x05\x05\x05\x05");
      unsafe {
        unpad_mut(s.as_mut_vec(), 16);
      }
    }).is_err()
  );

  assert_eq!(
    true,
    panic::catch_unwind(|| {
      let mut s = String::from("ICE ICE BABY\x01\x02\x03\x04");
      unsafe {
        unpad_mut(s.as_mut_vec(), 16);
      }
    }).is_err()
  );
}
