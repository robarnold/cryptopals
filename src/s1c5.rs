use util;
use xor;

#[test]
fn challenge() {
  let poem = String::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
  let key = String::from("ICE");
  assert_eq!(
    util::parse_byte_string("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"),
    xor::buffer_repeating(poem.as_bytes(), key.as_bytes())
  );
}

