use util;
use xor;

#[test]
fn challenge() {
  let result = util::parse_byte_string("746865206b696420646f6e277420706c6179");
  let data = &util::parse_byte_string("1c0111001f010100061a024b53535009181c");
  let key = &util::parse_byte_string("686974207468652062756c6c277320657965");
  assert_eq!(result, xor::buffer_full_key(data, key));
}


