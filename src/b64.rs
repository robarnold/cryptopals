pub fn encode(bytes: &[u8]) -> String {
  let table = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
  ];
  let mut s = String::from("");
  for chunk in bytes.chunks(3) {
    match chunk.len() {
      1 => {
        let b1 = chunk[0];
        let i1 = (b1 >> 2 & 0x3f) as usize;
        let i2 = (b1 << 4 & 0x3f) as usize;
        s.push(table[i1]);
        s.push(table[i2]);
        s.push('=');
        s.push('=');
      }
      2 => {
        let b1 = chunk[0];
        let b2 = chunk[1];
        let i1 = (b1 >> 2 & 0x3f) as usize;
        let i2 = (b1 << 4 & 0x30) as usize | (b2 >> 4 & 0x0f) as usize;
        let i3 = (b2 << 2 & 0x3f) as usize;
        s.push(table[i1]);
        s.push(table[i2]);
        s.push(table[i3]);
        s.push('=');
      }
      3 => {
        let b1 = chunk[0];
        let b2 = chunk[1];
        let b3 = chunk[2];
        let i1 = (b1 >> 2 & 0x3f) as usize;
        let i2 = (b1 << 4 & 0x30) as usize | (b2 >> 4 & 0x0f) as usize;
        let i3 = (b2 << 2 & 0x3f) as usize | (b3 >> 6 & 0x03) as usize;
        let i4 = (b3 & 0x3f) as usize;
        s.push(table[i1]);
        s.push(table[i2]);
        s.push(table[i3]);
        s.push(table[i4]);
      }
      _ => panic!("Chunk size too small"),
    }
  }
  s
}

#[test]
fn base64_one_letter() {
  assert_eq!(String::from("TQ=="), encode(&[0x4d]));
}

#[test]
fn base64_two_letter2() {
  assert_eq!(String::from("TWE="), encode(&[0x4d, 0x61]));
}

#[test]
fn base64_three_letter2() {
  assert_eq!(String::from("TWFu"), encode(&[0x4d, 0x61, 0x6e]));
}


