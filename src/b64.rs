const TABLE: [char; 64] = [
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
  'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
  'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
  '5', '6', '7', '8', '9', '+', '/',
];

pub fn encode(bytes: &[u8]) -> String {
  let mut s = String::from("");
  for chunk in bytes.chunks(3) {
    match chunk.len() {
      1 => {
        let b1 = chunk[0];
        let i1 = (b1 >> 2 & 0x3f) as usize;
        let i2 = (b1 << 4 & 0x3f) as usize;
        s.push(TABLE[i1]);
        s.push(TABLE[i2]);
        s.push('=');
        s.push('=');
      }
      2 => {
        let b1 = chunk[0];
        let b2 = chunk[1];
        let i1 = (b1 >> 2 & 0x3f) as usize;
        let i2 = (b1 << 4 & 0x30) as usize | (b2 >> 4 & 0x0f) as usize;
        let i3 = (b2 << 2 & 0x3f) as usize;
        s.push(TABLE[i1]);
        s.push(TABLE[i2]);
        s.push(TABLE[i3]);
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
        s.push(TABLE[i1]);
        s.push(TABLE[i2]);
        s.push(TABLE[i3]);
        s.push(TABLE[i4]);
      }
      _ => panic!("Chunk size too small"),
    }
  }
  s
}

#[test]
fn encode_one_letter() {
  assert_eq!(String::from("TQ=="), encode(&[0x4d]));
}

#[test]
fn encode_two_letters() {
  assert_eq!(String::from("TWE="), encode(&[0x4d, 0x61]));
}

#[test]
fn encode_three_letters() {
  assert_eq!(String::from("TWFu"), encode(&[0x4d, 0x61, 0x6e]));
}

pub fn decode(s: &str) -> Vec<u8> {
  let groups = s.len() / 4;
  let mut v = Vec::with_capacity(groups * 3);
  for i in 0..groups {
    let positions: Vec<Option<u8>> = s[4 * i..4 * i + 4]
      .chars()
      .map(|c| TABLE.iter().position(|t| t == &c).map(|p| p as u8))
      .collect();
    let mut residual = 0u8;
    for (i, p) in positions.iter().enumerate() {
      match (i, p) {
        (0, None) => panic!("No valid chars in this block"),
        (1, None) => {
          break;
        }
        (2, None) => {
          break;
        }
        (3, None) => {
          break;
        }
        (0, Some(p)) => residual = p << 2,
        (1, Some(p)) => {
          v.push(residual | p >> 4);
          residual = p << 4;
        }
        (2, Some(p)) => {
          v.push(residual | p >> 2);
          residual = p << 6;
        }
        (3, Some(p)) => {
          v.push(residual | p);
          residual = 0;
        }
        (_, _) => panic!("Unknown decoder state"),
      }
    }
  }
  v
}

#[test]
fn decode_one_letter() {
  assert_eq!(vec![0x4d], decode("TQ=="));
}

#[test]
fn decode_two_letters() {
  assert_eq!(vec![0x4d, 0x61], decode("TWE="));
}

#[test]
fn decode_three_letters() {
  assert_eq!(vec![0x4d, 0x61, 0x6e], decode("TWFu"));
}
