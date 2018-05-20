use std::ops::BitXor;
use std::ops::BitXorAssign;
use xor;

const RCON: [u8; 11] = [
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
];

const SBOX: [u8; 256] = [
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

fn sbox(data: &mut [u8]) {
  for e in data.iter_mut() {
    *e = SBOX[*e as usize];
  }
}

fn to_four_byte_array(data: &[u8]) -> [u8; 4] {
  [data[0], data[1], data[2], data[3]]
}

enum Mode {
  Xor,
  Sbox,
  Full,
}

fn generate_four_bytes(
  key_length: usize,
  expanded_key: &[u8],
  rcon_iteration: &mut usize,
  mode: Mode,
) -> [u8; 4] {
  let i = expanded_key.len();
  let source_bytes = &expanded_key[i - 4..i];
  let mut t: [u8; 4] = to_four_byte_array(source_bytes);
  match mode {
    Mode::Xor => {}
    Mode::Sbox => {
      sbox(&mut t);
    }
    Mode::Full => {
      t.rotate_left(1);
      sbox(&mut t);
      t[0].bitxor_assign(RCON[*rcon_iteration]);
      *rcon_iteration += 1;
    }
  };
  let xor_source = &expanded_key[i - key_length..i - key_length + 4];
  xor::buffer_mut(&mut t, xor::Key::FullBuffer(xor_source));
  t
}

fn expand_key(key: &[u8]) -> Vec<u8> {
  let key_length = key.len();
  let (rounds, sbox_round, extra_expansions) = match key_length {
    16 => (10, false, 0),
    24 => (12, false, 2),
    32 => (14, true, 3),
    len => panic!("Unsupported key length {}", len),
  };
  let expanded_key_size = 16 * (rounds + 1);
  let mut expanded_key = Vec::with_capacity(expanded_key_size);
  expanded_key.extend_from_slice(&key);
  let mut rcon_iteration = 1usize;
  while expanded_key.len() < expanded_key_size {
    let t = generate_four_bytes(key_length, &expanded_key, &mut rcon_iteration, Mode::Full);
    expanded_key.extend(t.iter());
    for _i in 0..3 {
      let t = generate_four_bytes(key_length, &expanded_key, &mut rcon_iteration, Mode::Xor);
      expanded_key.extend(t.iter());
    }
    if sbox_round {
      let t = generate_four_bytes(key_length, &expanded_key, &mut rcon_iteration, Mode::Sbox);
      expanded_key.extend(t.iter());
    }
    for _i in 0..extra_expansions {
      let t = generate_four_bytes(key_length, &expanded_key, &mut rcon_iteration, Mode::Xor);
      expanded_key.extend(t.iter());
    }
  }
  // Truncate any extra bytes
  expanded_key.resize(expanded_key_size, 0);
  if expanded_key.len() != expanded_key_size {
    panic!("Expanded key is too long: {}", expanded_key.len());
  }
  expanded_key
}

#[test]
fn expand_key_16() {
  use util::parse_byte_string;
  assert_eq!(
    parse_byte_string(
      "00000000000000000000000000000000626363636263636362636363626363639b9898c9f9fbfbaa9b9898c9f9fbfbaa90973450696ccffaf2f457330b0fac99ee06da7b876a1581759e42b27e91ee2b7f2e2b88f8443e098dda7cbbf34b9290ec614b851425758c99ff09376ab49ba7217517873550620bacaf6b3cc61bf09b0ef903333ba9613897060a04511dfa9fb1d4d8e28a7db9da1d7bb3de4c664941b4ef5bcb3e92e21123e951cf6f8f188e"
    ),
    expand_key(&vec![0; 16])
  );
  assert_eq!(
    parse_byte_string(
      "ffffffffffffffffffffffffffffffffe8e9e9e917161616e8e9e9e917161616adaeae19bab8b80f525151e6454747f0090e2277b3b69a78e1e7cb9ea4a08c6ee16abd3e52dc2746b33becd8179b60b6e5baf3ceb766d488045d385013c658e671d07db3c6b6a93bc2eb916bd12dc98de90d208d2fbb89b6ed5018dd3c7dd15096337366b988fad054d8e20d68a5335d8bf03f233278c5f366a027fe0e0514a3d60a3588e472f07b82d2d7858cd7c326"
    ),
    expand_key(&vec![0xff; 16])
  );
  assert_eq!(
    parse_byte_string(
      "000102030405060708090a0b0c0d0e0fd6aa74fdd2af72fadaa678f1d6ab76feb692cf0b643dbdf1be9bc5006830b3feb6ff744ed2c2c9bf6c590cbf0469bf4147f7f7bc95353e03f96c32bcfd058dfd3caaa3e8a99f9deb50f3af57adf622aa5e390f7df7a69296a7553dc10aa31f6b14f9701ae35fe28c440adf4d4ea9c02647438735a41c65b9e016baf4aebf7ad2549932d1f08557681093ed9cbe2c974e13111d7fe3944a17f307a78b4d2b30c5"
    ),
    expand_key(&parse_byte_string("000102030405060708090a0b0c0d0e0f"))
  );
  assert_eq!(
    parse_byte_string(
      "6920e299a5202a6d656e636869746f2afa8807605fa82d0d3ac64e6553b2214fcf75838d90ddae80aa1be0e5f9a9c1aa180d2f1488d0819422cb6171db62a0dbbaed96ad323d173910f67648cb94d693881b4ab2ba265d8baad02bc36144fd50b34f195d096944d6a3b96f15c2fd9245a7007778ae6933ae0dd05cbbcf2dcefeff8bccf251e2ff5c5c32a3e7931f6d1924b7182e7555e77229674495ba78298cae127cdadb479ba8f220df3d4858f6b1"
    ),
    expand_key(&parse_byte_string("6920e299a5202a6d656e636869746f2a"))
  );
}

#[test]
fn expand_key_24() {
  assert_eq!(208, expand_key(&vec![0; 24]).len());
}

#[test]
fn expand_key_32() {
  assert_eq!(240, expand_key(&vec![0; 32]).len());
}

fn add_round_key(state: &mut [u8], key: &[u8]) {
  xor::buffer_mut(state, xor::Key::FullBuffer(key));
}

// Shifted by 0, 1, 2, 3 columns
const ROW_SHIFTS: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

fn shift_rows(state: &mut [u8]) {
  let copy = state.to_vec();
  for (index, e) in state.iter_mut().enumerate() {
    *e = copy[ROW_SHIFTS[index]];
  }
}

#[test]
fn test_shift_rows() {
  let mut rows = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
  shift_rows(&mut rows);
  assert_eq!(
    rows,
    [1, 6, 11, 16, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12]
  );
}

const COLUMN_MATRIX: [u8; 16] = [2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2];

fn gmul(mut a: u8, mut b: u8) -> u8 {
  let mut p = 0;
  for _ in 0..8 {
    if (b & 0x1) != 0 {
      p.bitxor_assign(a);
    }
    let has_high_bit = (a & 0x80) == 0x80;
    a <<= 1;
    if has_high_bit {
      a.bitxor_assign(0x1b);
    }
    b >>= 1;
  }
  p
}

fn mix_column(state_column: &[u8]) -> Vec<u8> {
  COLUMN_MATRIX
    .chunks(4)
    .map(|mc| {
      mc.iter()
        .enumerate()
        .map(|(i, &coefficient)| gmul(coefficient, state_column[i]))
        .fold(None, |accum, current| match accum {
          None => Some(current),
          Some(x) => Some(x.bitxor(current)),
        })
        .unwrap()
    })
    .collect()
}

#[test]
fn test_mix_column() {
  use util::parse_byte_string;
  assert_eq!(
    parse_byte_string("8e4da1bc"),
    mix_column(&parse_byte_string("db135345")),
  );
  assert_eq!(
    parse_byte_string("9fdc589d"),
    mix_column(&parse_byte_string("f20a225c")),
  );
  assert_eq!(
    parse_byte_string("01010101"),
    mix_column(&parse_byte_string("01010101")),
  );
  assert_eq!(
    parse_byte_string("c6c6c6c6"),
    mix_column(&parse_byte_string("c6c6c6c6")),
  );
  assert_eq!(
    parse_byte_string("d5d5d7d6"),
    mix_column(&parse_byte_string("d4d4d4d5")),
  );
  assert_eq!(
    parse_byte_string("4d7ebdf8"),
    mix_column(&parse_byte_string("2d26314c")),
  );
}

fn mix_columns(state: &mut [u8]) {
  for column in state.chunks_mut(4) {
    let new_column = mix_column(column);
    column.copy_from_slice(&new_column);
  }
}

pub fn ecb(data: &[u8], key: &[u8]) -> Vec<u8> {
  let mut v = Vec::with_capacity(data.len());
  let expanded_key = expand_key(key);
  let last_round = expanded_key.chunks(key.len()).count() - 1;
  for chunk in data.chunks(16) {
    let mut state = chunk.to_vec();
    // Pad out to 16 bytes
    state.resize(16, 0);
    for (round, round_key) in expanded_key.chunks(state.len()).enumerate() {
      if round_key.len() != 16 {
        panic!("Invalid key length of {}", round_key.len());
      }
      println!("on round {}", round);
      match round {
        0 => {
          add_round_key(&mut state, round_key);
        }
        n if n != last_round => {
          sbox(&mut state);
          shift_rows(&mut state);
          mix_columns(&mut state);
          add_round_key(&mut state, round_key);
        }
        _ => {
          sbox(&mut state);
          shift_rows(&mut state);
          add_round_key(&mut state, round_key);
        }
      }
    }
    v.extend(state);
  }
  v
}

#[test]
fn ecb_once_16() {
  ecb(&vec![0; 16], &vec![0; 16]);
}

#[test]
fn ecb_once_24() {
  ecb(&vec![0; 24], &vec![0; 24]);
}

#[test]
fn ecb_once_32() {
  ecb(&vec![0; 32], &vec![0; 32]);
}
