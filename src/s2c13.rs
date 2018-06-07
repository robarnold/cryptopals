#[allow(dead_code)]
fn parse_query_string(s: &str) -> Vec<(&str, &str)> {
  #[derive(Clone)]
  enum State {
    Key(usize),
    Value(usize),
  }
  let mut state = State::Key(0);
  let mut current_key = None;
  let mut map = Vec::new();

  for (i, c) in s.char_indices() {
    state = match (state, c) {
      (State::Key(start), '=') => {
        current_key = Some(&s[start..i]);
        State::Value(i + 1)
      }
      (State::Value(start), '&') => {
        map.push((current_key.unwrap(), &s[start..i]));
        current_key = None;
        State::Key(i + 1)
      }
      (state, _) => state,
    };
  }
  match state {
    State::Key(_) => panic!("Invalid state"),
    State::Value(start) => {
      map.push((current_key.unwrap(), &s[start..s.len()]));
    }
  }
  map
}

#[test]
fn test_parse_query_string() {
  let map = parse_query_string("foo=bar&baz=qux&zap=zazzle");
  assert_eq!(vec![("foo", "bar"), ("baz", "qux"), ("zap", "zazzle")], map);
}

fn gen_query_string(h: &[(&str, &str)]) -> String {
  fn append_to_string(dest: &mut String, s: &str) {
    for sub_str in s.matches(|c| c != '&' && c != '=') {
      dest.push_str(sub_str);
    }
  };
  let mut query_string = String::new();
  for (k, v) in h.iter() {
    if !query_string.is_empty() {
      query_string.push('&');
    }
    append_to_string(&mut query_string, k);
    query_string.push('=');
    append_to_string(&mut query_string, v);
  }
  query_string
}

#[test]
fn test_gen_query_string() {
  fn test_string(s: &str) {
    let map = parse_query_string(s);
    assert_eq!(map, parse_query_string(&gen_query_string(&map)));
  }
  test_string("foo=bar&baz=qux&zap=zazzle");
  test_string("foo=bar");

  assert_eq!(
    "email=foo@bar.comroleadmin",
    gen_query_string(&[("email", "foo@bar.com&role=admin")])
  );
}

#[allow(dead_code)]
fn profile_for(s: &str) -> String {
  gen_query_string(&vec![("email", s), ("uid", "10"), ("role", "user")])
}

#[test]
fn challenge() {
  use oracle;
  use oracle::Oracle;
  use std::str;

  const EMAIL_PREFIX: &str = "email=";
  const ROLE_PREFIX: &str = "role=";
  const INITIAL_EMAIL: &str = "foo@bar.com";
  const ADMIN_START: &str = "admin";

  let o = oracle::AES128::new();
  let compute_role_offset = |o: &oracle::AES128, email: &str| {
    let ciphertext = o.encode(profile_for(email).as_bytes()).data;
    let plaintext = String::from_utf8(o.decode(&ciphertext)).unwrap();
    let mut chunk: &str = &plaintext;
    while chunk.len() > 16 {
      let parts = chunk.split_at(16);
      println!("chunk: {}", parts.0);
      chunk = parts.1;
    }
    println!("chunk: {}", chunk);
    plaintext.find(ROLE_PREFIX).unwrap() + ROLE_PREFIX.len() - 1
  };
  let role_offset = compute_role_offset(&o, INITIAL_EMAIL);
  println!("Role offset {}", role_offset);

  let block_size = oracle::determine_block_size(&o);
  let relative_role_offset = role_offset % block_size;
  println!("Relative role offset {}", relative_role_offset);

  let filler_needed = 3 * block_size - 1 - relative_role_offset;
  let line1_filler_needed = block_size - EMAIL_PREFIX.len();
  let line2_filler_needed = block_size - ADMIN_START.len();
  let line3_filler_needed =
    filler_needed - (line1_filler_needed + ADMIN_START.len() + line2_filler_needed);
  println!("filler needed: {}", filler_needed);
  let email_address = format!(
    "{}{}{}{}{}",
    &"a".repeat(line1_filler_needed),
    ADMIN_START,
    &str::from_utf8(&[line2_filler_needed as u8])
      .unwrap()
      .repeat(line2_filler_needed),
    &"B".repeat(line3_filler_needed),
    INITIAL_EMAIL
  );
  assert_eq!(15, compute_role_offset(&o, &email_address) % block_size);
  let ciphertext = o.encode(profile_for(&email_address).as_bytes()).data;
  let chunks: Vec<&[u8]> = ciphertext.chunks(block_size).collect();
  let modified_ciphertext = [chunks[0], chunks[2], chunks[3], chunks[1]].concat();
  let plaintext = String::from_utf8(o.decode(&modified_ciphertext)).unwrap();
  assert_eq!(
    "email=aaaaaaaaaaBBBBBBBBfoo@bar.com&uid=10&role=admin",
    plaintext
  );
  let profile = parse_query_string(&plaintext);
  let role = profile.iter().find(|(k, _)| k == &"role").unwrap().1;
  assert_eq!("admin", role);
}
