#[macro_use]
#[cfg(test)]
extern crate quickcheck;

extern crate rand;
extern crate rayon;

pub mod aes;
pub mod analysis;
pub mod b64;
pub mod oracle;
pub mod pkcs7;
pub mod util;
pub mod xor;

mod s1c1;
mod s1c2;
mod s1c3;
mod s1c4;
mod s1c5;
mod s1c6;
mod s1c7;
mod s1c8;

mod s2c10;
mod s2c11;
mod s2c12;
mod s2c13;
mod s2c14;
mod s2c15;
mod s2c16;
mod s2c9;
