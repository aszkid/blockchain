// Wrapping base conversion in a more convenient way
//
extern crate rust_base58;

use self::rust_base58::{ToBase58, FromBase58};

pub fn encode<T: ?Sized + ToBase58 + AsRef<[u8]>>(input: &T) -> String {
    input.to_base58()
}

pub fn decode<T :?Sized + FromBase58 + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, self::rust_base58::base58::FromBase58Error> {
    input.from_base58()
}
