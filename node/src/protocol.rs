use std::io::prelude::*;
use serde::{Serialize, Deserialize};
use serde::{Serializer, Deserializer};
use serde::de::Error as SerdeError;
use std::net::Ipv6Addr;
use ed25519_dalek::{PublicKey, Signature, SecretKey};

// We use SHA-512 for most hashing purposes
//
pub const HASH_LENGTH: usize = 64;

#[derive(Serialize, Deserialize)]
pub struct Output {
    // Amount of currency units to send
    //
    amount: u64,
    // Destination public key
    //
    creditor: PublicKey,
}


#[derive(Shrinkwrap)]
pub struct TxHash([u8; HASH_LENGTH]);

impl Serialize for TxHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for TxHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        use serde::de::Visitor;
        struct TxHashVisitor;

        impl<'de> Visitor<'de> for TxHashVisitor {
            type Value = TxHash;

            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                formatter.write_str("a transaction hash as a 32-byte SHA-512 hash")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<TxHash, E>
                where E: SerdeError
            {
                match bytes.len() {
                    HASH_LENGTH => {
                        let mut h: [u8; HASH_LENGTH] = [0; HASH_LENGTH];
                        h.copy_from_slice(&bytes[..]);
                        Ok(TxHash(h))
                    },
                    _ => Err(SerdeError::invalid_length(bytes.len(), &self))
                }
            }
        }

        deserializer.deserialize_bytes(TxHashVisitor)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Input {
    // Hash of the referenced transaction
    //
    tx: TxHash,
    // Index of output referenced in the transaction
    //
    index: u8
}

#[derive(Serialize, Deserialize)]
pub struct Transaction {
    // Source public key
    //
    debtor: PublicKey,
    // List of tx inputs
    //
    inputs: Vec<Input>,
    // List of tx outputs
    //
    outputs: Vec<Output>,
    // Tx signature, by the debtor
    //
    signature: Signature
}


impl Transaction {

    pub fn sign(&mut self, s: SecretKey) {
        self.signature = s.expand::<::sha2::Sha512>()
          .sign::<::sha2::Sha512>(
            &self.hash().0,
            &PublicKey::from_secret::<::sha2::Sha512>(&s)
        );
    }

    pub fn hash(&self) -> TxHash {
        TxHash([0; HASH_LENGTH])
    }

    // Verify whether the transaction's signature is valid,
    // i.e.
    //   1. that the transaction has not been tampered during broadcast; and
    //   2. that the debtor spends outputs credited to his public key
    pub fn verify(&self) -> bool {
        self.debtor.verify::<::sha2::Sha512>(&self.hash().0, &self.signature).is_ok()
    }
}

pub struct Block {
    // Hash of the previous block
    //
    prev_hash: TxHash,
    // Nonce used to verify signature
    //
    nonce: u64,
    // Signature
    //
    signature: Signature
}

#[derive(Serialize, Deserialize)]
pub struct Node {
    pub addr: Ipv6Addr,
    pub port: u16
}

#[derive(Serialize, Deserialize)]
pub struct MsgHandshake {
    pub nodes: Vec<Node>
}

#[derive(Serialize, Deserialize)]
pub struct MsgShareTx {
    pub txs: Vec<Transaction>
}
