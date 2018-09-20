use serde::{Serialize, Deserialize};
use serde::{Serializer, Deserializer};
use serde::de::Error as SerdeError;
use std::net::Ipv6Addr;
use ed25519_dalek::{PublicKey, Signature, SecretKey, Keypair};
use sha2::{Sha256, Sha512, Digest};
use base58;
use std::fmt;
use byteorder::{BigEndian, WriteBytesExt};

/// We use SHA-256 for most hashing purposes; 32-byte output
pub const HASH_LENGTH: usize = 32;

/// Public-key hash
#[derive(Shrinkwrap, Serialize, Deserialize, Clone, Copy)]
pub struct Address([u8; HASH_LENGTH]);

impl Address {
    pub fn new() -> Address {
        Address([0; HASH_LENGTH])
    }

    /// Encode in base58
    pub fn display(&self) -> String {
        base58::encode(&(self.0)[..])
    }

    /// Load from hash (raw bytes)
    pub fn from_bytes(b: &[u8]) -> Address {
        let mut addr = Address::new();
        addr.0.copy_from_slice(&b);
        addr
    }

    pub fn as_bytes<'a>(&'a self) -> &'a [u8; HASH_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", base58::encode(&self[..]))
    }
}

/// Transaction output
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct Output {
    /// Amount of currency units to send
    pub amount: u64,
    /// Destination address
    pub creditor: Address,
}

/// Special SHA-256 of a transaction
#[derive(Shrinkwrap, Clone, Copy)]
pub struct TxHash([u8; HASH_LENGTH]);

impl TxHash {
    pub fn new() -> TxHash {
        TxHash([0; HASH_LENGTH])
    }

    /// Load from raw bytes
    pub fn from_bytes(b: &[u8]) -> TxHash {
        let mut hash = TxHash::new();
        hash.0.copy_from_slice(&b);
        hash
    }

    pub fn as_bytes<'a>(&'a self) -> &'a [u8; HASH_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", base58::encode(&self[..]))
    }
}

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
                formatter.write_str("a transaction hash as a 32-byte SHA-256 hash")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<TxHash, E>
                where E: SerdeError
            {
                match bytes.len() {
                    HASH_LENGTH => {
                        let mut h = TxHash::from_bytes(&bytes[..]);
                        Ok(h)
                    },
                    _ => Err(SerdeError::invalid_length(bytes.len(), &self))
                }
            }
        }

        deserializer.deserialize_bytes(TxHashVisitor)
    }
}

/// Source of credit in a transaction
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct Input {
    /// Hash of the referenced transaction
    pub tx: TxHash,
    /// Index of output referenced in the transaction
    pub index: u8,
    /// Unlocking signature
    pub signature: Signature
}

/// Transaction object data
#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction {
    /// Debtor's public key
    debtor: PublicKey,
    /// List of transaction inputs
    inputs: Vec<Input>,
    /// List of transaction outputs
    outputs: Vec<Output>,
}


impl Transaction {
    /// Create empty transaction
    pub fn new(pubk: PublicKey) -> Transaction {
        Transaction {
            debtor: pubk,
            inputs: Vec::new(),
            outputs: Vec::new()
        }
    }

    pub fn attach_input(&mut self, inp: Input) {
        self.inputs.push(inp);
    }

    /// Hash using SHA-256
    pub fn hash(&self) -> TxHash {
        let mut hasher = Sha256::default();

        let mut wtr = vec![];
        wtr.extend_from_slice(self.debtor.as_bytes());
        
        for inp in &self.inputs {
            wtr.extend_from_slice(inp.tx.as_bytes());
            wtr.write_u8(inp.index).unwrap();
        }

        for outp in &self.outputs {
            wtr.write_u64::<BigEndian>(outp.amount).unwrap();
            wtr.extend_from_slice(outp.creditor.as_bytes());
        }


        /*for inp in &self.inputs {
            hasher.input(&inp.tx[..]);
            hasher.input(&vec!(inp.index));
        }
        
        for outp in &self.outputs {
            hasher.input(&vec!(outp.amount));
            hasher.input(outp.creditor);
        }*/

        TxHash::from_bytes(&hasher.result())
    }

    /// Sign transaction data; ready to be broadcasted
    pub fn sign(&mut self, kp: Keypair) {
        for input in &mut self.inputs {
            // Create a simplified transaction containing only current input
            // TODO: find a way to avoid cloning the outputs
            let t = Transaction {
                debtor: kp.public,
                inputs: vec!(*input),
                outputs: self.outputs.clone()
            };
            
            let simplified_hash = t.hash();
            input.signature = kp.sign::<Sha512>(simplified_hash.as_bytes());

            self.outputs = t.outputs;
        }
    }

    /// Verify whether the transaction is valid:
    /// for each input, check whether the 
    pub fn is_valid(&self) -> bool {
        //self.debtor.verify::<::sha2::Sha512>(&self.hash().0, &self.signature).is_ok()
        true
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
