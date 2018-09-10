extern crate rand;
extern crate sha2;
extern crate ed25519_dalek;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate rmp;
extern crate rmp_serde as rmps;
#[macro_use]
extern crate shrinkwraprs;
extern crate byteorder;

use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::env;
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream, Ipv6Addr};
use ed25519_dalek::{SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey, SecretKey, Signature};
use rand::OsRng;
use serde::{Serialize, Deserialize};
use serde::de::Error as SerdeError;
use rmps::{Serializer, Deserializer};
use byteorder::{ReadBytesExt, BigEndian, LittleEndian, NetworkEndian};


// Wrapping base conversion in a more convenient way
//
mod base58 {
    extern crate rust_base58;
    use self::rust_base58::{ToBase58, FromBase58};

    pub fn encode<T: ?Sized + ToBase58 + AsRef<[u8]>>(input: &T) -> String {
        input.to_base58()
    }

    pub fn decode<T :?Sized + FromBase58 + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, self::rust_base58::base58::FromBase58Error> {
        input.from_base58()
    }
}


// We use SHA-512 for most hashing purposes
//
const HASH_LENGTH: usize = 64;

#[derive(Serialize, Deserialize)]
struct Output {
    // Amount of currency units to send
    //
    amount: u64,
    // Destination public key
    //
    creditor: PublicKey,
}


#[derive(Shrinkwrap)]
struct TxHash([u8; HASH_LENGTH]);

impl Serialize for TxHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for TxHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        use serde::de::Visitor;
        struct TxHashVisitor;

        impl<'de> Visitor<'de> for TxHashVisitor {
            type Value = TxHash;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
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
struct Input {
    // Hash of the referenced transaction
    //
    tx: TxHash,
    // Index of output referenced in the transaction
    //
    index: u8
}

#[derive(Serialize, Deserialize)]
struct Transaction {
    // Source public key
    //
    debtor: PublicKey,
    // List of tx inputs
    //
    inputs: Vec<Input>,
    // List of tx outputs
    //
    outputs: Vec<Output>,
}


impl Transaction {
    fn hash(&self) -> TxHash {
        TxHash([0; HASH_LENGTH])
    }
}

struct Block {
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


// Owned account; not the same thing as a random
// 'account' in the network
//
struct Account {
    name: String,
    secret: SecretKey
}

impl Account {
    fn from_bytes(name: &String, buf: &[u8; SECRET_KEY_LENGTH]) -> Account {
        Account {
            name: name.clone(),
            secret: match SecretKey::from_bytes(buf) {
                Ok(kp) => kp,
                Err(_) => panic!("Secret key data is malformed!")
            }
        }
    }

    fn to_file(&self, path: &Path)  {
        let mut f = File::create(path).unwrap();
        match f.write(&self.secret.to_bytes()) {
            Ok(num) => {
                if num != SECRET_KEY_LENGTH {
                    panic!("Could not save all {} bytes of the secret key into `{}`!", SECRET_KEY_LENGTH, path.display());
                }
            },
            _ => panic!("Failed to write secret key `{}`!", path.display())
        };
    }

    fn from_file(name: &String, path: &Path) -> Account {
        println!("Importing account `{}` from file...", &name);

        // Import account's secret key file if exists and is valid, generate otherwise
        //
        match File::open(path) {
            Ok(mut f) => {
                let mut buf: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
                match f.read(&mut buf) {
                    Ok(num) => {
                        if num != SECRET_KEY_LENGTH {
                            panic!("Could not read {} bytes from `{}`!", SECRET_KEY_LENGTH, path.display());
                        }

                        Account::from_bytes(name, &buf)
                    },
                    Err(_) => {
                        panic!("Could not read secret key file `{}`!", path.display());
                    }
                }
            },
            _ => {
                println!("Secret key file `{}` does not exist, generating...", path.display());

                let mut csprng: OsRng = OsRng::new().unwrap();
                let acct = Account {
                    name: name.clone(),
                    secret: SecretKey::generate(&mut csprng)
                };
                acct.to_file(path);
                acct
            }
        }
    }

    fn public_key(&self) -> PublicKey {
        ed25519_dalek::PublicKey::from_secret::<sha2::Sha512>(&self.secret)
    }

}


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        panic!("Need arguments <root> <account_name>!");
    }

    let root = Path::new(&args[1]);
    println!("Using root folder `{}`...", root.display());

    // Create root folder if it does not exist
    //
    match fs::create_dir_all(&root) {
        Err(_) => {
            panic!("Could not create root folder!");
        },
        _ => ()
    };


    // Set secret key file
    //
    let mut secret = Path::new(root).join(&args[2]);
    secret.set_extension("keypair");

    // Open or generate new account
    //
    let account = Account::from_file(
        &args[2],
        &secret
    );

    println!("Using account `{}` with public key `{}` ...",
        account.name,
        base58::encode(&account.public_key().to_bytes()[..])
    );

    let listener: TcpListener;
    let mut port = 7878;
    loop {
        match TcpListener::bind(format!("127.0.0.1:{}", port)) {
            Ok(l) => { listener = l; break; },
            _ => { port += 1; }
        }
    }

    println!("Listening at {}...", port);

    for stream in listener.incoming() {
        handle_connection(stream.unwrap());
    }
}


fn handle_connection(mut stream: TcpStream) {
    const VERSION: u8 = 1;
    // Protocol message format v0.1
    // "BLOCK" | 1 byte version | 1 byte msg. type | 4 bytes payload size | payload

    const HEADER_SIZE: usize = 12;
    let mut header: [u8; HEADER_SIZE] = [0; HEADER_SIZE];

    const MAGIC_SIZE: usize = 5;
    let mut magic: [u8; MAGIC_SIZE] = [0; MAGIC_SIZE];
    stream.read_exact(&mut magic).unwrap();
    if &magic[..] != b"BLOCK" {
        println!("Message header is not `BLOCK`!");
        return
    }

    let v = stream.read_u8().unwrap();
    println!("Message refers to protocol version {}", v);
    if v > VERSION {
        println!("Incompatible versions!");
        return
    }

    let t = stream.read_u8().unwrap();
    println!("Message type is {}", t);

    let sz = stream.read_u32::<NetworkEndian>().unwrap();
    println!("Payload size is {}", sz);

    const MAX_MSG_SIZE: usize = 1024;
    if sz > MAX_MSG_SIZE as u32 {
        println!("Message payload is too large ({} > {})", sz, MAX_MSG_SIZE);
        return
    }

    let mut buffer = Vec::new();
    stream.take(sz.into()).read_to_end(&mut buffer).unwrap();
    handle_message(t, &buffer.as_slice());
}

#[derive(Serialize, Deserialize)]
struct Node {
    addr: Ipv6Addr,
    port: u16
}

#[derive(Serialize, Deserialize)]
struct MsgHandshake {
    nodes: Vec<Node>
}

#[derive(Serialize, Deserialize)]
struct MsgShareTx {
    txs: Vec<Transaction>
}

fn handle_message(t: u8, payload: &[u8]) {
    println!("Handling message with payload of size {}", payload.len());

    let mut de = Deserializer::new(payload);
    if t == 1 {
        // handshake
        let handshake: MsgHandshake = Deserialize::deserialize(&mut de).unwrap();
        for node in &handshake.nodes {
            println!("Got info for node IP `{}`, port `{}`", node.addr, node.port);
        }
    }
}
