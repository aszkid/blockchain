extern crate rand;
extern crate sha2;
extern crate ed25519_dalek;
extern crate base64;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate rmp_serde as rmps;
#[macro_use]
extern crate shrinkwraprs;

use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::env;
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use ed25519_dalek::{SecretKey, Signature};
use rand::OsRng;
use serde::{Serialize};


// Little hack to allow painless implementation of
// serde's Serialize and Deserialize traits on ed25519_dalek's PublicKey
//
#[derive(Shrinkwrap)]
struct PublicKey(ed25519_dalek::PublicKey);

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[derive(Serialize)]
struct Output {
    // Amount of currency units to send
    //
    amount: u64,
    // Destination public key
    //
    creditor: PublicKey,
}


#[derive(Shrinkwrap)]
struct TxHash([u8; 64]);

impl Serialize for TxHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

#[derive(Serialize)]
struct Input {
    // Hash of a transaction
    // TODO: check if serde is using `serialize_bytes` for this field
    //
    tx: TxHash,
    // Index of output referenced in the transaction
    //
    index: u8
}

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
        TxHash([0; 64])
    }
}

struct Block {
    // 32-byte SHA-256 hash of the previous block
    //
    prev_hash: [u8; 32],
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
    fn from_bytes(name: String, buf: &[u8; 32]) -> Account {
        Account {
            name: name,
            secret: match SecretKey::from_bytes(buf) {
                Ok(kp) => kp,
                Err(_) => panic!("Secret key data is malformed!")
            }
        }
    }

    fn to_file(&self, path: PathBuf)  {
        let mut f = File::create(&path).unwrap();
        match f.write(&self.secret.to_bytes()) {
            Ok(num) => {
                if num != 32 {
                    panic!("Could not save all 32 bytes of the secret key into `{}`!", path.display());
                }
            },
            _ => panic!("Failed to write secret key `{}`!", path.display())
        };
    }

    fn from_file(name: String, path: PathBuf) -> Account {
        println!("Importing account `{}` from file...", &name);

        // Import account's keypair file if exists and is valid, generate otherwise
        //
        match File::open(&path) {
            Ok(mut f) => {
                let mut buf: [u8; 32] = [0; 32];
                match f.read(&mut buf) {
                    Ok(num) => {
                        if num != 32 {
                            panic!("Could not read 32 bytes from `{}`!", path.display());
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
                    name: name,
                    secret: SecretKey::generate(&mut csprng)
                };
                acct.to_file(path);
                acct
            }
        }
    }

    fn public_key(&self) -> PublicKey {
        PublicKey(ed25519_dalek::PublicKey::from_secret::<sha2::Sha512>(&self.secret))
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
        args[2].clone(),
        secret
    );

    println!("Using account `{}` with public key `{}`...",
        account.name,
        base64::encode(&account.public_key().to_bytes()[..])
    );

    // Work buffer
    //
    let mut buf = Vec::new();

    // Test output
    //
    let out = Output { amount: 879, creditor: account.public_key() };
    out.serialize(&mut rmps::Serializer::new(&mut buf)).unwrap();
    println!("Output serialized: {:?}", base64::encode(&buf));

    // Test public key
    //
    account.public_key().serialize(&mut rmps::Serializer::new(&mut buf)).unwrap();
    println!("Serialized public key: {:?}", base64::encode(&buf));
    
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
    let mut buffer = [0; 512];
    stream.read(&mut buffer).unwrap();
    println!("Request: {}", String::from_utf8_lossy(&buffer[..]));
}
