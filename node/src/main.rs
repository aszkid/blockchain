#![feature(plugin)]
#![plugin(rocket_codegen)]
extern crate rand;
extern crate sha2;
extern crate ed25519_dalek;
#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate rmp;
extern crate rmp_serde as rmps;
#[macro_use] extern crate byteorder;
#[macro_use] extern crate shrinkwraprs;
extern crate ipnet;

// Crate-level modules
pub mod method;
pub mod rpc;
pub mod base58;
pub mod protocol;

use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::env;
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::thread;
use ed25519_dalek::{SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey, SecretKey, Signature};
use rand::OsRng;
use byteorder::{ReadBytesExt, BigEndian, LittleEndian, NetworkEndian};


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

    // Start local JSON-RPC server (user-to-node comm)
    let mut rpc = rpc::Server::new();
    rpc.add_method(method::DumpPrivKey);
    rpc.run();


    // Start good-old TCP server (node-to-node comm)
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
    // Protocol message format:
    // "BLOCK" | 4 byte version | 4 byte msg. type | 4 bytes payload size | payload
    // Message payload is MessagePack-encoded

    const MAGIC_SIZE: usize = 5;
    let mut magic: [u8; MAGIC_SIZE] = [0; MAGIC_SIZE];
    stream.read_exact(&mut magic).unwrap();
    if &magic[..] != b"BLOCK" {
        println!("Message header is not `BLOCK`!");
        return
    }

    // We don't really take versions seriously for now -- but just for the sake of it,
    // having this field from the very start gives us margin for the future
    let v = stream.read_u32::<NetworkEndian>().unwrap();
    println!("Message refers to protocol version {}", v);

    let t = stream.read_u32::<NetworkEndian>().unwrap();
    println!("Message type is {}", t);

    let sz = stream.read_u32::<NetworkEndian>().unwrap();
    println!("Payload size is {}", sz);

    let mut buffer = Vec::new();
    stream.take(sz.into()).read_to_end(&mut buffer).unwrap();
    protocol::handle_message(v, t, &buffer.as_slice());
}

