extern crate rand;
extern crate sha2;
extern crate ed25519_dalek;

use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::env;
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use ed25519_dalek::Keypair;
use rand::OsRng;


struct Account {
    name: String,
    keypair: Keypair
}

impl Account {
    fn from_bytes(name: String, buf: &[u8; 64]) -> Account {
        Account {
            name: name,
            keypair: match Keypair::from_bytes(buf) {
                Ok(kp) => kp,
                Err(_) => panic!("Keypair data is malformed!")
            }
        }
    }

    fn to_file(&self, path: PathBuf)  {
        let mut f = File::create(&path).unwrap();
        match f.write(&self.keypair.to_bytes()) {
            Ok(num) => {
                if num != 64 {
                    panic!("Could not save all 64 bytes of the keypair file `{}`!", path.display());
                }
            },
            _ => panic!("Failed to write keypair file `{}`!", path.display())
        };
    }

    fn from_file(name: String, path: PathBuf) -> Account {
        println!("Importing account `{}` from file...", &name);

        // Import account's keypair file if exists and is valid, generate otherwise
        //
        match File::open(&path) {
            Ok(mut f) => {
                let mut buf: [u8; 64] = [0; 64];
                match f.read(&mut buf) {
                    Ok(num) => {
                        if num != 64 {
                            panic!("Keypair file `{}` is not 64 bytes!", path.display());
                        }

                        Account::from_bytes(name, &buf)
                    },
                    Err(_) => {
                        panic!("Could not read keypair file `{}`!", path.display());
                    }
                }
            },
            _ => {
                println!("Keypair file `{}` does not exist, generating...", path.display());

                let mut csprng: OsRng = OsRng::new().unwrap();
                let acct = Account {
                    name: name,
                    keypair: Keypair::generate::<sha2::Sha512, _>(&mut csprng)
                };
                acct.to_file(path);
                acct
            }
        }
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


    // Set keypair file
    //
    let mut keypair = Path::new(root).join(&args[2]);
    keypair.set_extension("keypair");

    // Open or generate new account
    //
    let account = Account::from_file(
        args[2].clone(),
        keypair
    );

    println!("Using account `{}`...", account.name);

    
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
