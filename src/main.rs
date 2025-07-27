#[macro_use]
extern crate cfg_if;

use osshkeys::error::OsshResult;
use osshkeys::{cipher::Cipher, KeyPair, KeyType, PublicKey, PublicParts};
use osshkeys::keys::FingerprintHash;
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::*;
use std::path::Path;
use clap::Parser;
use rpassword::read_password;
use std::fmt::Display;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Type [internal, external, deployed]
    #[arg(short, long)]
    keytype: String,

    /// Algorith [RSA, ED25519]
    #[arg(short, long, default_value_t = String::from("RSA"))]
    algorithm: String,
}

fn get_passwords() -> (String, String) {
    print!("Enter password: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();
    print!("Enter password second time: ");
    io::stdout().flush().unwrap();
    let password_second = read_password().unwrap();
    return (password, password_second);
}

fn print_fingerprint<P: Display + AsRef<Path>>(path: P) -> OsshResult<()> {
    print!("{}: ", path);
    match fs::read_to_string(path) {
        Ok(s) => {
            let pubkey = PublicKey::from_keystr(&s)?;
            let mut hs = hex::encode_upper(pubkey.fingerprint(FingerprintHash::SHA256)?);
            let mut result = String::new();
            for (i, c) in hs.chars().enumerate() {
                result.push(c);
                if (i + 1) % 2 == 0 && (i + 1) < hs.len() {
                    result.push_str(":");
                }
            }
            println!(
                "SHA256:{}",
                result
            );
        }
        Err(e) => {
            println!("{}", e);
        }
    }
    Ok(())
}
fn print_fingerprint_art<P: Display + AsRef<Path>>(path: P) -> OsshResult<()> {
    match fs::read_to_string(path) {
        Ok(s) => {
            let pubkey = PublicKey::from_keystr(&s)?;
            println!(
                "{}",
                pubkey.fingerprint_randomart(FingerprintHash::SHA256)?
            );
        }
        Err(e) => {
            println!("{}", e);
        }
    }
    Ok(())
}
fn main() -> OsshResult<()> {
    let args = Args::parse();
    let mut password = String::from("none");
    let mut p_second = String::from("none");
    loop {
        (password, p_second) = get_passwords();
        if password != p_second {
            println!("Passwords do not match. Try again")
        } else {
            break;
        }
    }
    
    let filename = &args.keytype;

    // Generate a keypair
    let keypair;
    if args.algorithm == "RSA" {
        keypair = KeyPair::generate(KeyType::RSA, 2048)?;
    } else if args.algorithm == "ED25519" {
        keypair = KeyPair::generate(KeyType::ED25519, 256)?;
    } else {
        panic!("Invalid algorithm!")
    }
    // Create the file with permission 0600
    let mut fop = fs::OpenOptions::new();
    fop.write(true).create(true).truncate(true);
    cfg_if! {
        if #[cfg(unix)] {
            fop.mode(0o600);
        }
    }

    let mut f = fop.open(filename)?;
    // Serialize the private key and write it
    f.write_all(
        keypair
            .serialize_openssh(Some(&password), Cipher::Aes256_Ctr)?
            //.serialize_pkcs8(Some(&password))?
            .as_bytes(),
    )?;
    f.sync_all()?;

    // Get the serialized public key
    let pubkey = keypair.serialize_publickey()?;
    let f = format!("{}.pub", filename);


    // Create public key file
    let mut pubf = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(Path::new(filename).with_extension("pub"))?;
    // Write the public key
    writeln!(pubf, "{}", &pubkey)?;
    pubf.sync_all()?;

    let _ = print_fingerprint(&f)?;
    let _ = print_fingerprint_art(&f)?;
    // Print it out
    println!("{}", &pubkey);
    Ok(())
}
