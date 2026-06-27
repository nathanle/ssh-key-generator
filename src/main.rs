#[macro_use]
extern crate cfg_if;

use osshkeys::error::OsshResult;
use osshkeys::{cipher::Cipher, KeyPair, KeyType, PublicKey, PublicParts};
use osshkeys::keys::FingerprintHash;
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::*;
use std::path::{Path, PathBuf};
use clap::Parser;
use rpassword::read_password;
use std::fmt::Display;
use chrono::{Local, NaiveDate};
use emoji_printer::print_emojis;
use std::io::prelude::*;
use std::net::TcpStream;
use ssh2::Session;
use serde::Deserialize;
use gethostname::gethostname;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Type [internal, external, deployed]
    #[arg(short, long)]
    keytype: String,

    /// Algorithm [RSA, ED25519]
    #[arg(short, long, default_value_t = String::from("RSA"))]
    algorithm: String,

    /// Copy to systems using config.toml Default is FALSE 
    #[arg(short, long, action=clap::ArgAction::SetTrue)]
    copy_key: bool, 
}
// Ask for the password twice and make sure it matches.
fn get_passwords() -> (String, String) {
    print!("Enter password: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();
    print!("Enter password second time: ");
    io::stdout().flush().unwrap();
    let password_second = read_password().unwrap();
    return (password, password_second);
}

// Print the fingerprint and add ":" as a delimiter
fn print_fingerprint<P: Display + AsRef<Path>>(path: P) -> OsshResult<()> {
    match fs::read_to_string(path) {
        Ok(s) => {
            let pubkey = PublicKey::from_keystr(&s)?;
            let hs = hex::encode_upper(pubkey.fingerprint(FingerprintHash::SHA256)?);
            let mut result = String::new();
            for (i, c) in hs.chars().enumerate() {
                result.push(c);
                if (i + 1) % 2 == 0 && (i + 1) < hs.len() {
                    result.push_str(":");
                }
            }
            //Show the fingerprint in SHA256 hex
            println!(
                "SHA256 (HEX):{}",
                result
            );
            //Show the fingerprint in SHA256)
            let fp = sshkeys::Fingerprint::compute(sshkeys::FingerprintKind::Sha256, &s);
            println!(
                "SHA256 fingerprint: {}",
                fp.hash
            );
        }
        Err(e) => {
            println!("{}", e);
        }
    }
    Ok(())
}
//Print the ASCII art for fingerprint
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

fn copy_key(public_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Debug, Deserialize)]
    struct Config {
        user: String,    
        servers: Vec<Server>,  
    }

    #[derive(Debug, Deserialize)]
    struct Server {
        name: String,
        ip: String,
        port: u32,
    }


    let config_content = fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&config_content)?;

    print!("Enter password for systems: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();

    for server in config.servers {
        let result = TcpStream::connect(format!("{}:{}", server.ip, server.port));
        let tcp = match result {
            Ok(result) => result, 
            Err(e) => {
                eprintln!("{}: {}", server.name, e);
                continue;
            }
        };
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;


        sess.userauth_password(&config.user, &password)?;
        if !sess.authenticated() {
            return Err("Authentication failed".into());
        }

        let mut channel = sess.channel_session()?;
        
        let cmd = format!(
            "mkdir -p ~/.ssh && \
            chmod 700 ~/.ssh && \
            sed -i '/ssh-rust-{}/d' ~/.ssh/authorized_keys && \
            echo '{} ssh-rust-{}' >> ~/.ssh/authorized_keys && \
            chmod 600 ~/.ssh/authorized_keys",
            gethostname().to_string_lossy(), public_key, gethostname().to_string_lossy() 
        );

        channel.exec(&cmd)?;
        
        let mut output = String::new();
        channel.read_to_string(&mut output)?;
        channel.wait_close()?;

        println!("Public key successfully appended to remote host: {}.", server.name);
    }
    Ok(())
}

fn main() -> OsshResult<()> {

    // Parse args from command line
    let args = Args::parse();
    // Get today's date
    let now_local = Local::now();
    let today_naive_date: NaiveDate = now_local.date_naive();

    let mut password;
    let mut p_second;
    loop {
        (password, p_second) = get_passwords();
        if password != p_second {
            println!("Passwords do not match. Try again")
        } else {
            break;
        }
    }
    let filename = &args.keytype;    
    let today = today_naive_date.to_string();
    let username = whoami::username();
    let merged = format!("{username}-{filename}-{today}");

    // Generate a keypair
    let keypair;
    if args.algorithm.to_lowercase() == "rsa" {
        keypair = KeyPair::generate(KeyType::RSA, 2048)?;
    } else if args.algorithm.to_lowercase() == "ed25519" {
        keypair = KeyPair::generate(KeyType::ED25519, 256)?;
    } else {
        panic!("Invalid algorithm!")
    }
    // Create the file with permission 0600
    let directory = format!("~/.ssh/{}", filename);
    let expanded_path = shellexpand::tilde(&directory);
    let path_buf: PathBuf = expanded_path.into_owned().into();
    let path = format!("{}/{}", &path_buf.display(), merged);
    println!("{}: {}", print_emojis(":locked_with_key:"), path);
    let _createdir = fs::create_dir(path_buf);
    let mut fop = fs::OpenOptions::new();
    fop.write(true).create(true).truncate(true);
    cfg_if! {
        if #[cfg(unix)] {
            fop.mode(0o600);
        }
    }

    let mut f = fop.open(&path)?;
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
    let f = format!("{}.pub", path);


    // Create public key file
    let mut pubf = fs::OpenOptions::new();
    pubf.write(true).create(true).truncate(true);
    cfg_if! {
        if #[cfg(unix)] {
            pubf.mode(0o600);
        }
    }

    let mut pub_file = pubf.open(Path::new(&path).with_extension("pub"))?;
    // Write the public key
    writeln!(pub_file, "{}", &pubkey)?;
    pub_file.sync_all()?;

    // Display fingerprint, art, and pubkey
    let _ = print_fingerprint(&f)?;
    let _ = print_fingerprint_art(&f)?;
    println!("{} Public key:", print_emojis(":locked_with_pen:"));
    println!("{}", &pubkey);
    if args.copy_key {
        println!("Copying key to host...");
        let _  = copy_key(&pubkey);
    }
    //println!("{:?}", result);
    Ok(())
}
