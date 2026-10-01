use elementsplus_preconf::elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};
use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args_os()
        .nth(1)
        .ok_or("usage: preconf-key SECRET_FILE")?;
    let secret_hex = fs::read_to_string(Path::new(&path))?;
    let secret = SecretKey::from_slice(&hex::decode(secret_hex.trim())?)?;
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    println!("{}", keypair.x_only_public_key().0);
    Ok(())
}
