//! Encrypted mnemonic keystore (spec §6.2).
//!
//! `keystore.json` holds the BIP39 mnemonic encrypted with
//! XChaCha20-Poly1305 under a key derived from the password by Argon2id.
//! The KDF parameters, salt and nonce are stored alongside; the serialized
//! header is bound to the ciphertext as associated data so parameters cannot
//! be downgraded without failing authentication. Secrets live in
//! `Zeroizing` buffers and are wiped on drop.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use elementsplus_wallet_core::WalletCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const KEYSTORE_VERSION: u32 = 1;
const KDF_NAME: &str = "argon2id";
const CIPHER_NAME: &str = "xchacha20poly1305";

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Production default: 64 MiB, 3 passes, 1 lane (OWASP-ish baseline).
    pub const DEFAULT: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    fn validate(&self) -> Result<()> {
        // Refuse files that would make unlocking trivially cheap or absurdly
        // expensive (a tampered file must not become a DoS or a downgrade).
        if !(8 * 1024..=4 * 1024 * 1024).contains(&self.m_cost_kib)
            || !(1..=64).contains(&self.t_cost)
            || !(1..=16).contains(&self.p_cost)
        {
            bail!("keystore KDF parameters are outside the accepted range");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct KdfSection {
    name: String,
    params: KdfParams,
    salt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CipherSection {
    name: String,
    nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeystoreFile {
    version: u32,
    kdf: KdfSection,
    cipher: CipherSection,
    ciphertext: String,
}

impl KeystoreFile {
    /// Associated data: everything except the ciphertext, canonically encoded.
    fn aad(&self) -> Vec<u8> {
        serde_json::to_vec(&(self.version, &self.kdf, &self.cipher)).expect("header serializes")
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| anyhow!("OS random number generator failed: {e}"))?;
    Ok(bytes)
}

fn derive_key(password: &str, salt: &[u8], params: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| anyhow!("invalid Argon2 parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypt a (validated) mnemonic.
pub fn encrypt(mnemonic: &str, password: &str, params: KdfParams) -> Result<KeystoreFile> {
    WalletCore::validate_mnemonic(mnemonic).map_err(|_| anyhow!("invalid BIP39 mnemonic"))?;
    if password.is_empty() {
        bail!("password must not be empty");
    }
    params.validate()?;
    let salt = random_bytes::<16>()?;
    let nonce = random_bytes::<24>()?;
    let mut file = KeystoreFile {
        version: KEYSTORE_VERSION,
        kdf: KdfSection {
            name: KDF_NAME.into(),
            params,
            salt: hex::encode(salt),
        },
        cipher: CipherSection {
            name: CIPHER_NAME.into(),
            nonce: hex::encode(nonce),
        },
        ciphertext: String::new(),
    };
    let key = derive_key(password, &salt, params)?;
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key[..]));
    let aad = file.aad();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: mnemonic.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    file.ciphertext = hex::encode(ciphertext);
    Ok(file)
}

/// Decrypt the mnemonic. A wrong password and a tampered file are
/// indistinguishable by design.
pub fn decrypt(file: &KeystoreFile, password: &str) -> Result<Zeroizing<String>> {
    if file.version != KEYSTORE_VERSION
        || file.kdf.name != KDF_NAME
        || file.cipher.name != CIPHER_NAME
    {
        bail!("unsupported keystore format");
    }
    file.kdf.params.validate()?;
    let salt = hex::decode(&file.kdf.salt).context("keystore salt is not hex")?;
    let nonce = hex::decode(&file.cipher.nonce).context("keystore nonce is not hex")?;
    if salt.len() < 16 || nonce.len() != 24 {
        bail!("keystore salt or nonce has the wrong length");
    }
    let ciphertext = hex::decode(&file.ciphertext).context("keystore ciphertext is not hex")?;
    let key = derive_key(password, &salt, file.kdf.params)?;
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key[..]));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &file.aad(),
                },
            )
            .map_err(|_| anyhow!("wrong password or corrupted keystore"))?,
    );
    let mnemonic = Zeroizing::new(
        std::str::from_utf8(&plaintext)
            .map_err(|_| anyhow!("keystore plaintext is not UTF-8"))?
            .to_owned(),
    );
    WalletCore::validate_mnemonic(&mnemonic)
        .map_err(|_| anyhow!("keystore holds an invalid mnemonic"))?;
    Ok(mnemonic)
}

pub fn exists(path: &Path) -> bool {
    path.exists()
}

/// Write a new keystore; never overwrites an existing one.
pub fn write_new(path: &Path, file: &KeystoreFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        crate::config::create_private_dir(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut handle = options
        .open(path)
        .with_context(|| format!("refusing to overwrite existing keystore {}", path.display()))?;
    handle.write_all(serde_json::to_string_pretty(file)?.as_bytes())?;
    handle.write_all(b"\n")?;
    handle.sync_all()?;
    Ok(())
}

pub fn read(path: &Path) -> Result<KeystoreFile> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "no keystore at {} (run `epw init` or `epw import`)",
            path.display()
        )
    })?;
    serde_json::from_str(&text).context("keystore file is malformed")
}

/// Obtain the password from `EPW_PASSWORD` or an interactive prompt.
pub fn password(confirm: bool) -> Result<Zeroizing<String>> {
    if let Ok(password) = std::env::var("EPW_PASSWORD") {
        if password.is_empty() {
            bail!("EPW_PASSWORD is set but empty");
        }
        return Ok(Zeroizing::new(password));
    }
    let first = Zeroizing::new(
        rpassword::prompt_password("epw password: ")
            .context("no EPW_PASSWORD set and no terminal to prompt on")?,
    );
    if first.is_empty() {
        bail!("password must not be empty");
    }
    if confirm {
        let second = Zeroizing::new(rpassword::prompt_password("repeat password: ")?);
        if *first != *second {
            bail!("passwords do not match");
        }
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const CHEAP: KdfParams = KdfParams {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn round_trip_and_wrong_password() {
        let file = encrypt(MNEMONIC, "correct horse", CHEAP).unwrap();
        assert!(!file.ciphertext.contains("abandon"));
        assert_eq!(&*decrypt(&file, "correct horse").unwrap(), MNEMONIC);
        let err = decrypt(&file, "wrong horse").unwrap_err().to_string();
        assert!(err.contains("wrong password"), "{err}");
    }

    #[test]
    fn fresh_salt_and_nonce_each_time() {
        let a = encrypt(MNEMONIC, "pw", CHEAP).unwrap();
        let b = encrypt(MNEMONIC, "pw", CHEAP).unwrap();
        assert_ne!(a.kdf.salt, b.kdf.salt);
        assert_ne!(a.cipher.nonce, b.cipher.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn tampering_is_detected() {
        let file = encrypt(MNEMONIC, "pw", CHEAP).unwrap();
        // Downgrading the KDF parameters breaks the AAD binding.
        let mut downgraded = file.clone();
        downgraded.kdf.params.t_cost = 2;
        assert!(decrypt(&downgraded, "pw").is_err());
        // Out-of-range parameters are rejected before any work.
        let mut weak = file.clone();
        weak.kdf.params.m_cost_kib = 1;
        assert!(decrypt(&weak, "pw").is_err());
        // Flipping a ciphertext bit fails authentication.
        let mut flipped = file.clone();
        let mut bytes = hex::decode(&flipped.ciphertext).unwrap();
        bytes[0] ^= 1;
        flipped.ciphertext = hex::encode(bytes);
        assert!(decrypt(&flipped, "pw").is_err());
    }

    #[test]
    fn rejects_invalid_mnemonic_and_empty_password() {
        assert!(encrypt("not a mnemonic", "pw", CHEAP).is_err());
        assert!(encrypt(MNEMONIC, "", CHEAP).is_err());
    }

    #[test]
    fn file_write_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.json");
        let file = encrypt(MNEMONIC, "pw", CHEAP).unwrap();
        write_new(&path, &file).unwrap();
        assert!(write_new(&path, &file).is_err());
        let loaded = read(&path).unwrap();
        assert_eq!(loaded, file);
        assert_eq!(&*decrypt(&loaded, "pw").unwrap(), MNEMONIC);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
