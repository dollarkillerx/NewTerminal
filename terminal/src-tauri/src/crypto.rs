// Data-plane E2E: NaCl secretbox (XSalsa20-Poly1305), the one AEAD that's
// byte-compatible across Rust (dryoc), Go (x/crypto/nacl/secretbox) and Dart
// (sodium) — so every client encrypts/decrypts the same wire format. The relay
// only ever sees `nonce(24) || ciphertext`.
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine};
use dryoc::classic::crypto_secretbox::{
    crypto_secretbox_easy, crypto_secretbox_open_easy, Nonce,
};
use dryoc::constants::{CRYPTO_SECRETBOX_MACBYTES as MAC, CRYPTO_SECRETBOX_NONCEBYTES as NONCE};
use rand::Rng;

pub type AccountKey = [u8; 32];

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rng().fill_bytes(&mut b);
    b
}

/// Seal a plaintext frame: returns `nonce || mac || ciphertext`.
pub fn seal(key: &AccountKey, msg: &[u8]) -> Vec<u8> {
    let nonce: Nonce = random();
    let mut ct = vec![0u8; msg.len() + MAC];
    crypto_secretbox_easy(&mut ct, msg, &nonce, key).expect("secretbox encrypt");
    let mut out = Vec::with_capacity(NONCE + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Open a `nonce || mac || ciphertext` frame. Returns None on a short frame or a
/// failed MAC check — anything not produced by a holder of `key` is dropped.
pub fn open(key: &AccountKey, frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < NONCE + MAC {
        return None;
    }
    let (nonce, ct) = frame.split_at(NONCE);
    let nonce: Nonce = nonce.try_into().ok()?;
    let mut msg = vec![0u8; ct.len() - MAC];
    crypto_secretbox_open_easy(&mut msg, ct, &nonce, key).ok()?;
    Some(msg)
}

/// The pairing code is just the account key, base64'd, to be shown/scanned and
/// pasted on a second device. ponytail: manual key transfer over a trusted
/// out-of-band channel (screen→camera); swap to an X25519 handshake over the
/// relay when you want pairing without ever rendering the raw key.
pub fn pairing_code(key: &AccountKey) -> String {
    STANDARD.encode(key)
}

pub fn key_from_code(code: &str) -> Option<AccountKey> {
    STANDARD.decode(code.trim()).ok()?.try_into().ok()
}

/// Load the account key from disk, generating one on first run.
/// ponytail: 0600 file under the app config dir. The OS keychain is the right
/// home, but an *unsigned* dev binary triggers a keychain prompt on every run;
/// move to keyring once the app is code-signed.
pub fn load_or_create_key(dir: PathBuf) -> std::io::Result<AccountKey> {
    let path = dir.join("account.key");
    if let Ok(raw) = std::fs::read(&path) {
        if let Ok(k) = AccountKey::try_from(raw.as_slice()) {
            return Ok(k);
        }
    }
    std::fs::create_dir_all(&dir)?;
    let key: AccountKey = random();
    std::fs::write(&path, key)?;
    set_owner_only(&path);
    Ok(key)
}

#[cfg(unix)]
fn set_owner_only(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_owner_only(_path: &std::path::Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let k = random();
        let frame = seal(&k, b"echo REMOTE_OK\n");
        assert_ne!(&frame[24..], b"echo REMOTE_OK\n"); // wire is ciphertext, not plaintext
        assert_eq!(open(&k, &frame).unwrap(), b"echo REMOTE_OK\n");
    }

    #[test]
    fn tamper_and_wrong_key_rejected() {
        let k = random();
        let mut frame = seal(&k, b"secret");
        let last = frame.len() - 1;
        frame[last] ^= 0xff; // flip a ciphertext byte
        assert!(open(&k, &frame).is_none());
        assert!(open(&random(), &seal(&k, b"secret")).is_none()); // wrong key
        assert!(open(&k, &[0u8; 4]).is_none()); // too short
    }

    #[test]
    fn pairing_code_round_trip() {
        let k = random();
        assert_eq!(key_from_code(&pairing_code(&k)).unwrap(), k);
        assert!(key_from_code("not base64!!!").is_none());
    }
}
