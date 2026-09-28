use crate::models::encrypted_identity::KdfParams;
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

// Leitet aus dem Passwort den Schlüssel für identity.nexo ab (Argon2id).
// Zeroizing überschreibt ihn beim Freigeben mit Nullen.
pub fn derive_file_key(
    password: &str,
    salt: &[u8; 16],
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, Box<dyn std::error::Error>> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| "Invalid key derivation parameters in identity file")?;

    let mut key = Zeroizing::new([0u8; 32]);

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(
        password.as_bytes(),
        salt,
        key.as_mut_slice(),
    )?;

    Ok(key)
}
