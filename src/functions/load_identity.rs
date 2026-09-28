use crate::models::encrypted_identity::{
    EncryptedIdentity, IdentityFormat, KdfParams, MAGIC_V1, MAGIC_V2,
};
use std::fs;
use std::path::Path;

// Obergrenzen für die Argon2-Parameter aus der Datei. Eine manipulierte Datei
// soll den Rechner nicht mit riesigen Werten lahmlegen können.
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_ITERATIONS: u32 = 64;
const MAX_PARALLELISM: u32 = 16;

pub fn load_identity(
    path: &Path,
) -> Result<EncryptedIdentity, Box<dyn std::error::Error>> {
    let data = fs::read(path)?;

    if data.starts_with(MAGIC_V2) {
        parse_v2(&data[MAGIC_V2.len()..])
    } else if data.starts_with(MAGIC_V1) {
        parse_v1(&data[MAGIC_V1.len()..])
    } else {
        Err("Unknown identity file format".into())
    }
}

fn parse_v2(data: &[u8]) -> Result<EncryptedIdentity, Box<dyn std::error::Error>> {
    // 3 × u32 + Salt + Nonce
    if data.len() < 12 + 16 + 24 + 1 {
        return Err("Identity file is corrupted".into());
    }

    let read_u32 = |offset: usize| {
        u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
    };

    let kdf = KdfParams {
        memory_kib: read_u32(0),
        iterations: read_u32(4),
        parallelism: read_u32(8),
    };

    if kdf.memory_kib > MAX_MEMORY_KIB
        || kdf.iterations > MAX_ITERATIONS
        || kdf.parallelism > MAX_PARALLELISM
    {
        return Err("Identity file is corrupted".into());
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[12..28]);

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&data[28..52]);

    Ok(EncryptedIdentity {
        format: IdentityFormat::V2,
        kdf,
        salt,
        nonce,
        ciphertext: data[52..].to_vec(),
    })
}

fn parse_v1(data: &[u8]) -> Result<EncryptedIdentity, Box<dyn std::error::Error>> {
    if data.len() < 2 {
        return Err("Identity file is too short".into());
    }

    let nickname_length = u16::from_le_bytes([data[0], data[1]]) as usize;

    let nickname_end = 2 + nickname_length;
    let salt_end = nickname_end + 16;
    let nonce_end = salt_end + 24;

    if data.len() <= nonce_end {
        return Err("Identity file is corrupted".into());
    }

    let nickname = String::from_utf8(data[2..nickname_end].to_vec())?;

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[nickname_end..salt_end]);

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&data[salt_end..nonce_end]);

    Ok(EncryptedIdentity {
        format: IdentityFormat::V1 { nickname },
        kdf: KdfParams::V1,
        salt,
        nonce,
        ciphertext: data[nonce_end..].to_vec(),
    })
}
