// Inhalt von identity.nexo
//
// Format 3 (aktuell):
//   "NEXO3" | Argon2-Speicher in KiB (u32) | Durchläufe (u32) | Threads (u32)
//   | Salt (16 Bytes) | Nonce (24 Bytes) | Ciphertext
// Verschlüsselt sind: privater Schlüssel (32 Bytes) | Länge des Nicknames (u16)
//   | Nickname | Server-Adresse
// Ohne Passwort verrät die Datei also weder, wem sie gehört, noch welchen Server
// man nutzt. Der Kopf wird als "associated data" mitgeprüft und kann nicht
// unbemerkt verändert werden.
//
// Ältere Formate werden nur noch gelesen und beim Login in Format 3 umgewandelt:
// Format 2: wie Format 3, verschlüsselt sind nur privater Schlüssel + Nickname
//           (die Server-Adresse stand im Klartext in config.toml)
// Format 1: "NEXO1" | Länge des Nicknames (u16) | Nickname im Klartext
//           | Salt (16 Bytes) | Nonce (24 Bytes) | Ciphertext des privaten Schlüssels

pub const MAGIC_V1: &[u8] = b"NEXO1";
pub const MAGIC_V2: &[u8] = b"NEXO2";
pub const MAGIC_V3: &[u8] = b"NEXO3";

// Parameter, mit denen aus dem Passwort der Dateischlüssel abgeleitet wird (Argon2id).
// Sie stehen in der Datei, damit sie sich später ändern lassen, ohne alte Dateien
// unlesbar zu machen.
#[derive(Clone, Copy)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    // Für neue Dateien: 64 MiB Speicher, 3 Durchläufe
    pub const CURRENT: KdfParams = KdfParams {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    // Was Format 1 verwendet hat (die damaligen Standardwerte von argon2)
    pub const V1: KdfParams = KdfParams {
        memory_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    };
}

pub enum IdentityFormat {
    V1 { nickname: String },
    V2,
    V3,
}

impl IdentityFormat {
    pub fn is_current(&self) -> bool {
        matches!(self, IdentityFormat::V3)
    }
}

pub struct EncryptedIdentity {
    pub format: IdentityFormat,
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl EncryptedIdentity {
    // Dateikopf ab Format 2, zugleich die "associated data" der Verschlüsselung
    pub fn header(magic: &[u8], kdf: &KdfParams, salt: &[u8; 16], nonce: &[u8; 24]) -> Vec<u8> {
        [
            magic,
            &kdf.memory_kib.to_le_bytes(),
            &kdf.iterations.to_le_bytes(),
            &kdf.parallelism.to_le_bytes(),
            salt.as_slice(),
            nonce.as_slice(),
        ]
            .concat()
    }
}
