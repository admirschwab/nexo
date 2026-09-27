use crate::models::identity::Identity;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

// Schreibt die Identität in eine neue Datei. Eine vorhandene Datei wird nie
// überschrieben, damit kein Schlüssel versehentlich verloren geht.
pub fn save_identity(
    path: &Path,
    identity: &Identity,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = Vec::new();

    data.extend_from_slice(b"NEXO1");

    // Nickname
    let nickname_bytes = identity.nickname.as_bytes();
    let nickname_length = nickname_bytes.len() as u16;

    data.extend_from_slice(&nickname_length.to_le_bytes());
    data.extend_from_slice(nickname_bytes);

    // Encrypted private key
    data.extend_from_slice(&identity.encrypted_private_key.salt);
    data.extend_from_slice(&identity.encrypted_private_key.nonce);
    data.extend_from_slice(&identity.encrypted_private_key.ciphertext);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    // Unter Linux/macOS darf nur der Besitzer die Datei lesen
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;

    file.write_all(&data)?;

    // Sicherstellen, dass die Daten wirklich auf der Platte liegen
    file.sync_all()?;

    Ok(())
}
