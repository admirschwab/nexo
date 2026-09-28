use crate::models::encrypted_identity::{EncryptedIdentity, IdentityFormat};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

// Schreibt die Identität in eine neue Datei (immer Format 2). Eine vorhandene
// Datei wird nie überschrieben, damit kein Schlüssel versehentlich verloren geht.
pub fn save_identity(
    path: &Path,
    identity: &EncryptedIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(identity.format, IdentityFormat::V2) {
        return Err("Only the current identity file format can be saved".into());
    }

    let data = [
        EncryptedIdentity::header_v2(&identity.kdf, &identity.salt, &identity.nonce),
        identity.ciphertext.clone(),
    ]
        .concat();

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
