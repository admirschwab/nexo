use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

// Alle Dateien von Nexo liegen in einem festen Ordner, damit `nexo` aus jedem
// Verzeichnis heraus funktioniert:
//   Windows: %LOCALAPPDATA%\nexo
//   Linux:   ~/.local/share/nexo
//   macOS:   ~/Library/Application Support/nexo
//
// Bewusst der lokale und nicht der Roaming-Ordner (%APPDATA%): Roaming-Profile
// werden in Firmennetzen auf einen Server synchronisiert. Die Identität soll
// diesen Rechner nie verlassen.
//
// Nexo speichert nur eine einzige Datei: identity.nexo. Sie enthält privaten
// Schlüssel, Nickname und Server-Adresse, alles mit dem Passwort verschlüsselt.

const APP_DIR: &str = "nexo";

pub const IDENTITY_FILE: &str = "identity.nexo";
// Zwischendatei während der Registrierung
const PENDING_IDENTITY_FILE: &str = "identity.nexo.pending";
// Zwischendatei beim Neuschreiben der Identitätsdatei
const REWRITE_IDENTITY_FILE: &str = "identity.nexo.upgrade";

// Von früheren Versionen: Server-Adresse im Klartext. Wird beim nächsten Login
// in identity.nexo übernommen und dann gelöscht.
const OLD_CONFIG_FILE: &str = "config.toml";

// Von früheren Versionen: gemerkte Schlüssel der Gesprächspartner.
// Wird nicht mehr verwendet und gelöscht, wo sie noch liegt.
const OLD_KNOWN_PEERS_FILE: &str = "known_peers.nexo";

pub struct Paths {
    pub dir: PathBuf,
    pub identity: PathBuf,
    pub pending_identity: PathBuf,
    pub rewrite_identity: PathBuf,
    pub old_config: PathBuf,
}

impl Paths {
    // Ermittelt den Ordner und legt ihn an, falls es ihn noch nicht gibt
    pub fn init() -> Result<Self, Box<dyn Error>> {
        let dir = dirs::data_local_dir()
            .ok_or("Could not find the folder for application data")?
            .join(APP_DIR);

        create_private_dir(&dir)
            .map_err(|error| format!("Could not create {}: {error}", dir.display()))?;

        Ok(Self {
            identity: dir.join(IDENTITY_FILE),
            pending_identity: dir.join(PENDING_IDENTITY_FILE),
            rewrite_identity: dir.join(REWRITE_IDENTITY_FILE),
            old_config: dir.join(OLD_CONFIG_FILE),
            dir,
        })
    }

    // Übernimmt Dateien, die frühere Versionen im aktuellen Verzeichnis abgelegt haben
    pub fn migrate_from_current_dir(&self) -> Result<(), Box<dyn Error>> {
        let current = Path::new(".");

        // Die Identität wird verschoben, damit keine Kopie des Schlüssels zurückbleibt
        let old_identity = current.join(IDENTITY_FILE);

        if old_identity.is_file() && !self.identity.exists() {
            move_file(&old_identity, &self.identity)?;
            println!("Moved your identity to {}", self.identity.display());
        }

        // Eine alte config.toml im aktuellen Ordner wird nur gelesen (siehe
        // old_server_address), nie gelöscht: Sie kann zu einem Git-Repository gehören.

        // Gemerkte Schlüssel werden nicht mehr gespeichert: alte Dateien löschen
        for old_known_peers in [current.join(OLD_KNOWN_PEERS_FILE), self.dir.join(OLD_KNOWN_PEERS_FILE)] {
            if old_known_peers.is_file() {
                fs::remove_file(&old_known_peers)?;
                println!("Deleted {} (no longer used)", old_known_peers.display());
            }
        }

        Ok(())
    }

    // Server-Adresse aus einer config.toml früherer Versionen, falls vorhanden
    pub fn old_server_address(&self) -> Option<String> {
        [self.old_config.clone(), Path::new(".").join(OLD_CONFIG_FILE)]
            .iter()
            .filter_map(|path| fs::read_to_string(path).ok())
            .find_map(|data| {
                toml::from_str::<toml::Table>(&data)
                    .ok()?
                    .get("server")?
                    .as_str()
                    .map(str::to_string)
            })
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;

    // Unter Linux/macOS darf nur der Besitzer in den Ordner schauen
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

// Verschieben, notfalls über Laufwerksgrenzen hinweg (kopieren, dann löschen)
fn move_file(from: &Path, to: &Path) -> Result<(), Box<dyn Error>> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }

    fs::copy(from, to)?;
    fs::remove_file(from)?;

    Ok(())
}
