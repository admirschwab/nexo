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

const APP_DIR: &str = "nexo";

pub const IDENTITY_FILE: &str = "identity.nexo";
// Zwischendatei während der Registrierung
pub const PENDING_IDENTITY_FILE: &str = "identity.nexo.pending";
// Zwischendatei beim Umwandeln einer alten Identitätsdatei
pub const UPGRADE_IDENTITY_FILE: &str = "identity.nexo.upgrade";
pub const CONFIG_FILE: &str = "config.toml";

// Von früheren Versionen: gemerkte Schlüssel der Gesprächspartner.
// Wird nicht mehr verwendet und gelöscht, wo sie noch liegt.
const OLD_KNOWN_PEERS_FILE: &str = "known_peers.nexo";

pub struct Paths {
    pub dir: PathBuf,
    pub identity: PathBuf,
    pub pending_identity: PathBuf,
    pub upgrade_identity: PathBuf,
    pub config: PathBuf,
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
            upgrade_identity: dir.join(UPGRADE_IDENTITY_FILE),
            config: dir.join(CONFIG_FILE),
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

        // Die Konfiguration enthält nichts Geheimes und wird nur kopiert
        let old_config = current.join(CONFIG_FILE);

        if !self.config.exists()
            && old_config.is_file()
            && fs::metadata(&old_config)?.len() > 0
        {
            fs::copy(&old_config, &self.config)?;
            println!("Copied config.toml to {}", self.config.display());
        }

        // Gemerkte Schlüssel werden nicht mehr gespeichert: alte Dateien löschen
        for old_known_peers in [current.join(OLD_KNOWN_PEERS_FILE), self.dir.join(OLD_KNOWN_PEERS_FILE)] {
            if old_known_peers.is_file() {
                fs::remove_file(&old_known_peers)?;
                println!("Deleted {} (no longer used)", old_known_peers.display());
            }
        }

        Ok(())
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
