use serde::Deserialize;
use std::{fs, path::Path};

// Wird beim ersten Start angelegt, wenn es noch keine config.toml gibt
const DEFAULT_CONFIG: &str = "# Address of the Nexo server (http:// or https://)
server = \"http://127.0.0.1:3000\"
";

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: String,
}

pub fn load_config(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    if !path.exists() {
        fs::write(path, DEFAULT_CONFIG)?;

        println!("Created {} (server: http://127.0.0.1:3000).", path.display());
        println!("Edit this file to use another server.");
        println!();
    }

    let data = fs::read_to_string(path)?;
    let config = toml::from_str(&data)?;

    Ok(config)
}

// Ohne https ist die Verbindung zum Server unverschlüsselt. Die Nachrichten
// bleiben Ende-zu-Ende verschlüsselt, aber jeder im Netzwerk sieht, wer mit wem
// wann schreibt und wer online ist. Auf dem eigenen Rechner ist das egal.
pub fn warn_if_insecure(config: &Config) {
    let Some(rest) = config.server.strip_prefix("http://") else {
        return;
    };

    let authority = rest.split('/').next().unwrap_or_default();

    // Port abschneiden, IPv6 steht in eckigen Klammern: [::1]:3000
    let host = if let Some(ipv6) = authority.strip_prefix('[') {
        ipv6.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };

    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return;
    }

    eprintln!("Warning: the connection to {} is not encrypted (http instead of https).", config.server);
    eprintln!("         Your messages stay end-to-end encrypted, but anyone on the network");
    eprintln!("         can see who you are talking to, when, and who is online.");
    eprintln!();
}
