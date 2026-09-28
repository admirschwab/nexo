// Die Server-Adresse steht verschlüsselt in identity.nexo (siehe paths.rs).
// Ohne Passwort verrät der Rechner also nicht, welchen Nexo-Server man nutzt.

pub const DEFAULT_SERVER: &str = "http://127.0.0.1:3000";

pub struct Config {
    pub server: String,
}

// Die Adresse muss mit http:// oder https:// beginnen
pub fn validate_server(server: &str) -> Result<(), &'static str> {
    let rest = server
        .strip_prefix("https://")
        .or_else(|| server.strip_prefix("http://"))
        .ok_or("The server address must start with http:// or https://")?;

    if rest.trim_end_matches('/').is_empty() {
        return Err("The server address is missing a host name");
    }

    Ok(())
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

    eprintln!("Warning: the connection to the server is not encrypted (http instead of https).");
    eprintln!("         Your messages stay end-to-end encrypted, but anyone on the network");
    eprintln!("         can see who you are talking to, when, and who is online.");
    eprintln!();
}
