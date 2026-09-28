use ed25519_dalek::SigningKey;

// Entschlüsselte Identität, nur im Arbeitsspeicher.
// SigningKey überschreibt sich beim Freigeben selbst mit Nullen.
pub struct Identity {
    pub nickname: String,
    pub signing_key: SigningKey,
    // Adresse des Servers, bei dem die Identität registriert ist.
    // Leer bei Dateien aus früheren Versionen (die Adresse stand dort in config.toml).
    pub server: String,
}
