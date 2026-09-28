use ed25519_dalek::SigningKey;

// Entschlüsselte Identität, nur im Arbeitsspeicher.
// SigningKey überschreibt sich beim Freigeben selbst mit Nullen.
pub struct Identity {
    pub nickname: String,
    pub signing_key: SigningKey,
}
