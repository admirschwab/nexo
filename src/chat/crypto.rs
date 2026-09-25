use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

// Kontexte, damit Signaturen und Schlüssel nie für etwas anderes verwendet werden können
const HANDSHAKE_CONTEXT: &[u8] = b"nexo-handshake-v1";
const CHAT_KEY_INFO: &[u8] = b"nexo-chat-key-v1";

pub fn generate_ephemeral_secret() -> Result<StaticSecret, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;

    Ok(StaticSecret::from(bytes))
}

// Signiert wird: Kontext + eigener X25519-Key + Absender + Empfänger.
// So kann ein Handshake nicht an einen anderen Empfänger umgeleitet werden.
fn handshake_transcript(
    ephemeral_key: &[u8; 32],
    from: &VerifyingKey,
    to: &VerifyingKey,
) -> Vec<u8> {
    [
        HANDSHAKE_CONTEXT,
        ephemeral_key.as_slice(),
        from.as_bytes().as_slice(),
        to.as_bytes().as_slice(),
    ]
        .concat()
}

pub fn sign_handshake(
    signing_key: &SigningKey,
    ephemeral_key: &PublicKey,
    to: &VerifyingKey,
) -> Signature {
    signing_key.sign(&handshake_transcript(
        ephemeral_key.as_bytes(),
        &signing_key.verifying_key(),
        to,
    ))
}

pub fn verify_handshake(
    from: &VerifyingKey,
    to: &VerifyingKey,
    ephemeral_key: &[u8; 32],
    signature: &Signature,
) -> bool {
    from.verify(&handshake_transcript(ephemeral_key, from, to), signature)
        .is_ok()
}

// Diffie-Hellman + HKDF. Beide Seiten erhalten denselben Schlüssel.
// Er wird beim Freigeben mit Nullen überschrieben.
pub fn derive_chat_key(
    own_secret: &StaticSecret,
    their_ephemeral_key: &PublicKey,
) -> Option<Zeroizing<[u8; 32]>> {
    let shared = own_secret.diffie_hellman(their_ephemeral_key);

    // Schutz gegen manipulierte Schlüssel, die ein bekanntes Ergebnis erzwingen
    if !shared.was_contributory() {
        return None;
    }

    // Beide öffentlichen Schlüssel sortiert einbeziehen, damit beide Seiten
    // unabhängig von der Rolle dieselbe Eingabe haben
    let own_public = PublicKey::from(own_secret);
    let (first, second) = if own_public.as_bytes() < their_ephemeral_key.as_bytes() {
        (own_public.as_bytes(), their_ephemeral_key.as_bytes())
    } else {
        (their_ephemeral_key.as_bytes(), own_public.as_bytes())
    };

    let info = [CHAT_KEY_INFO, first.as_slice(), second.as_slice()].concat();

    let mut key = Zeroizing::new([0u8; 32]);

    Hkdf::<Sha256>::new(None, shared.as_bytes())
        .expand(&info, key.as_mut_slice())
        .ok()?;

    Some(key)
}

// Absender und Empfänger werden als "associated data" mitgeprüft.
// Eine Nachricht kann so nicht als Nachricht in die andere Richtung ausgegeben werden.
fn associated_data(from: &VerifyingKey, to: &VerifyingKey) -> Vec<u8> {
    [from.as_bytes().as_slice(), to.as_bytes().as_slice()].concat()
}

pub fn encrypt_text(
    key: &[u8; 32],
    from: &VerifyingKey,
    to: &VerifyingKey,
    text: &str,
) -> Result<([u8; 24], Vec<u8>), Box<dyn std::error::Error>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())?;

    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce)?;

    let ciphertext = cipher.encrypt(
        &XNonce::try_from(nonce.as_slice())?,
        Payload {
            msg: text.as_bytes(),
            aad: &associated_data(from, to),
        },
    )?;

    Ok((nonce, ciphertext))
}

pub fn decrypt_text(
    key: &[u8; 32],
    from: &VerifyingKey,
    to: &VerifyingKey,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Option<String> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).ok()?;

    let plaintext = cipher
        .decrypt(
            &XNonce::try_from(nonce.as_slice()).ok()?,
            Payload {
                msg: ciphertext,
                aad: &associated_data(from, to),
            },
        )
        .ok()?;

    String::from_utf8(plaintext).ok()
}
