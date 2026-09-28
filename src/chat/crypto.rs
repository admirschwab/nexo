use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

// Kontexte, damit Signaturen und Schlüssel nie für etwas anderes verwendet werden können
const HANDSHAKE_INIT_CONTEXT: &[u8] = b"nexo-handshake-init-v1";
const HANDSHAKE_REPLY_CONTEXT: &[u8] = b"nexo-handshake-reply-v2";
const CHAT_KEY_INFO: &[u8] = b"nexo-chat-key-v2";
const SAFETY_NUMBER_CONTEXT: &[u8] = b"nexo-safety-number-v1";

pub fn generate_ephemeral_secret() -> Result<StaticSecret, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;

    Ok(StaticSecret::from(bytes))
}

// Ob ein Handshake eine neue Sitzung beginnt oder auf einen Beginn antwortet
#[derive(Clone, Copy)]
pub enum HandshakeRole {
    Init,
    Reply,
}

// Signiert wird: Kontext (je nach Rolle) + eigener X25519-Key + Absender + Empfänger.
// So kann ein Handshake nicht an einen anderen Empfänger umgeleitet
// und eine Antwort nicht als Beginn ausgegeben werden (oder umgekehrt).
// Eine Antwort signiert zusätzlich den X25519-Key des Handshakes, auf den sie
// antwortet. Eine veraltete Antwort (auf einen früheren Versuch) passt dann
// nicht mehr und kann keine Sitzung mit falschem Schlüssel erzeugen.
fn handshake_transcript(
    role: HandshakeRole,
    ephemeral_key: &[u8; 32],
    from: &VerifyingKey,
    to: &VerifyingKey,
    in_reply_to: Option<&[u8; 32]>,
) -> Vec<u8> {
    let context = match role {
        HandshakeRole::Init => HANDSHAKE_INIT_CONTEXT,
        HandshakeRole::Reply => HANDSHAKE_REPLY_CONTEXT,
    };

    [
        context,
        ephemeral_key.as_slice(),
        from.as_bytes().as_slice(),
        to.as_bytes().as_slice(),
        in_reply_to.map_or(&[][..], |key| key.as_slice()),
    ]
        .concat()
}

pub fn sign_handshake(
    role: HandshakeRole,
    signing_key: &SigningKey,
    ephemeral_key: &PublicKey,
    to: &VerifyingKey,
    in_reply_to: Option<&[u8; 32]>,
) -> Signature {
    signing_key.sign(&handshake_transcript(
        role,
        ephemeral_key.as_bytes(),
        &signing_key.verifying_key(),
        to,
        in_reply_to,
    ))
}

pub fn verify_handshake(
    role: HandshakeRole,
    from: &VerifyingKey,
    to: &VerifyingKey,
    ephemeral_key: &[u8; 32],
    signature: &Signature,
    in_reply_to: Option<&[u8; 32]>,
) -> bool {
    from.verify(
        &handshake_transcript(role, ephemeral_key, from, to, in_reply_to),
        signature,
    )
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

// Nachrichten werden vor dem Verschlüsseln auf eine dieser Größen aufgefüllt.
// Sonst verrät die Länge des Ciphertexts, wie lang der Text ist.
// Größere Nachrichten werden auf ein Vielfaches der letzten Stufe aufgefüllt.
const PADDING_BUCKETS: [usize; 3] = [256, 1024, 4096];

// Text + 0x80 + Nullen bis zur nächsten Stufe (ISO/IEC 7816-4).
// Das 0x80 markiert, wo der Text endet.
fn pad(text: &[u8]) -> Zeroizing<Vec<u8>> {
    let needed = text.len() + 1;
    let largest = PADDING_BUCKETS[PADDING_BUCKETS.len() - 1];

    let padded_length = PADDING_BUCKETS
        .iter()
        .copied()
        .find(|&bucket| bucket >= needed)
        .unwrap_or_else(|| needed.div_ceil(largest) * largest);

    let mut padded = Zeroizing::new(Vec::with_capacity(padded_length));
    padded.extend_from_slice(text);
    padded.push(0x80);
    padded.resize(padded_length, 0);

    padded
}

// Entfernt Nullen und das 0x80 am Ende
fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let end = padded.iter().rposition(|&byte| byte != 0)?;

    (padded[end] == 0x80).then(|| &padded[..end])
}

// Verschlüsselt wird: Nachrichtennummer (8 Bytes) + Text, aufgefüllt.
// Die Nummer steht im verschlüsselten Teil, der Server sieht sie nicht.
// Die Nonce bleibt trotzdem zufällig: Beide Richtungen verwenden denselben
// Schlüssel, eine Nonce aus dem Zähler käme also in beiden Richtungen doppelt vor.
pub fn encrypt_text(
    key: &[u8; 32],
    from: &VerifyingKey,
    to: &VerifyingKey,
    counter: u64,
    text: &str,
) -> Result<([u8; 24], Vec<u8>), Box<dyn std::error::Error>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())?;

    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce)?;

    let plaintext = Zeroizing::new([counter.to_le_bytes().as_slice(), text.as_bytes()].concat());
    let padded = pad(&plaintext);

    let ciphertext = cipher.encrypt(
        &XNonce::try_from(nonce.as_slice())?,
        Payload {
            msg: &padded,
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
) -> Option<(u64, String)> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).ok()?;

    let padded = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::try_from(nonce.as_slice()).ok()?,
                Payload {
                    msg: ciphertext,
                    aad: &associated_data(from, to),
                },
            )
            .ok()?,
    );

    let plaintext = unpad(&padded)?;

    if plaintext.len() < 8 {
        return None;
    }

    let (counter, text) = plaintext.split_at(8);
    let counter = u64::from_le_bytes(counter.try_into().ok()?);

    Some((counter, String::from_utf8(text.to_vec()).ok()?))
}

// Sicherheitsnummer: 60 Ziffern, berechnet aus beiden Public Keys.
// Die Schlüssel werden sortiert, damit beide Seiten dieselbe Zahl sehen.
// Stimmt sie bei beiden überein (verglichen z. B. am Telefon), hat niemand,
// auch nicht der Server, einen Schlüssel ausgetauscht.
// Es wird nichts gespeichert, die Zahl wird jedes Mal neu berechnet.
pub fn safety_number(a: &VerifyingKey, b: &VerifyingKey) -> String {
    let (first, second) = if a.as_bytes() < b.as_bytes() { (a, b) } else { (b, a) };

    let hash = Sha512::new()
        .chain_update(SAFETY_NUMBER_CONTEXT)
        .chain_update(first.as_bytes())
        .chain_update(second.as_bytes())
        .finalize();

    // 12 Blöcke aus je 5 Bytes, jeweils als fünfstellige Zahl
    hash.chunks_exact(5)
        .take(12)
        .map(|chunk| {
            let mut bytes = [0u8; 8];
            bytes[..5].copy_from_slice(chunk);

            format!("{:05}", u64::from_le_bytes(bytes) % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}
