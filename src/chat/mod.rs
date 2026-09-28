// Ende-zu-Ende-Verschlüsselung der Chats
//
// Ablauf pro Gesprächspartner und Sitzung:
// 1. Beide erzeugen einen frischen X25519-Schlüssel (nur im Arbeitsspeicher)
//    und schicken den öffentlichen Teil, signiert mit ihrem Ed25519-Identitätsschlüssel.
// 2. Aus beiden Schlüsseln berechnen beide per Diffie-Hellman + HKDF denselben Chat-Schlüssel.
// 3. Jede Nachricht wird damit per XChaCha20-Poly1305 verschlüsselt.
//
// Der Server sieht nur verschlüsselte Daten. Weil die X25519-Schlüssel beim Beenden
// verloren gehen, bleiben alte Nachrichten auch mit identity.nexo + Passwort unlesbar.

pub mod crypto;
pub mod session;
