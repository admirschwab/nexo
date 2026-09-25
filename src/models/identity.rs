use super::encrypted_private_key::EncryptedPrivateKey;

pub struct Identity {
    pub nickname: String,
    pub encrypted_private_key: EncryptedPrivateKey,
}