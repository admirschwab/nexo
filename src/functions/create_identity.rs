use crate::functions::encrypt_identity::encrypt_identity;
use crate::models::{encrypted_identity::EncryptedIdentity, identity::Identity};
use ed25519_dalek::SigningKey;
use getrandom::{rand_core::UnwrapErr, SysRng};

pub fn create_identity(
    nickname: String,
    password: &str,
) -> Result<(Identity, EncryptedIdentity), Box<dyn std::error::Error>> {
    let mut rng = UnwrapErr(SysRng);

    let identity = Identity {
        nickname,
        signing_key: SigningKey::generate(&mut rng),
    };

    let encrypted = encrypt_identity(&identity, password)?;

    Ok((identity, encrypted))
}
