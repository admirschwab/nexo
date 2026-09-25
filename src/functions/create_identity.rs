use crate::models::identity::Identity;
use crate::functions::encrypt_private_key::encrypt_private_key;
use ed25519_dalek::SigningKey;
use getrandom::{rand_core::UnwrapErr, SysRng};

pub fn create_identity(
    nickname: String,
    password: &str,
) -> Result<(Identity, SigningKey), Box<dyn std::error::Error>> {
    let mut rng = UnwrapErr(SysRng);

    let signing_key = SigningKey::generate(&mut rng);

    let encrypted_private_key =
        encrypt_private_key(&signing_key, password)?;

    let identity = Identity {
        nickname,
        encrypted_private_key,
    };

    Ok((identity, signing_key))
}