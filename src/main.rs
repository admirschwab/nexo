mod config;
mod functions;
mod models;

use clap::{Parser, Subcommand};
use functions::{
    create_identity::create_identity,
    decrypt_private_key::decrypt_private_key,
    load_identity::load_identity,
    save_identity::save_identity,
    register_identity::register_identity,
};
use std::path::Path;

#[derive(Parser)]
#[command(name = "nexo")]
#[command(about = "A simple private CLI messenger")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Login,
    Whoami,
    Register,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            let password = rpassword::prompt_password("Choose a password: ")
                .expect("Failed to read password");

            let nickname = rpassword::prompt_password("Choose a nickname: ")
                .expect("Failed to read nickname");

            let (identity, signing_key) = create_identity(
                nickname,
                &password,
            )
            .expect("Failed to create identity");

            let identity_path = Path::new("identity.nexo");

            save_identity(identity_path, &identity)
                .expect("Failed to save identity");

            let loaded = load_identity(identity_path)
                .expect("Failed to load identity");

            let decrypted_key = decrypt_private_key(
                &loaded.encrypted_private_key,
                &password,
            )
            .expect("Failed to decrypt private key");

            assert_eq!(
                decrypted_key.to_bytes(),
                signing_key.to_bytes()
            );

            let verifying_key = signing_key.verifying_key();

            println!(
                "Identity created: {}",
                hex::encode(verifying_key.to_bytes())
            );
        }

        Commands::Login => {
            let identity_path = Path::new("identity.nexo");

            let identity = load_identity(identity_path)
                .expect("Failed to load identity");

            let password = rpassword::prompt_password("Password: ")
                .expect("Failed to read password");

            let signing_key = decrypt_private_key(
                &identity.encrypted_private_key,
                &password,
            )
            .expect("Invalid password or corrupted identity");

            let verifying_key = signing_key.verifying_key();

            println!("Logged in as: {}", identity.nickname);
            println!(
                "Public key: {}",
                hex::encode(verifying_key.to_bytes())
            );
        }

        Commands::Whoami => {

            let identity_path = Path::new("identity.nexo");

            let identity = load_identity(identity_path)
                .expect("Failed to load identity");

            let password = rpassword::prompt_password("Password: ")
                .expect("Failed to read password");

            let signing_key = decrypt_private_key(
                &identity.encrypted_private_key,
                &password,
            )
            .expect("Invalid password or corrupted identity");

            let verifying_key = signing_key.verifying_key();

            println!("Nickname: {}", identity.nickname);
            println!(
                "Public key: {}",
                hex::encode(verifying_key.to_bytes())
            );
        }

        Commands::Register => {
            let config = config::load_config()
                .expect("Failed to load config");

            let identity_path = Path::new("identity.nexo");

            let identity = load_identity(identity_path)
                .expect("Failed to load identity");

            let password = rpassword::prompt_password("Password: ")
                .expect("Failed to read password");

            let signing_key = decrypt_private_key(
                &identity.encrypted_private_key,
                &password,
            )
            .expect("Invalid password or corrupted identity");

            register_identity(
                &config,
                &identity,
                &signing_key,
            )
            .expect("Failed to register identity");

            println!("Identity registered successfully.");
        }
    }
}