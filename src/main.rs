mod chat;
mod config;
mod functions;
mod models;
mod overlay;

use clap::{Parser, Subcommand};
use config::{load_config, Config};
use dialoguer::{Input, Password};
use functions::{
    connect::connect,
    create_identity::create_identity,
    decrypt_private_key::decrypt_private_key,
    load_identity::load_identity,
    register_identity::register_identity,
    save_identity::save_identity,
    validate_nickname::validate_nickname,
};
use overlay::run_overlay;
use std::{error::Error, path::Path, process};

const IDENTITY_PATH: &str = "identity.nexo";
const PASSWORD_MIN_LENGTH: usize = 8;

#[derive(Parser)]
#[command(name = "nexo")]
#[command(about = "A simple private CLI messenger")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new identity on this computer and register it on the server
    Register,
    /// Log in with the identity stored on this computer
    Login,
    /// Show the identity stored on this computer
    Whoami,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(error) = run(cli).await {
        eprintln!("Error: {error}");
        process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    let config = load_config()
        .map_err(|error| format!("Could not read config.toml: {error}"))?;

    match cli.command {
        Commands::Register => register(&config).await,
        Commands::Login => login(&config).await,
        Commands::Whoami => whoami(),
    }
}

async fn register(config: &Config) -> Result<(), Box<dyn Error>> {
    let identity_path = Path::new(IDENTITY_PATH);

    // Pro Rechner gibt es genau eine Identität
    if identity_path.exists() {
        return Err(
            "This computer is already registered. Use `nexo login` instead.".into(),
        );
    }

    let nickname: String = Input::new()
        .with_prompt("Choose a nickname")
        .validate_with(|nickname: &String| {
            if validate_nickname(nickname) {
                Ok(())
            } else {
                Err("Nickname must be 3-20 characters: letters, digits, '_' or '-'")
            }
        })
        .interact_text()?;

    let password = Password::new()
        .with_prompt("Choose a password")
        .with_confirmation("Repeat password", "Passwords do not match")
        .validate_with(|password: &String| {
            if password.chars().count() >= PASSWORD_MIN_LENGTH {
                Ok(())
            } else {
                Err(format!(
                    "Password must be at least {PASSWORD_MIN_LENGTH} characters"
                ))
            }
        })
        .interact()?;

    let (identity, signing_key) = create_identity(nickname, &password)?;

    // Erst beim Server registrieren, dann lokal speichern:
    // Ist der Nickname vergeben, bleibt keine Identitätsdatei zurück
    register_identity(config, &identity, &signing_key).await?;

    save_identity(identity_path, &identity)?;

    println!();
    println!("Registered successfully.");
    println!("Nickname:   {}", identity.nickname);
    println!(
        "Public key: {}",
        hex::encode(signing_key.verifying_key().to_bytes())
    );
    println!();
    println!("Use `nexo login` to log in.");

    Ok(())
}

async fn login(config: &Config) -> Result<(), Box<dyn Error>> {
    let identity_path = Path::new(IDENTITY_PATH);

    if !identity_path.exists() {
        return Err(
            "No identity found on this computer. Use `nexo register` first.".into(),
        );
    }

    let identity = load_identity(identity_path)?;

    let password = Password::new()
        .with_prompt("Password")
        .interact()?;

    let signing_key = decrypt_private_key(
        &identity.encrypted_private_key,
        &password,
    )
        .map_err(|_| "Wrong password or corrupted identity file")?;

    println!("Connecting to {} ...", config.server);

    let (connection, nickname) = connect(config, &signing_key).await?;

    run_overlay(connection, nickname, signing_key, config.server.clone()).await
}

fn whoami() -> Result<(), Box<dyn Error>> {
    let identity_path = Path::new(IDENTITY_PATH);

    if !identity_path.exists() {
        return Err(
            "No identity found on this computer. Use `nexo register` first.".into(),
        );
    }

    let identity = load_identity(identity_path)?;

    let password = Password::new()
        .with_prompt("Password")
        .interact()?;

    let signing_key = decrypt_private_key(
        &identity.encrypted_private_key,
        &password,
    )
        .map_err(|_| "Wrong password or corrupted identity file")?;

    println!("Nickname:   {}", identity.nickname);
    println!(
        "Public key: {}",
        hex::encode(signing_key.verifying_key().to_bytes())
    );

    Ok(())
}
