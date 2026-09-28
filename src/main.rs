mod chat;
mod config;
mod functions;
mod models;
mod overlay;
mod paths;

use clap::{Parser, Subcommand};
use config::{load_config, warn_if_insecure, Config};
use dialoguer::{Confirm, Input, Password};
use functions::{
    connect::connect,
    create_identity::create_identity,
    decrypt_identity::decrypt_identity,
    encrypt_identity::encrypt_identity,
    load_identity::load_identity,
    register_identity::register_identity,
    save_identity::save_identity,
    unregister_identity::unregister_identity,
    validate_nickname::validate_nickname,
};
use models::{encrypted_identity::IdentityFormat, identity::Identity};
use overlay::run_overlay;
use paths::Paths;
use std::{error::Error, fs, process};
use zeroize::Zeroizing;

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
    /// Permanently delete your identity from the server and this computer
    Unregister,
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
    let paths = Paths::init()?;

    paths
        .migrate_from_current_dir()
        .map_err(|error| format!("Could not move old files to {}: {error}", paths.dir.display()))?;

    let config = load_config(&paths.config)
        .map_err(|error| format!("Could not read {}: {error}", paths.config.display()))?;

    warn_if_insecure(&config);

    match cli.command {
        Commands::Register => register(&config, &paths).await,
        Commands::Login => login(&config, &paths).await,
        Commands::Unregister => unregister(&config, &paths).await,
    }
}

async fn register(config: &Config, paths: &Paths) -> Result<(), Box<dyn Error>> {
    // Pro Rechner gibt es genau eine Identität
    if paths.identity.exists() {
        return Err(
            "This computer is already registered. Use `nexo login` instead.".into(),
        );
    }

    // Übrig von einer abgebrochenen Registrierung. Ob sie beim Server angekommen ist,
    // lässt sich nicht sicher sagen, also nichts automatisch löschen.
    if paths.pending_identity.exists() {
        return Err(format!(
            "An unfinished registration was found ({}). \
             If it was registered successfully, rename it to {}; \
             otherwise delete it and run `nexo register` again.",
            paths.pending_identity.display(),
            paths::IDENTITY_FILE,
        )
            .into());
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

    // Zeroizing überschreibt das Passwort beim Freigeben mit Nullen
    let password = Zeroizing::new(Password::new()
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
        .interact()?);

    let (identity, encrypted) = create_identity(nickname, &password)?;

    // Erst lokal in eine Zwischendatei speichern, dann registrieren, dann umbenennen.
    // So geht der Schlüssel nie verloren, wenn der Nickname schon registriert ist,
    // und wenn die Registrierung scheitert, bleibt keine Identitätsdatei zurück.
    save_identity(&paths.pending_identity, &encrypted).map_err(|error| {
        format!("Could not save {}: {error}", paths.pending_identity.display())
    })?;

    if let Err(error) = register_identity(config, &identity).await {
        let _ = fs::remove_file(&paths.pending_identity);
        return Err(error);
    }

    fs::rename(&paths.pending_identity, &paths.identity).map_err(|error| {
        format!(
            "Registered, but could not rename {} to {}: {error}. \
             Please rename it yourself, it contains your identity.",
            paths.pending_identity.display(),
            paths::IDENTITY_FILE,
        )
    })?;

    println!();
    println!("Registered successfully.");
    println!("Nickname:   {}", identity.nickname);
    println!(
        "Public key: {}",
        hex::encode(identity.signing_key.verifying_key().to_bytes())
    );
    println!();
    println!("Use `nexo login` to log in.");

    Ok(())
}

async fn login(config: &Config, paths: &Paths) -> Result<(), Box<dyn Error>> {
    let identity = unlock_identity(paths)?;

    println!("Connecting to {} ...", config.server);

    let (connection, nickname) = connect(config, &identity.signing_key).await?;

    run_overlay(
        connection,
        nickname,
        identity.signing_key,
        config.server.clone(),
    )
        .await
}

async fn unregister(config: &Config, paths: &Paths) -> Result<(), Box<dyn Error>> {
    let identity = unlock_identity(paths)?;

    let confirmed = Confirm::new()
        .with_prompt(format!(
            "Permanently delete '{}' from the server and this computer? This cannot be undone.",
            identity.nickname
        ))
        .default(false)
        .interact()?;

    if !confirmed {
        println!("Nothing was deleted.");
        return Ok(());
    }

    // Erst auf dem Server löschen: Scheitert das, bleibt die lokale Identität erhalten
    unregister_identity(config, &identity.signing_key).await?;

    fs::remove_file(&paths.identity).map_err(|error| {
        format!(
            "Deleted on the server, but could not delete {}: {error}",
            paths.identity.display()
        )
    })?;

    println!();
    println!("Your identity '{}' has been deleted.", identity.nickname);
    println!("The server no longer knows your public key or nickname.");

    Ok(())
}

// Lädt identity.nexo und entschlüsselt sie mit dem Passwort.
// Eine Datei im alten Format wird dabei ins neue umgewandelt.
fn unlock_identity(paths: &Paths) -> Result<Identity, Box<dyn Error>> {
    if !paths.identity.exists() {
        return Err(
            "No identity found on this computer. Use `nexo register` first.".into(),
        );
    }

    let encrypted = load_identity(&paths.identity)?;

    let password = Zeroizing::new(Password::new()
        .with_prompt("Password")
        .interact()?);

    let identity = decrypt_identity(&encrypted, &password)
        .map_err(|_| "Wrong password or corrupted identity file")?;

    if matches!(encrypted.format, IdentityFormat::V1 { .. }) {
        match upgrade_identity_file(paths, &identity, &password) {
            Ok(()) => println!("Your identity file was upgraded to the new, more private format."),
            Err(error) => eprintln!(
                "Warning: could not upgrade {}: {error}",
                paths.identity.display()
            ),
        }
    }

    Ok(identity)
}

// Schreibt die Identität im neuen Format (Nickname verschlüsselt, Argon2-Parameter
// in der Datei) und ersetzt die alte Datei erst, wenn die neue vollständig ist
fn upgrade_identity_file(
    paths: &Paths,
    identity: &Identity,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let upgrade_path = paths.upgrade_identity.as_path();

    // Rest eines abgebrochenen Versuchs. Die alte Datei ist dann noch vollständig.
    if upgrade_path.exists() {
        fs::remove_file(upgrade_path)?;
    }

    save_identity(upgrade_path, &encrypt_identity(identity, password)?)?;

    // Neue Datei zur Kontrolle einmal lesen und entschlüsseln
    let check = decrypt_identity(&load_identity(upgrade_path)?, password)?;

    // Über den Public Key vergleichen, damit keine Kopien des privaten Schlüssels entstehen
    if check.signing_key.verifying_key() != identity.signing_key.verifying_key()
        || check.nickname != identity.nickname
    {
        let _ = fs::remove_file(upgrade_path);
        return Err("Verification of the new file failed".into());
    }

    fs::rename(upgrade_path, &paths.identity)?;

    Ok(())
}
