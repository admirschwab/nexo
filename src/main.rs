mod chat;
mod config;
mod functions;
mod models;
mod overlay;
mod paths;

use clap::{Parser, Subcommand};
use config::{validate_server, warn_if_insecure, Config, DEFAULT_SERVER};
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
use models::identity::Identity;
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
    /// Change the password of the identity stored on this computer
    Passwd,
    /// Show the server address, or change it (e.g. if the server moved)
    Server {
        /// New server address, starting with http:// or https://
        url: Option<String>,
    },
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

    match cli.command {
        Commands::Register => register(&paths).await,
        Commands::Login => login(&paths).await,
        Commands::Unregister => unregister(&paths).await,
        Commands::Passwd => change_password(&paths),
        Commands::Server { url } => server(&paths, url),
    }
}

async fn register(paths: &Paths) -> Result<(), Box<dyn Error>> {
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

    let server = prompt_server(paths)?;
    let config = Config { server };

    warn_if_insecure(&config);

    let password = prompt_new_password("Choose a password")?;

    let (identity, encrypted) = create_identity(nickname, config.server.clone(), &password)?;

    // Erst lokal in eine Zwischendatei speichern, dann registrieren, dann umbenennen.
    // So geht der Schlüssel nie verloren, wenn der Nickname schon registriert ist,
    // und wenn die Registrierung scheitert, bleibt keine Identitätsdatei zurück.
    save_identity(&paths.pending_identity, &encrypted).map_err(|error| {
        format!("Could not save {}: {error}", paths.pending_identity.display())
    })?;

    if let Err(error) = register_identity(&config, &identity).await {
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

    delete_old_config(paths);

    // Bewusst ohne Nickname, Public Key oder Server: Alles, was hier ausgegeben
    // wird, bleibt im Verlauf des Terminals stehen
    println!();
    println!("Registered successfully. Nexo is ready to serve. Use `nexo login` to log in.");

    Ok(())
}

async fn login(paths: &Paths) -> Result<(), Box<dyn Error>> {
    let (identity, _) = unlock_identity(paths, "Password")?;
    let config = Config {
        server: identity.server.clone(),
    };

    warn_if_insecure(&config);

    println!("Connecting ...");

    let (connection, nickname) = connect(&config, &identity.signing_key).await?;

    run_overlay(connection, nickname, identity.signing_key, config.server).await
}

async fn unregister(paths: &Paths) -> Result<(), Box<dyn Error>> {
    let (identity, _) = unlock_identity(paths, "Password")?;
    let config = Config {
        server: identity.server.clone(),
    };

    let confirmed = Confirm::new()
        .with_prompt(
            "Permanently delete your identity from the server and this computer? \
             This cannot be undone.",
        )
        .default(false)
        .interact()?;

    if !confirmed {
        println!("Nothing was deleted.");
        return Ok(());
    }

    warn_if_insecure(&config);

    // Erst auf dem Server löschen: Scheitert das, bleibt die lokale Identität erhalten
    unregister_identity(&config, &identity.signing_key).await?;

    fs::remove_file(&paths.identity).map_err(|error| {
        format!(
            "Deleted on the server, but could not delete {}: {error}",
            paths.identity.display()
        )
    })?;

    delete_old_config(paths);

    println!();
    println!("Your identity has been deleted.");
    println!("The server no longer knows your public key or nickname.");

    Ok(())
}

// `nexo passwd`: verschlüsselt die Identitätsdatei mit einem neuen Passwort
fn change_password(paths: &Paths) -> Result<(), Box<dyn Error>> {
    let (identity, _) = unlock_identity(paths, "Current password")?;

    let password = prompt_new_password("New password")?;

    rewrite_identity_file(paths, &identity, &password)?;

    println!("Password changed.");

    Ok(())
}

// `nexo server`: zeigt die Server-Adresse an, `nexo server <url>` ändert sie
fn server(paths: &Paths, url: Option<String>) -> Result<(), Box<dyn Error>> {
    let (mut identity, password) = unlock_identity(paths, "Password")?;

    let Some(url) = url else {
        println!("Server: {}", identity.server);
        return Ok(());
    };

    let url = normalize_server(&url);
    validate_server(&url)?;

    identity.server = url;

    warn_if_insecure(&Config {
        server: identity.server.clone(),
    });

    rewrite_identity_file(paths, &identity, &password)?;

    println!("Server address changed.");
    println!("Note: your identity only exists on the server where you registered it.");

    Ok(())
}

// Lädt identity.nexo und entschlüsselt sie mit dem Passwort.
// Eine Datei aus einer früheren Version wird dabei ins aktuelle Format umgewandelt.
// Gibt auch das Passwort zurück (für Befehle, die die Datei neu schreiben).
fn unlock_identity(
    paths: &Paths,
    prompt: &str,
) -> Result<(Identity, Zeroizing<String>), Box<dyn Error>> {
    if !paths.identity.exists() {
        return Err(
            "No identity found on this computer. Use `nexo register` first.".into(),
        );
    }

    let encrypted = load_identity(&paths.identity)?;

    let password = Zeroizing::new(Password::new().with_prompt(prompt).interact()?);

    let mut identity = decrypt_identity(&encrypted, &password)
        .map_err(|_| "Wrong password or corrupted identity file")?;

    if !encrypted.format.is_current() {
        // Frühere Versionen hatten die Server-Adresse im Klartext in config.toml
        if identity.server.is_empty() {
            identity.server = match paths.old_server_address() {
                Some(server) => server,
                None => prompt_server(paths)?,
            };
        }

        match rewrite_identity_file(paths, &identity, &password) {
            Ok(()) => {
                delete_old_config(paths);
                println!("Your identity file was upgraded to the new, more private format.");
            }
            Err(error) => eprintln!(
                "Warning: could not upgrade {}: {error}",
                paths.identity.display()
            ),
        }
    }

    Ok((identity, password))
}

// Schreibt die Identität neu (aktuelles Format, frischer Salt und Nonce) und
// ersetzt die alte Datei erst, wenn die neue vollständig und lesbar ist
fn rewrite_identity_file(
    paths: &Paths,
    identity: &Identity,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let rewrite_path = paths.rewrite_identity.as_path();

    // Rest eines abgebrochenen Versuchs. Die alte Datei ist dann noch vollständig.
    if rewrite_path.exists() {
        fs::remove_file(rewrite_path)?;
    }

    save_identity(rewrite_path, &encrypt_identity(identity, password)?)?;

    // Neue Datei zur Kontrolle einmal lesen und entschlüsseln
    let check = decrypt_identity(&load_identity(rewrite_path)?, password)?;

    // Über den Public Key vergleichen, damit keine Kopien des privaten Schlüssels entstehen
    if check.signing_key.verifying_key() != identity.signing_key.verifying_key()
        || check.nickname != identity.nickname
        || check.server != identity.server
    {
        let _ = fs::remove_file(rewrite_path);
        return Err("Verification of the new file failed".into());
    }

    fs::rename(rewrite_path, &paths.identity)?;

    Ok(())
}

fn prompt_server(paths: &Paths) -> Result<String, Box<dyn Error>> {
    let default = paths
        .old_server_address()
        .unwrap_or_else(|| DEFAULT_SERVER.to_string());

    let server: String = Input::new()
        .with_prompt("Server address")
        .default(default)
        .validate_with(|server: &String| validate_server(&normalize_server(server)))
        .interact_text()?;

    Ok(normalize_server(&server))
}

fn normalize_server(server: &str) -> String {
    server.trim().trim_end_matches('/').to_string()
}

// Zeroizing überschreibt das Passwort beim Freigeben mit Nullen
fn prompt_new_password(prompt: &str) -> Result<Zeroizing<String>, Box<dyn Error>> {
    Ok(Zeroizing::new(
        Password::new()
            .with_prompt(prompt)
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
            .interact()?,
    ))
}

// Die Server-Adresse steht jetzt verschlüsselt in identity.nexo.
// Eine config.toml früherer Versionen im Nexo-Ordner wird nicht mehr gebraucht.
fn delete_old_config(paths: &Paths) {
    if paths.old_config.is_file() && fs::remove_file(&paths.old_config).is_ok() {
        println!("Deleted {} (the server address is now stored encrypted).", paths.old_config.display());
    }
}
