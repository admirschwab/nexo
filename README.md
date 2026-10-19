# Nexo

**A privacy-focused, end-to-end encrypted messenger for the terminal, written in Rust.**

Messages are encrypted on your computer before they leave it. The server only passes them on and
never sees their content. It knows just what it needs to connect people:

* your **public key**
* your **nickname**
* whether you are **online** right now

There is no chat history: not on the server, and not on your computer. Messages only reach people
who are online, and once you close Nexo, the conversation is gone.

## Features

* End-to-end encryption with a fresh key for every session
* Safety numbers: compare a 60-digit number with your contact (by phone or in person) to make sure
  nobody, not even the server, is listening in
* Lost, replayed or reordered messages are detected
* Your private key is stored encrypted with your password
* No accounts, e-mail addresses or phone numbers: your identity is a key pair
* No message storage, no chat history, no cloud sync
* Delete your account at any time with `nexo unregister`: the server forgets your public key and nickname
* Emoji support

## Installation

### Windows

Open PowerShell and run:

```powershell
irm https://raw.githubusercontent.com/admirschwab/nexo/main/install.ps1 | iex
```

This downloads `nexo.exe` from the latest release, verifies its SHA-256 checksum, installs it to
`%LOCALAPPDATA%\Programs\nexo` and adds it to your PATH. No administrator rights are needed.
Afterwards, `nexo` works in any terminal.

Use [Windows Terminal](https://aka.ms/terminal): the old console window cannot show emojis.

### From source (any platform)

With [Rust](https://rustup.rs) 1.85 or newer installed:

```sh
cargo install --git https://github.com/admirschwab/nexo
```

### Updating

Run the install command again. Your identity is not touched. Check the installed version with
`nexo --version`.

A server can require a minimum version. If yours is too old, Nexo tells you when you log in and
shows the command to update.

### Uninstalling

```powershell
irm https://raw.githubusercontent.com/admirschwab/nexo/main/uninstall.ps1 | iex
```

This keeps your identity (`%LOCALAPPDATA%\nexo`). To delete your account completely, run
`nexo unregister` **before** uninstalling.

## Getting started

```sh
nexo register
```

Choose a nickname (3–20 characters: letters, digits, `_` or `-`), enter the address of your Nexo
server (e.g. `https://chat.example.com`) and a password with at least 8 characters.

```sh
nexo login
```

Enter your password, pick someone from the list of online users and start chatting.

## Commands

| Command | Description |
|---|---|
| `nexo register` | Create a new identity and register it on a server |
| `nexo login` | Log in and chat |
| `nexo passwd` | Change your password |
| `nexo server` | Show the server address |
| `nexo server <url>` | Change the server address (e.g. if the server moved) |
| `nexo unregister` | Permanently delete your identity from the server and this computer |
| `nexo --version` | Show the installed version |

## Keyboard shortcuts

**User list**

| Key | Action |
|---|---|
| `↑` / `↓` | Select a user |
| `Enter` | Open the chat |
| `q` / `Esc` | Quit |

**Chat**

| Key | Action |
|---|---|
| `Enter` | Send the message |
| `←` / `→` | Move the cursor |
| `Ctrl+←` / `Ctrl+→` | Jump to the previous / next word |
| `Home` / `End` | Jump to the start / end of the message |
| `Backspace` / `Del` | Delete before / after the cursor |
| `↑` / `↓` | Scroll the chat by one line |
| `PgUp` / `PgDn` | Scroll the chat by one page |
| `Ctrl+End` | Back to the newest messages |
| `Esc` | Back to the user list |
| `Ctrl+C` | Quit |

## Security

* **Identity:** an Ed25519 key pair, created on your computer. The private key never leaves it.
* **Login:** the server sends a random challenge, Nexo signs it. No password is sent to the server.
* **Messages:** for every chat session, both sides create a fresh X25519 key and sign it with their
  identity key. The shared chat key is derived from both (Diffie-Hellman + HKDF-SHA256). Messages
  are encrypted with XChaCha20-Poly1305 and padded to fixed sizes, so their length does not reveal
  how long the text is.
* **No old messages:** session keys only exist in memory. Once Nexo is closed, past messages can't
  be decrypted, not even with your identity file and password.
* **Identity file:** encrypted with XChaCha20-Poly1305, the key is derived from your password with
  Argon2id (64 MiB). Without the password, the file reveals neither your nickname nor your server.
* **Safety numbers:** the server could, in theory, hand out a wrong public key. Comparing the safety
  number shown in the chat with your contact rules that out.

Use a server with `https://`. Over plain `http://`, messages stay end-to-end encrypted, but anyone
on the network can see who talks to whom and when. Nexo shows a warning in that case.

## Files

Nexo keeps its data in one folder, so `nexo` works from any directory:

* Windows: `%LOCALAPPDATA%\nexo`
* Linux: `~/.local/share/nexo`
* macOS: `~/Library/Application Support/nexo`

On Windows, the local folder is used on purpose (not the roaming `%APPDATA%`), so your identity is
never synced to other machines.

The folder contains a single file, `identity.nexo`: your private key, nickname and server address,
all encrypted with your password.

## Architecture

Nexo consists of two Rust projects:

* [`nexo`](https://github.com/admirschwab/nexo) (this repository): the client, binary `nexo`
* [`nexo-server`](https://github.com/admirschwab/nexo-server): a minimal directory and relay server

The server acts as a **directory and relay**, not as a message archive. See its README for how to
run your own.

## Development

The version is set in `Cargo.toml`. Releases are built by GitHub Actions when a matching version
tag is pushed:

```sh
# after setting version = "x.y.z" in Cargo.toml and running cargo check
git tag vx.y.z
git push origin vx.y.z
```

The workflow fails if the tag does not match the version in `Cargo.toml`.

## Project status

Nexo is under active development and intentionally kept small. Groups, file sharing, message
history, reactions, read receipts and cloud sync are not part of the design.
