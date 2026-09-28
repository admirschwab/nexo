# Nexo

**Nexo is a privacy-focused, end-to-end encrypted CLI messenger written in Rust.**

Your messages are encrypted locally on your computer before they leave your device. The server never receives the plaintext of your messages and does not store your private key.

The server only knows the information it needs to connect users:

* Your **public key**
* Your **nickname**
* Whether you are currently **online**

You can only send messages to users who are currently online. Nexo does not store chat history on the server or permanently on the client.

Once you close the CLI, the current chat history is gone.

There are no pop-up notifications, no cloud-synced conversations, and no message history waiting on a server.

Nexo is designed to keep messaging **simple, private, and minimal**.

## Features

* End-to-end encrypted messaging
* Safety numbers: compare a 60-digit number with your contact (by phone or in person) to make sure nobody, not even the server, is in between
* Lost, replayed or reordered messages are detected
* Local encrypted private key
* Public-key-based identity
* Privacy-focused server architecture
* No server-side message storage
* No chat history
* Online-only messaging
* Delete your account at any time with `nexo unregister`: the server forgets your public key and nickname
* CLI-based interface
* Written in Rust

## Files

Nexo keeps its files in one folder, so `nexo` works from any directory:

* Windows: `%LOCALAPPDATA%\nexo`
* Linux: `~/.local/share/nexo`
* macOS: `~/Library/Application Support/nexo`

The local folder is used on purpose (not the roaming `%APPDATA%`), so your identity is never synced to other machines or servers.

It contains only two files:

* `identity.nexo` — your private key and nickname, encrypted with your password
* `config.toml` — the server address (created on first start)

## Architecture

Nexo consists of two separate Rust projects:

* `nexo-cli` — the client used to create identities, connect to the server, and chat
* `nexo-server` — a minimal server that handles user discovery and message relaying

The server acts as a **directory and relay**, not as a message archive.

## Project Status

Nexo is currently under active development.

The project is intentionally kept small and simple. Features such as groups, file sharing, message history, reactions, read receipts, and cloud synchronization are not part of the current design.
