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
* Local encrypted private key
* Public-key-based identity
* Privacy-focused server architecture
* No server-side message storage
* No chat history
* Online-only messaging
* CLI-based interface
* Written in Rust

## Architecture

Nexo consists of two separate Rust projects:

* `nexo-cli` — the client used to create identities, connect to the server, and chat
* `nexo-server` — a minimal server that handles user discovery and message relaying

The server acts as a **directory and relay**, not as a message archive.

## Project Status

Nexo is currently under active development.

The project is intentionally kept small and simple. Features such as groups, file sharing, message history, reactions, read receipts, and cloud synchronization are not part of the current design.
