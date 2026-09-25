mod app;
mod render;

use crate::functions::connect::Connection;
use crate::models::protocol::ServerMessage;
use app::App;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use ratatui::crossterm::event::{Event, EventStream, KeyEventKind};
use render::render;
use std::{error::Error, mem};
use tokio_tungstenite::tungstenite::Message;

// Startet das Vollbild-Overlay nach dem Login.
// Läuft, bis der Nutzer es beendet; danach wird die Verbindung geschlossen
// und alle Chats sind weg.
pub async fn run_overlay(
    connection: Connection,
    nickname: String,
    signing_key: SigningKey,
    server: String,
) -> Result<(), Box<dyn Error>> {
    let (mut ws_sender, mut ws_receiver) = connection.split();

    let mut app = App::new(nickname, signing_key, server);
    let mut events = EventStream::new();

    // Stellt das Terminal auch bei einem Panic wieder her
    let mut terminal = ratatui::init();

    let result: Result<(), Box<dyn Error>> = loop {
        if let Err(error) = terminal.draw(|frame| render(frame, &mut app)) {
            break Err(error.into());
        }

        tokio::select! {
            event = events.next() => match event {
                // Unter Windows kommen Tasten auch beim Loslassen an
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    app.handle_key(key);
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => break Err(error.into()),
                None => break Ok(()),
            },

            message = ws_receiver.next(), if app.connected => match message {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(message) = serde_json::from_str::<ServerMessage>(&text) {
                        app.handle_server_message(message);
                    }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => app.disconnected(),
                Some(Ok(_)) => {}
            },
        }

        // Alles verschicken, was beim Verarbeiten angefallen ist
        for message in mem::take(&mut app.outgoing) {
            if !app.connected {
                break;
            }

            let Ok(text) = serde_json::to_string(&message) else {
                continue;
            };

            if ws_sender.send(Message::text(text)).await.is_err() {
                app.disconnected();
            }
        }

        if app.should_quit {
            break Ok(());
        }
    };

    ratatui::restore();

    // Verbindung schließen: Der Server nimmt uns aus der Online-Liste
    let _ = ws_sender.close().await;

    result
}
