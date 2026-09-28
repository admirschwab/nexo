use crate::chat::{
    crypto::HandshakeRole,
    session::{HandshakeTimeout, ReceivedText, Session},
};
use crate::models::{
    peer_message::PeerMessage,
    protocol::{ClientMessage, OnlineUser, ServerMessage},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use ratatui::{
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    widgets::ListState,
};
use zeroize::{Zeroize, Zeroizing};

// Weitere Zeichen werden bei der Eingabe ignoriert
pub const MAX_INPUT_LENGTH: usize = 1000;

pub enum LineKind {
    Own,
    Peer,
    System,
}

pub struct ChatLine {
    pub time: String,
    pub kind: LineKind,
    pub text: String,
}

// Der Verlauf soll nach dem Beenden nicht im Arbeitsspeicher zurückbleiben
impl Drop for ChatLine {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

// Ein Eintrag in der Liste: ein Nutzer, der online ist, oder ein Chat mit
// jemandem, der inzwischen offline ist (ausgegraut bis Nexo beendet wird)
pub struct Conversation {
    pub nickname: String,
    pub public_key: String,
    pub verifying_key: VerifyingKey,
    pub online: bool,
    // Verbindung des Partners, zu der die aktuelle Sitzung gehört
    connection_id: u64,
    // Verlauf, nur im Arbeitsspeicher
    pub lines: Vec<ChatLine>,
    pub unread: usize,
    pub session: Session,
}

impl Conversation {
    fn push(&mut self, kind: LineKind, text: String) {
        self.lines.push(ChatLine {
            time: chrono::Local::now().format("%H:%M").to_string(),
            kind,
            text,
        });
    }

    fn system(&mut self, text: String) {
        self.push(LineKind::System, text);
    }
}

#[derive(PartialEq)]
pub enum View {
    List,
    // Offener Chat, identifiziert über den Public Key
    Chat(String),
}

// Zustand des Overlays
pub struct App {
    pub nickname: String,
    pub public_key: String,
    pub server: String,
    signing_key: SigningKey,
    pub connected: bool,
    pub conversations: Vec<Conversation>,
    pub list_state: ListState,
    pub view: View,
    pub input: String,
    pub status: String,
    pub should_quit: bool,
    // Nachrichten, die an den Server gehen sollen (die Ereignisschleife verschickt sie)
    pub outgoing: Vec<ClientMessage>,
}

impl App {
    pub fn new(nickname: String, signing_key: SigningKey, server: String) -> Self {
        Self {
            nickname,
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            server,
            signing_key,
            connected: true,
            conversations: Vec::new(),
            list_state: ListState::default(),
            view: View::List,
            // Platz für die längste erlaubte Eingabe (bis zu 4 Bytes pro Zeichen).
            // So wird der Puffer beim Tippen nie umkopiert und es bleiben
            // keine alten Kopien der Eingabe im Speicher liegen.
            input: String::with_capacity(MAX_INPUT_LENGTH * 4),
            status: String::new(),
            should_quit: false,
            outgoing: Vec::new(),
        }
    }

    pub fn online_count(&self) -> usize {
        self.conversations
            .iter()
            .filter(|conversation| conversation.online)
            .count()
    }

    pub fn open_conversation(&self) -> Option<&Conversation> {
        match &self.view {
            View::Chat(public_key) => self.find(public_key).map(|index| &self.conversations[index]),
            View::List => None,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            self.should_quit = true;
            return;
        }

        match self.view {
            View::List => self.handle_list_key(key),
            View::Chat(_) => self.handle_chat_key(key),
        }
    }

    fn handle_list_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Up | KeyCode::Char('k') => self.list_state.select_previous(),
            KeyCode::Down | KeyCode::Char('j') => self.list_state.select_next(),
            KeyCode::Enter => {
                let selected = self
                    .list_state
                    .selected()
                    .and_then(|index| self.conversations.get_mut(index));

                if let Some(conversation) = selected {
                    conversation.unread = 0;
                    self.view = View::Chat(conversation.public_key.clone());
                    self.status.clear();
                }
            }
            _ => {}
        }
    }

    fn handle_chat_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.view = View::List;
                self.status.clear();
            }
            KeyCode::Enter => self.send_input(),
            KeyCode::Backspace => {
                self.input.pop();
            }
            // AltGr-Zeichen (z. B. @ auf deutscher Tastatur) kommen als Strg+Alt an
            KeyCode::Char(c) if key.modifiers != KeyModifiers::CONTROL => {
                if self.input.chars().count() < MAX_INPUT_LENGTH {
                    self.input.push(c);
                }
            }
            _ => {}
        }
    }

    fn send_input(&mut self) {
        let text = Zeroizing::new(self.input.trim().to_string());

        if text.is_empty() {
            return;
        }

        let View::Chat(public_key) = &self.view else {
            return;
        };

        let Some(index) = self.find(public_key) else {
            return;
        };

        let conversation = &mut self.conversations[index];

        if !conversation.online {
            conversation.system(format!(
                "{} is offline, message not sent",
                conversation.nickname
            ));
            return;
        }

        // Überschreibt die Eingabe mit Nullen, der Puffer bleibt erhalten
        self.input.zeroize();

        match conversation.session.send_text(
            &self.signing_key,
            &conversation.verifying_key,
            text.clone(),
        ) {
            Ok(messages) => {
                conversation.push(LineKind::Own, text.to_string());
                queue(&mut self.outgoing, &conversation.public_key, messages);
            }
            Err(error) => conversation.system(format!("Could not send message: {error}")),
        }
    }

    pub fn handle_server_message(&mut self, message: ServerMessage) {
        match message {
            ServerMessage::OnlineUsers { users } => self.set_online_users(users),
            ServerMessage::Received { from, payload } => self.receive(from, payload),
            ServerMessage::NotDelivered { to } => {
                if let Some(index) = self.find(&to) {
                    let conversation = &mut self.conversations[index];

                    conversation.system(format!(
                        "{} is offline, message not delivered",
                        conversation.nickname
                    ));
                }
            }
            ServerMessage::RateLimited { to } => {
                if let Some(index) = self.find(&to) {
                    let conversation = &mut self.conversations[index];

                    conversation.system("Slow down, message not delivered".to_string());

                    // War es der Handshake, würde die Sitzung sonst ewig warten
                    if conversation.session.is_pending() {
                        let dropped = conversation.session.reset();

                        if dropped > 0 {
                            conversation.system(format!("{dropped} message(s) could not be delivered"));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn receive(&mut self, from: String, payload: String) {
        // Nachrichten von Unbekannten (nicht in der Liste) werden ignoriert
        let Some(index) = self.find(&from) else {
            return;
        };

        let Ok(message) = serde_json::from_str::<PeerMessage>(&payload) else {
            return;
        };

        let role = match message {
            PeerMessage::HandshakeReply { .. } => HandshakeRole::Reply,
            _ => HandshakeRole::Init,
        };

        let viewing = self.view == View::Chat(from.clone());
        let conversation = &mut self.conversations[index];

        match message {
            PeerMessage::HandshakeInit {
                ephemeral_key,
                signature,
            }
            | PeerMessage::HandshakeReply {
                ephemeral_key,
                signature,
            } => match conversation.session.receive_handshake(
                role,
                &self.signing_key,
                &conversation.verifying_key,
                &ephemeral_key,
                &signature,
            ) {
                Ok(messages) => queue(&mut self.outgoing, &from, messages),
                Err(_) => conversation.system(format!(
                    "Warning: invalid key exchange from {} was ignored",
                    conversation.nickname
                )),
            },

            PeerMessage::Text { nonce, ciphertext } => match conversation.session.receive_text(
                &self.signing_key,
                &conversation.verifying_key,
                &nonce,
                &ciphertext,
            ) {
                ReceivedText::Text(text) => {
                    conversation.push(LineKind::Peer, text);

                    if !viewing {
                        conversation.unread += 1;
                        self.status = format!("New message from {}", conversation.nickname);
                    }
                }
                ReceivedText::NoSession(messages) => {
                    conversation.system(format!(
                        "A message from {} could not be decrypted, setting up a new encrypted session",
                        conversation.nickname
                    ));
                    queue(&mut self.outgoing, &from, messages);
                }
                ReceivedText::Invalid => conversation.system(format!(
                    "Warning: a message from {} could not be decrypted",
                    conversation.nickname
                )),
            },
        }
    }

    // Wird regelmäßig aufgerufen: wiederholt unbeantwortete Handshakes
    pub fn tick(&mut self) {
        if !self.connected {
            return;
        }

        for conversation in &mut self.conversations {
            if !conversation.online || !conversation.session.is_pending() {
                continue;
            }

            match conversation
                .session
                .check_timeout(&self.signing_key, &conversation.verifying_key)
            {
                Ok(HandshakeTimeout::Waiting) => {}
                Ok(HandshakeTimeout::Retry(messages)) => {
                    queue(&mut self.outgoing, &conversation.public_key, messages);
                }
                Ok(HandshakeTimeout::GaveUp(dropped)) => {
                    conversation.system(format!(
                        "Could not set up an encrypted session with {}",
                        conversation.nickname
                    ));

                    if dropped > 0 {
                        conversation.system(format!("{dropped} message(s) could not be delivered"));
                    }
                }
                Err(error) => {
                    let dropped = conversation.session.reset();

                    conversation.system(format!("Key exchange failed: {error}"));

                    if dropped > 0 {
                        conversation.system(format!("{dropped} message(s) could not be delivered"));
                    }
                }
            }
        }
    }

    pub fn disconnected(&mut self) {
        self.connected = false;
        self.set_online_users(Vec::new());
        self.status = "Connection to server lost. Press q to quit.".to_string();
    }

    fn find(&self, public_key: &str) -> Option<usize> {
        self.conversations
            .iter()
            .position(|conversation| conversation.public_key == public_key)
    }

    fn set_online_users(&mut self, users: Vec<OnlineUser>) {
        // Auswahl beim selben Eintrag halten, auch wenn sich die Liste ändert
        let selected_key = self
            .list_state
            .selected()
            .and_then(|index| self.conversations.get(index))
            .map(|conversation| conversation.public_key.clone());

        for conversation in &mut self.conversations {
            let current = users
                .iter()
                .find(|user| user.public_key == conversation.public_key);

            let online = current.is_some();

            // Neu verbunden, ohne dazwischen offline gewesen zu sein:
            // Der Partner hat seine Schlüssel verloren, also neu aushandeln
            if let Some(user) = current {
                if conversation.online && user.connection_id != conversation.connection_id {
                    let dropped = conversation.session.reset();

                    if !conversation.lines.is_empty() {
                        conversation.system(format!("{} reconnected", conversation.nickname));
                    }

                    if dropped > 0 {
                        conversation.system(format!("{dropped} message(s) could not be delivered"));
                    }
                }

                conversation.connection_id = user.connection_id;
            }

            if conversation.online && !online {
                conversation.online = false;

                // Schlüssel dieser Sitzung verwerfen
                let dropped = conversation.session.reset();

                if !conversation.lines.is_empty() {
                    conversation.system(format!("{} went offline", conversation.nickname));
                }

                if dropped > 0 {
                    conversation.system(format!("{dropped} message(s) could not be delivered"));
                }
            } else if !conversation.online && online {
                conversation.online = true;

                if !conversation.lines.is_empty() {
                    conversation.system(format!("{} is back online", conversation.nickname));
                }
            }
        }

        for user in users {
            if user.public_key == self.public_key || self.find(&user.public_key).is_some() {
                continue;
            }

            let Some(verifying_key) = parse_verifying_key(&user.public_key) else {
                continue;
            };

            self.conversations.push(Conversation {
                nickname: user.nickname,
                public_key: user.public_key,
                verifying_key,
                online: true,
                connection_id: user.connection_id,
                lines: Vec::new(),
                unread: 0,
                session: Session::None,
            });
        }

        // Offline ohne Verlauf braucht niemand in der Liste
        self.conversations
            .retain(|conversation| conversation.online || !conversation.lines.is_empty());

        // Online zuerst, dann alphabetisch
        self.conversations.sort_by_key(|conversation| {
            (!conversation.online, conversation.nickname.to_lowercase())
        });

        if let View::Chat(public_key) = &self.view {
            if self.find(public_key).is_none() {
                self.view = View::List;
            }
        }

        let index = selected_key
            .and_then(|key| self.find(&key))
            .or(if self.conversations.is_empty() { None } else { Some(0) });

        self.list_state.select(index);
    }
}

// Eine angefangene Eingabe soll nach dem Beenden nicht im Speicher zurückbleiben
impl Drop for App {
    fn drop(&mut self) {
        self.input.zeroize();
    }
}

fn queue(outgoing: &mut Vec<ClientMessage>, to: &str, messages: Vec<PeerMessage>) {
    for message in messages {
        if let Ok(payload) = serde_json::to_string(&message) {
            outgoing.push(ClientMessage::Send {
                to: to.to_string(),
                payload,
            });
        }
    }
}

fn parse_verifying_key(public_key: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(public_key).ok()?.try_into().ok()?;

    VerifyingKey::from_bytes(&bytes).ok()
}
