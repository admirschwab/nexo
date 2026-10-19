use crate::chat::{
    crypto::{safety_number, HandshakeRole},
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
use std::cell::Cell;
use unicode_segmentation::UnicodeSegmentation;
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
    // Aus beiden Public Keys berechnet, zum Vergleichen am Telefon oder persönlich
    pub safety_number: String,
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
    // Position des Cursors in `input` (Byte-Index, immer an einer Zeichengrenze)
    pub cursor: usize,
    // Erstes sichtbares Byte der Eingabe, wenn sie länger als das Feld ist.
    // Wird beim Zeichnen angepasst, damit der Cursor sichtbar bleibt.
    pub input_scroll: Cell<usize>,
    // Oberste sichtbare Zeile des Verlaufs im offenen Chat.
    // None: ganz unten, neue Nachrichten rutschen automatisch nach.
    pub chat_scroll: Option<usize>,
    // Neue Nachrichten, seit hochgescrollt wurde (für den Hinweis unten im Verlauf)
    pub unseen: usize,
    // Zeilen des Verlaufs und Höhe des Felds beim letzten Zeichnen.
    // Daraus ergibt sich, wie weit gescrollt werden kann.
    pub chat_lines: Cell<usize>,
    pub chat_height: Cell<usize>,
    pub status: String,
    // Warum und wann die Verbindung abgerissen ist. Bleibt stehen, auch wenn
    // `status` beim Wechseln der Ansicht geleert wird.
    pub disconnect_reason: String,
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
            cursor: 0,
            input_scroll: Cell::new(0),
            chat_scroll: None,
            unseen: 0,
            chat_lines: Cell::new(0),
            chat_height: Cell::new(0),
            status: String::new(),
            disconnect_reason: String::new(),
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
                    // Ein Chat öffnet immer bei den neuesten Nachrichten
                    self.chat_scroll = None;
                    self.unseen = 0;
                }
            }
            _ => {}
        }
    }

    fn handle_chat_key(&mut self, key: KeyEvent) {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);

        // Der Puffer hat Platz für die längste Eingabe: Einfügen und Löschen
        // verschieben nur innerhalb des Puffers, es entstehen keine Kopien
        match key.code {
            KeyCode::Esc => {
                self.view = View::List;
                self.status.clear();
            }
            KeyCode::Enter => self.send_input(),
            KeyCode::Up => self.scroll_up(1),
            KeyCode::Down => self.scroll_down(1),
            KeyCode::PageUp => self.scroll_up(self.page()),
            KeyCode::PageDown => self.scroll_down(self.page()),
            KeyCode::End if control => self.scroll_to_bottom(),
            KeyCode::Left if control => self.cursor = self.previous_word(),
            KeyCode::Right if control => self.cursor = self.next_word(),
            KeyCode::Left => self.cursor = self.previous_boundary(),
            KeyCode::Right => self.cursor = self.next_boundary(),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.input.len(),
            // Löscht ein ganzes sichtbares Zeichen. Viele Emojis bestehen aus mehreren
            // Teilen (z. B. 👍🏽 oder 👨‍👩‍👧), die sonst einzeln gelöscht würden.
            KeyCode::Backspace => {
                let start = self.previous_boundary();
                self.input.replace_range(start..self.cursor, "");
                self.cursor = start;
            }
            KeyCode::Delete => {
                let end = self.next_boundary();
                self.input.replace_range(self.cursor..end, "");
            }
            // AltGr-Zeichen (z. B. @ auf deutscher Tastatur) kommen als Strg+Alt an
            KeyCode::Char(c) if key.modifiers != KeyModifiers::CONTROL => {
                if self.input.chars().count() < MAX_INPUT_LENGTH {
                    self.input.insert(self.cursor, c);
                    self.cursor += c.len_utf8();
                }
            }
            _ => {}
        }
    }

    // Eine Seite weit scrollen, eine Zeile bleibt zur Orientierung stehen
    fn page(&self) -> usize {
        self.chat_height.get().saturating_sub(1).max(1)
    }

    // Weiteste Position: die letzte Zeile steht ganz unten
    fn max_scroll(&self) -> usize {
        self.chat_lines.get().saturating_sub(self.chat_height.get())
    }

    fn scroll_up(&mut self, lines: usize) {
        let max = self.max_scroll();

        // Alles passt ins Feld, es gibt nichts zu scrollen
        if max == 0 {
            return;
        }

        let top = self.chat_scroll.unwrap_or(max).min(max);
        self.chat_scroll = Some(top.saturating_sub(lines));
    }

    fn scroll_down(&mut self, lines: usize) {
        let Some(top) = self.chat_scroll else {
            return;
        };

        if top + lines >= self.max_scroll() {
            self.scroll_to_bottom();
        } else {
            self.chat_scroll = Some(top + lines);
        }
    }

    fn scroll_to_bottom(&mut self) {
        self.chat_scroll = None;
        self.unseen = 0;
    }

    // Anfang des sichtbaren Zeichens vor dem Cursor
    fn previous_boundary(&self) -> usize {
        self.input[..self.cursor]
            .grapheme_indices(true)
            .next_back()
            .map_or(0, |(index, _)| index)
    }

    // Ende des sichtbaren Zeichens nach dem Cursor
    fn next_boundary(&self) -> usize {
        self.input[self.cursor..]
            .graphemes(true)
            .next()
            .map_or(self.cursor, |grapheme| self.cursor + grapheme.len())
    }

    // Strg+←: an den Anfang des aktuellen oder vorigen Worts
    fn previous_word(&self) -> usize {
        let mut position = self.cursor;
        let mut in_word = false;

        for (index, grapheme) in self.input[..self.cursor].grapheme_indices(true).rev() {
            let space = is_space(grapheme);

            if space && in_word {
                break;
            }

            in_word |= !space;
            position = index;
        }

        position
    }

    // Strg+→: an den Anfang des nächsten Worts (oder ans Ende)
    fn next_word(&self) -> usize {
        let mut after_space = false;

        for (index, grapheme) in self.input[self.cursor..].grapheme_indices(true) {
            let space = is_space(grapheme);

            if !space && after_space {
                return self.cursor + index;
            }

            after_space |= space;
        }

        self.input.len()
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
        self.cursor = 0;

        match conversation.session.send_text(
            &self.signing_key,
            &conversation.verifying_key,
            text.clone(),
        ) {
            Ok(messages) => {
                conversation.push(LineKind::Own, text.to_string());
                // Nach dem Senden die eigene Nachricht zeigen
                self.chat_scroll = None;
                self.unseen = 0;
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
                ReceivedText::Text { text, lost } => {
                    // Der Server hat Nachrichten verworfen oder nicht zugestellt
                    if lost > 0 {
                        conversation.system(format!(
                            "{lost} message(s) from {} got lost on the way",
                            conversation.nickname
                        ));
                    }

                    conversation.push(LineKind::Peer, text);

                    // Hochgescrollt: Der Ausschnitt bleibt stehen, unten erscheint ein Hinweis
                    if viewing && self.chat_scroll.is_some() {
                        self.unseen += 1;
                    }

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

    // `reason` erklärt, wie die Verbindung geendet hat. Mit der Uhrzeit lässt sich
    // ein Abriss z. B. einem Neustart des Servers oder der eigenen Leitung zuordnen.
    pub fn disconnected(&mut self, reason: &str) {
        self.connected = false;
        self.set_online_users(Vec::new());
        self.disconnect_reason = format!(
            "Connection to server lost at {}: {reason}. Press q to quit.",
            chrono::Local::now().format("%H:%M:%S")
        );
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

            let safety_number = safety_number(&self.signing_key.verifying_key(), &verifying_key);

            self.conversations.push(Conversation {
                nickname: user.nickname,
                public_key: user.public_key,
                verifying_key,
                online: true,
                connection_id: user.connection_id,
                lines: Vec::new(),
                unread: 0,
                session: Session::None,
                safety_number,
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

fn is_space(grapheme: &str) -> bool {
    grapheme.chars().all(char::is_whitespace)
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
