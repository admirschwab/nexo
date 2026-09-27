use super::app::{App, Conversation, LineKind, MAX_INPUT_LENGTH};
use crate::chat::known_peers::PeerTrust;
use ratatui::{
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, List, ListItem, Paragraph, Wrap},
    Frame,
};

pub fn render(frame: &mut Frame, app: &mut App) {
    let [header_area, main_area, footer_area] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(6),
        Constraint::Length(2),
    ])
        .areas(frame.area());

    render_header(frame, app, header_area);

    let hint = match app.open_conversation() {
        Some(conversation) => {
            render_chat(frame, app, conversation, main_area);

            if conversation.trust.is_warning() {
                "Ctrl+T accept new key · Esc back to list · Ctrl+C quit"
            } else {
                "Enter send · Esc back to list · Ctrl+C quit"
            }
        }
        None => {
            render_list(frame, app, main_area);
            "↑/↓ select · Enter open chat · q quit"
        }
    };

    // Fußzeile: Status und Tastenbelegung
    let footer = Paragraph::new(vec![
        Line::from(app.status.clone().yellow()),
        Line::from(hint.dark_gray()),
    ]);

    frame.render_widget(footer, footer_area.inner(Margin::new(1, 0)));
}

// Kopfbereich: wer bin ich
fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let connection = if app.connected {
        Span::styled("● connected", Style::new().fg(Color::Green))
    } else {
        Span::styled("○ disconnected", Style::new().fg(Color::Red))
    };

    let header = Paragraph::new(vec![
        Line::from(vec!["Logged in as: ".dark_gray(), app.nickname.clone().bold()]),
        Line::from(vec!["Public key:   ".dark_gray(), app.public_key.clone().into()]),
        Line::from(vec![
            "Server:       ".dark_gray(),
            app.server.clone().into(),
            "  ".into(),
            connection,
        ]),
    ])
        .block(Block::bordered().title(" Nexo ".bold()));

    frame.render_widget(header, area);
}

// Liste: alle Online-Nutzer + ausgegraute Chats mit Nutzern, die offline sind
fn render_list(frame: &mut Frame, app: &mut App, area: Rect) {
    let block = Block::bordered().title(format!(" Online ({}) ", app.online_count()));

    if app.conversations.is_empty() {
        let text = if app.connected {
            "Nobody else is online right now."
        } else {
            "Not connected."
        };

        frame.render_widget(Paragraph::new(text.dark_gray()).block(block), area);
        return;
    }

    let items: Vec<ListItem> = app
        .conversations
        .iter()
        .map(|conversation| {
            let mut spans = vec![
                format!("{:<22}", conversation.nickname).into(),
                format!("{:<16}", short_key(&conversation.public_key)).dark_gray(),
            ];

            if conversation.trust.is_warning() {
                spans.push("⚠ key changed".red().bold());
            } else if !conversation.online {
                spans.push("offline".into());
            } else if conversation.unread > 0 {
                spans.push(format!("● {} new", conversation.unread).yellow().bold());
            }

            let line = Line::from(spans);

            if conversation.online {
                ListItem::new(line)
            } else {
                ListItem::new(line).style(Style::new().fg(Color::DarkGray))
            }
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_symbol("> ")
        .highlight_style(Style::new().add_modifier(Modifier::BOLD).fg(Color::Cyan));

    frame.render_stateful_widget(list, area, &mut app.list_state);
}

fn render_chat(frame: &mut Frame, app: &App, conversation: &Conversation, area: Rect) {
    let [info_area, messages_area, input_area] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
        .areas(area);

    // Kopf: mit wem, Fingerprint, Zustand der Verschlüsselung
    let state = if !conversation.online {
        "offline".red()
    } else if conversation.session.is_established() {
        "end-to-end encrypted".green()
    } else if conversation.session.is_pending() {
        "exchanging keys ...".yellow()
    } else {
        "encryption starts with the first message".dark_gray()
    };

    let info = Paragraph::new(vec![
        Line::from(vec![
            "Fingerprint: ".dark_gray(),
            fingerprint(&conversation.public_key).into(),
        ]),
        Line::from(vec!["Status:      ".dark_gray(), state]),
        Line::from(vec!["Key:         ".dark_gray(), trust_label(&conversation.trust)]),
    ])
        .block(Block::bordered().title(format!(" Chat with {} ", conversation.nickname).bold()));

    frame.render_widget(info, info_area);

    // Verlauf, immer bis ganz unten gescrollt
    let lines: Vec<Line> = conversation
        .lines
        .iter()
        .map(|line| {
            let time = format!("{} ", line.time).dark_gray();

            match line.kind {
                LineKind::Own => Line::from(vec![
                    time,
                    "you: ".cyan().bold(),
                    line.text.clone().into(),
                ]),
                LineKind::Peer => Line::from(vec![
                    time,
                    format!("{}: ", conversation.nickname).magenta().bold(),
                    line.text.clone().into(),
                ]),
                LineKind::System => Line::from(vec![
                    time,
                    format!("— {}", line.text).dark_gray().italic(),
                ]),
            }
        })
        .collect();

    let inner = messages_area.inner(Margin::new(1, 1));
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });

    let scroll = paragraph
        .line_count(inner.width)
        .saturating_sub(inner.height as usize);

    frame.render_widget(
        paragraph
            .block(Block::bordered())
            .scroll((scroll.min(u16::MAX as usize) as u16, 0)),
        messages_area,
    );

    // Eingabezeile
    let input_title = if conversation.online {
        " Message "
    } else {
        " Offline, cannot send "
    };

    let width = input_area.width.saturating_sub(2) as usize;
    let input_length = app.input.chars().count();

    // Bei langen Eingaben nur das Ende anzeigen
    let visible: String = app
        .input
        .chars()
        .skip(input_length.saturating_sub(width.saturating_sub(1)))
        .collect();

    let cursor_x = input_area.x + 1 + visible.chars().count() as u16;

    // Zeichenzähler rechts oben, gelb ab 900, rot am Limit
    let counter = format!(" {input_length}/{MAX_INPUT_LENGTH} ");

    let counter = if input_length >= MAX_INPUT_LENGTH {
        counter.red().bold()
    } else if input_length >= MAX_INPUT_LENGTH * 9 / 10 {
        counter.yellow()
    } else {
        counter.dark_gray()
    };

    let input_block = Block::bordered()
        .title(input_title)
        .title_top(Line::from(counter).right_aligned());

    frame.render_widget(Paragraph::new(visible).block(input_block), input_area);

    frame.set_cursor_position((cursor_x, input_area.y + 1));
}

// Ob der Schlüssel zu dem passt, was wir uns beim ersten Chat gemerkt haben
fn trust_label(trust: &PeerTrust) -> Span<'static> {
    match trust {
        PeerTrust::New => "new contact · compare the fingerprint to be sure".dark_gray(),
        PeerTrust::Known => "same key as in earlier chats".green(),
        PeerTrust::KeyChanged => "⚠ KEY CHANGED · possible attack, sending blocked".red().bold(),
        PeerTrust::NicknameChanged { previous } => {
            format!("⚠ this key was known as '{previous}' · sending blocked").red().bold()
        }
    }
}

// Kurzform des Public Keys für die Liste, z. B. "3f9a1c2e…b21e"
fn short_key(public_key: &str) -> String {
    if public_key.len() <= 12 {
        return public_key.to_string();
    }

    format!(
        "{}…{}",
        &public_key[..8],
        &public_key[public_key.len() - 4..]
    )
}

// Voller Public Key in Vierergruppen, zum Vergleichen über einen anderen Weg
fn fingerprint(public_key: &str) -> String {
    public_key
        .to_uppercase()
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}
