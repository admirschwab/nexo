use super::app::{App, Conversation, LineKind, MAX_INPUT_LENGTH};
use crate::models::protocol::CLIENT_VERSION;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;
use ratatui::{
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, List, ListItem, Padding, Paragraph},
    Frame,
};

// Ist weniger Platz für den Text, werden umbrochene Zeilen nicht eingerückt
const MIN_TEXT_WIDTH: usize = 10;

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
            "Enter send · Esc back to list · Ctrl+C quit"
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
        .block(Block::bordered().title(format!(" Nexo {CLIENT_VERSION} ").bold()));

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

            if !conversation.online {
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

    // Kopf: mit wem, Sicherheitsnummer, Zustand der Verschlüsselung
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
        // 12 Blöcke, auf zwei Zeilen verteilt
        Line::from(vec![
            "Safety number: ".dark_gray(),
            conversation.safety_number[..35].to_string().into(),
        ]),
        Line::from(vec![
            "               ".into(),
            conversation.safety_number[36..].to_string().into(),
            "   compare by phone or in person".dark_gray(),
        ]),
        Line::from(vec!["Status:        ".dark_gray(), state]),
    ])
        .block(Block::bordered().title(format!(" Chat with {} ", conversation.nickname).bold()));

    frame.render_widget(info, info_area);

    // Verlauf, immer bis ganz unten gescrollt
    let inner = messages_area.inner(Margin::new(1, 1));
    let lines = history_lines(conversation, inner.width as usize);
    let scroll = lines.len().saturating_sub(inner.height as usize);

    frame.render_widget(
        Paragraph::new(lines)
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

    let input_length = app.input.chars().count();

    // Bei langen Eingaben nur das Ende anzeigen (ausgeliehen, nicht kopiert).
    // Gerechnet wird mit der Breite auf dem Bildschirm: Emojis und viele
    // asiatische Schriftzeichen belegen zwei Spalten. Abzüglich Rahmen und Einrückung
    // bleibt eine Spalte für den Cursor frei.
    let available = input_area.width.saturating_sub(4) as usize;
    let mut visible_start = app.input.len();
    let mut visible_width = 0;

    for (start, grapheme) in app.input.grapheme_indices(true).rev() {
        let grapheme_width = grapheme.width();

        if visible_width + grapheme_width > available {
            break;
        }

        visible_width += grapheme_width;
        visible_start = start;
    }

    let visible = &app.input[visible_start..];
    // Rahmen + eine Spalte Einrückung: Der Text beginnt unter dem "M" von " Message "
    let cursor_x = input_area.x + 2 + visible_width as u16;

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
        .padding(Padding::left(1))
        .title(input_title)
        .title_top(Line::from(counter).right_aligned());

    frame.render_widget(Paragraph::new(visible).block(input_block), input_area);

    frame.set_cursor_position((cursor_x, input_area.y + 1));
}

// Zeilen des Verlaufs, selbst umbrochen: Folgezeilen beginnen unter dem Anfang
// des Textes, nicht unter der Uhrzeit. Der Text wird nur ausgeliehen, damit keine
// Kopien der Nachrichten im Speicher zurückbleiben.
fn history_lines<'a>(conversation: &'a Conversation, width: usize) -> Vec<Line<'a>> {
    let mut lines = Vec::new();

    for line in &conversation.lines {
        let time = format!("{} ", line.time).dark_gray();

        let (label, style) = match line.kind {
            LineKind::Own => ("you: ".cyan().bold(), Style::new()),
            LineKind::Peer => (
                format!("{}: ", conversation.nickname).magenta().bold(),
                Style::new(),
            ),
            LineKind::System => ("— ".dark_gray().italic(), Style::new().dark_gray().italic()),
        };

        let prefix_width = time.width() + label.width();

        let indent = if width >= prefix_width + MIN_TEXT_WIDTH {
            prefix_width
        } else {
            0
        };

        let mut parts = wrap(&line.text, width.saturating_sub(prefix_width), width - indent).into_iter();

        let first = parts.next().unwrap_or_default();
        lines.push(Line::from(vec![time, label, Span::styled(first, style)]));

        for part in parts {
            lines.push(Line::from(vec![
                Span::raw(" ".repeat(indent)),
                Span::styled(part, style),
            ]));
        }
    }

    lines
}

// Bricht den Text an Leerzeichen um. Die erste Zeile hat `first_width` Spalten,
// alle weiteren `rest_width`. Wörter, die länger als eine Zeile sind, werden
// zwischen zwei Zeichen getrennt (nie mitten in einem Emoji).
fn wrap(text: &str, first_width: usize, rest_width: usize) -> Vec<&str> {
    let mut lines = Vec::new();
    // Beginn und Breite der aktuellen Zeile
    let mut start = 0;
    let mut width = 0;
    let mut limit = first_width.max(1);
    let mut offset = 0;

    for word in text.split_inclusive(' ') {
        // Leerzeichen am Ende dürfen über den Rand hinausgehen
        if width > 0 && width + word.trim_end().width() > limit {
            lines.push(text[start..offset].trim_end());
            start = offset;
            width = 0;
            limit = rest_width.max(1);
        }

        for (index, grapheme) in word.grapheme_indices(true) {
            let grapheme_width = grapheme.width();

            if width > 0 && width + grapheme_width > limit && grapheme != " " {
                lines.push(&text[start..offset + index]);
                start = offset + index;
                width = 0;
                limit = rest_width.max(1);
            }

            width += grapheme_width;
        }

        offset += word.len();
    }

    lines.push(text[start..].trim_end());

    lines
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

