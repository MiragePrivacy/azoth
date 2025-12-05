//! Header rendering for the TUI application.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

/// Render the header bar with logo and keyboard shortcuts.
pub fn render_header(f: &mut Frame<'_>, area: Rect) {
    // Calculate the minimum width needed for shortcuts
    let shortcuts_text = "j/k Navigate  Space Expand  J/K Scroll  q Quit";
    let shortcuts_len = shortcuts_text.len() as u16;

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(10), Constraint::Length(shortcuts_len)])
        .split(area);

    let logo = Paragraph::new(Line::from(Span::styled(
        " \u{f0668} Azoth ",
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));

    let shortcuts = Line::from(vec![
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::styled(" Navigate  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Space", Style::default().fg(Color::Yellow)),
        Span::styled(" Expand  ", Style::default().fg(Color::DarkGray)),
        Span::styled("J/K", Style::default().fg(Color::Yellow)),
        Span::styled(" Scroll  ", Style::default().fg(Color::DarkGray)),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::styled(" Quit", Style::default().fg(Color::DarkGray)),
    ]);

    let shortcuts_widget = Paragraph::new(shortcuts).alignment(ratatui::layout::Alignment::Right);

    f.render_widget(logo, chunks[0]);
    f.render_widget(shortcuts_widget, chunks[1]);
}
