//! Header rendering for the TUI application.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;
use crate::data::ViewMode;

/// Render the header bar with logo, view mode indicator, filename, and keyboard shortcuts.
pub fn render_header(f: &mut Frame<'_>, area: Rect, app: &App) {
    // Build shortcuts based on view mode
    let shortcuts = build_shortcuts(app);
    let shortcuts_len = shortcuts.iter().map(|s| s.width()).sum::<usize>() as u16;

    // Build view mode indicator
    let view_indicator = build_view_indicator(app);
    let view_len = view_indicator.iter().map(|s| s.width()).sum::<usize>() as u16;

    // Build filename display
    let filename_spans = build_filename_spans(app);
    let filename_len = filename_spans.iter().map(|s| s.width()).sum::<usize>() as u16;

    // Logo width (including padding)
    let logo_len: u16 = 10;

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(logo_len),
            Constraint::Length(view_len + 1),
            Constraint::Length(filename_len + 1),
            Constraint::Min(1),
            Constraint::Length(shortcuts_len),
        ])
        .split(area);

    let logo = Paragraph::new(Line::from(Span::styled(
        " \u{f0668} Azoth ",
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));

    let view_widget = Paragraph::new(Line::from(view_indicator));

    let filename_widget = Paragraph::new(Line::from(filename_spans));

    let shortcuts_widget =
        Paragraph::new(Line::from(shortcuts)).alignment(ratatui::layout::Alignment::Right);

    f.render_widget(logo, chunks[0]);
    f.render_widget(view_widget, chunks[1]);
    f.render_widget(filename_widget, chunks[2]);
    // chunks[3] is spacer
    f.render_widget(shortcuts_widget, chunks[4]);
}

/// Build the view mode indicator spans.
fn build_view_indicator(app: &App) -> Vec<Span<'static>> {
    let has_diff = app.has_diff();
    let mut spans = Vec::new();

    // Trace indicator
    let trace_style = if app.view_mode == ViewMode::Trace {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Magenta)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    spans.push(Span::styled(" Trace ", trace_style));

    // Separator
    spans.push(Span::styled(" | ", Style::default().fg(Color::DarkGray)));

    // Diff indicator (grayed out if not available)
    let diff_style = if !has_diff {
        Style::default().fg(Color::DarkGray)
    } else if app.view_mode == ViewMode::DecompileDiff {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    spans.push(Span::styled(" Diff ", diff_style));

    spans
}

/// Build filename display spans.
fn build_filename_spans(app: &App) -> Vec<Span<'static>> {
    match &app.filename {
        Some(name) => vec![Span::styled(name.clone(), Style::default().fg(Color::DarkGray))],
        None => Vec::new(),
    }
}

/// Build keyboard shortcuts based on view mode.
fn build_shortcuts(app: &App) -> Vec<Span<'static>> {
    let mut spans = vec![
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::styled(" Nav  ", Style::default().fg(Color::DarkGray)),
    ];

    // View-specific shortcuts
    match app.view_mode {
        ViewMode::Trace => {
            spans.push(Span::styled("Space", Style::default().fg(Color::Yellow)));
            spans.push(Span::styled(" Expand  ", Style::default().fg(Color::DarkGray)));
        }
        ViewMode::DecompileDiff => {
            // No expand in diff view, but keep similar layout
        }
    }

    spans.push(Span::styled("J/K", Style::default().fg(Color::Yellow)));
    spans.push(Span::styled(" Scroll  ", Style::default().fg(Color::DarkGray)));

    // Tab hint if diff is available
    if app.has_diff() {
        spans.push(Span::styled("Tab", Style::default().fg(Color::Yellow)));
        spans.push(Span::styled(" Switch  ", Style::default().fg(Color::DarkGray)));
    }

    spans.push(Span::styled("q", Style::default().fg(Color::Yellow)));
    spans.push(Span::styled(" Quit", Style::default().fg(Color::DarkGray)));

    spans
}
