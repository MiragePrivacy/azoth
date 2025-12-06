//! List panel rendering for the TUI application.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Frame;

use crate::app::App;
use crate::data::ListEntry;
use crate::format::{format_diff_summary, format_operation_kind_short};

/// Render the list panel showing transforms and operations.
pub fn render_list(f: &mut Frame<'_>, area: Rect, app: &mut App) {
    // Store area for mouse hit testing
    app.list_area = area;

    let items: Vec<ListItem<'_>> = app
        .visible_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let is_selected = i == app.selected;
            match entry {
                ListEntry::GroupHeader {
                    name,
                    op_count,
                    expanded,
                    ..
                } => {
                    let icon = if *expanded { "▼" } else { "▶" };
                    let style = if is_selected {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Cyan)
                    };
                    ListItem::new(format!("{icon} {name} ({op_count})")).style(style)
                }
                ListEntry::Operation { trace_idx, .. } => {
                    let event = &app.debug.trace[*trace_idx];
                    let kind_str = format_operation_kind_short(&event.kind);
                    let diff_str = format_diff_summary(&event.diff);
                    let style = if is_selected {
                        Style::default().add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Gray)
                    };
                    ListItem::new(format!("  {kind_str} {diff_str}")).style(style)
                }
                ListEntry::EdgeGroup {
                    trace_indices,
                    expanded,
                    ..
                } => {
                    let icon = if *expanded { "▼" } else { "▶" };
                    let style = if is_selected {
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Magenta)
                    };
                    ListItem::new(format!("  {icon} Edges ({})", trace_indices.len())).style(style)
                }
                ListEntry::EdgeOperation { trace_idx, .. }
                | ListEntry::SymbolicOperation { trace_idx, .. } => {
                    let event = &app.debug.trace[*trace_idx];
                    let kind_str = format_operation_kind_short(&event.kind);
                    let diff_str = format_diff_summary(&event.diff);
                    let style = if is_selected {
                        Style::default().add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Gray)
                    };
                    ListItem::new(format!("    {kind_str} {diff_str}")).style(style)
                }
                ListEntry::SymbolicGroup {
                    trace_indices,
                    expanded,
                    ..
                } => {
                    let icon = if *expanded { "▼" } else { "▶" };
                    let style = if is_selected {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Yellow)
                    };
                    ListItem::new(format!("  {icon} Symbolic ({})", trace_indices.len()))
                        .style(style)
                }
            }
        })
        .collect();

    let title_right = format!(
        " {} groups, {} events ",
        app.groups.len(),
        app.debug.trace.len()
    );
    let list = List::new(items)
        .block(
            Block::default()
                .title(" Transforms & Operations ")
                .title(Line::from(title_right).right_aligned())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, area, &mut app.list_state);
}
