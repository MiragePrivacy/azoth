//! Detail panel rendering for the TUI application.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::data::ListEntry;
use crate::format::format_operation_kind_full;

/// Render the detail panel showing information about the selected item.
pub fn render_detail(f: &mut Frame<'_>, area: Rect, app: &mut App) {
    // Store area for mouse scrolling
    app.detail_area = area;

    // Look up pre-computed detail lines from the cache
    let lines: &[Line<'static>] = match app.current_entry() {
        Some(ListEntry::GroupHeader { group_idx, .. }) => app
            .detail_cache
            .group_details
            .get(*group_idx)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        Some(ListEntry::Operation { trace_idx, .. })
        | Some(ListEntry::EdgeOperation { trace_idx, .. })
        | Some(ListEntry::SymbolicOperation { trace_idx, .. }) => app
            .detail_cache
            .trace_details
            .get(*trace_idx)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        Some(ListEntry::EdgeGroup { key, .. }) => app
            .detail_cache
            .edge_group_details
            .get(key)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        Some(ListEntry::SymbolicGroup { key, .. }) => app
            .detail_cache
            .symbolic_group_details
            .get(key)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        None => &[],
    };

    // Track content height for scroll bounds
    app.detail_content_height = lines.len() as u16;

    // Build breadcrumb title based on current selection
    let title = build_breadcrumb_title(app);

    let paragraph = Paragraph::new(lines.to_vec())
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .scroll((app.detail_scroll, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

/// Build breadcrumb title for the detail panel based on current selection.
///
/// Format: " Group -> SubGroup (x/n) -> Operation "
fn build_breadcrumb_title(app: &App) -> Line<'static> {
    let mut spans = Vec::new();
    spans.push(Span::raw(" "));

    match app.current_entry() {
        Some(ListEntry::GroupHeader { name, op_count, .. }) => {
            // Group name with count
            spans.push(Span::styled(
                format!("{name} ({op_count})"),
                Style::default().add_modifier(Modifier::BOLD),
            ));
        }
        Some(ListEntry::Operation {
            trace_idx,
            group_idx,
        }) => {
            // Group (x/n) -> OperationName
            if let Some(group) = app.groups.get(*group_idx) {
                // Find position within group
                let pos = group
                    .event_indices
                    .iter()
                    .position(|&i| i == *trace_idx)
                    .map(|p| p + 1)
                    .unwrap_or(0);
                let total = group.event_indices.len();

                spans.push(Span::styled(
                    format!("{} ({pos}/{total})", group.name),
                    Style::default().fg(Color::DarkGray),
                ));
                spans.push(Span::styled(" → ", Style::default().fg(Color::DarkGray)));

                // Get operation name from the trace event
                let op_name = app
                    .debug
                    .trace
                    .get(*trace_idx)
                    .map(|e| format_operation_kind_full(&e.kind))
                    .unwrap_or_else(|| "Unknown".to_string());

                spans.push(Span::styled(
                    op_name,
                    Style::default().add_modifier(Modifier::BOLD),
                ));
            }
        }
        Some(ListEntry::EdgeGroup {
            trace_indices,
            group_idx,
            ..
        }) => {
            // Group -> Edges (n)
            if let Some(group) = app.groups.get(*group_idx) {
                spans.push(Span::styled(
                    group.name.clone(),
                    Style::default().fg(Color::DarkGray),
                ));
                spans.push(Span::styled(" → ", Style::default().fg(Color::DarkGray)));
                spans.push(Span::styled(
                    format!("Edges ({})", trace_indices.len()),
                    Style::default().add_modifier(Modifier::BOLD),
                ));
            }
        }
        Some(ListEntry::EdgeOperation {
            trace_idx,
            group_idx,
        }) => {
            // Group (x/n) -> Edges (x/n) -> OperationName
            if let Some(group) = app.groups.get(*group_idx) {
                // Find position within group
                let group_pos = group
                    .event_indices
                    .iter()
                    .position(|&i| i == *trace_idx)
                    .map(|p| p + 1)
                    .unwrap_or(0);
                let group_total = group.event_indices.len();

                spans.push(Span::styled(
                    format!("{} ({group_pos}/{group_total})", group.name),
                    Style::default().fg(Color::DarkGray),
                ));
                spans.push(Span::styled(" → ", Style::default().fg(Color::DarkGray)));

                // Find the edge group this belongs to and position within it
                let (edge_count, edge_pos) = find_edge_group_position(app, *group_idx, *trace_idx);
                spans.push(Span::styled(
                    format!("Edges ({edge_pos}/{edge_count})"),
                    Style::default().fg(Color::DarkGray),
                ));
                spans.push(Span::styled(" → ", Style::default().fg(Color::DarkGray)));

                // Get operation name from the trace event
                let op_name = app
                    .debug
                    .trace
                    .get(*trace_idx)
                    .map(|e| format_operation_kind_full(&e.kind))
                    .unwrap_or_else(|| "Unknown".to_string());

                spans.push(Span::styled(
                    op_name,
                    Style::default().add_modifier(Modifier::BOLD),
                ));
            }
        }
        Some(ListEntry::SymbolicGroup {
            trace_indices,
            group_idx,
            ..
        }) => {
            // Group -> Symbolic (n)
            if let Some(group) = app.groups.get(*group_idx) {
                spans.push(Span::styled(
                    group.name.clone(),
                    Style::default().fg(Color::DarkGray),
                ));
                spans.push(Span::styled(" → ", Style::default().fg(Color::DarkGray)));
                spans.push(Span::styled(
                    format!("Symbolic ({})", trace_indices.len()),
                    Style::default().add_modifier(Modifier::BOLD),
                ));
            }
        }
        Some(ListEntry::SymbolicOperation {
            trace_idx,
            group_idx,
        }) => {
            // Group (x/n) -> Symbolic (x/n) -> OperationName
            if let Some(group) = app.groups.get(*group_idx) {
                // Find position within group
                let group_pos = group
                    .event_indices
                    .iter()
                    .position(|&i| i == *trace_idx)
                    .map(|p| p + 1)
                    .unwrap_or(0);
                let group_total = group.event_indices.len();

                spans.push(Span::styled(
                    format!("{} ({group_pos}/{group_total})", group.name),
                    Style::default().fg(Color::DarkGray),
                ));
                spans.push(Span::styled(" → ", Style::default().fg(Color::DarkGray)));

                // Find the symbolic group this belongs to and position within it
                let (sym_count, sym_pos) =
                    find_symbolic_group_position(app, *group_idx, *trace_idx);
                spans.push(Span::styled(
                    format!("Symbolic ({sym_pos}/{sym_count})"),
                    Style::default().fg(Color::DarkGray),
                ));
                spans.push(Span::styled(" → ", Style::default().fg(Color::DarkGray)));

                // Get operation name from the trace event
                let op_name = app
                    .debug
                    .trace
                    .get(*trace_idx)
                    .map(|e| format_operation_kind_full(&e.kind))
                    .unwrap_or_else(|| "Unknown".to_string());

                spans.push(Span::styled(
                    op_name,
                    Style::default().add_modifier(Modifier::BOLD),
                ));
            }
        }
        None => {
            spans.push(Span::styled(
                "No selection",
                Style::default().fg(Color::DarkGray),
            ));
        }
    }

    spans.push(Span::raw(" "));
    Line::from(spans)
}

/// Find position of an edge operation within its edge group.
fn find_edge_group_position(app: &App, group_idx: usize, trace_idx: usize) -> (usize, usize) {
    // Look through visible entries to find the EdgeGroup containing this trace_idx
    for entry in &app.visible_entries {
        if let ListEntry::EdgeGroup {
            trace_indices,
            group_idx: g_idx,
            ..
        } = entry
        {
            if *g_idx == group_idx && trace_indices.contains(&trace_idx) {
                let pos = trace_indices
                    .iter()
                    .position(|&i| i == trace_idx)
                    .map(|p| p + 1)
                    .unwrap_or(0);
                return (trace_indices.len(), pos);
            }
        }
    }
    (0, 0)
}

/// Find position of a symbolic operation within its symbolic group.
fn find_symbolic_group_position(app: &App, group_idx: usize, trace_idx: usize) -> (usize, usize) {
    // Look through visible entries to find the SymbolicGroup containing this trace_idx
    for entry in &app.visible_entries {
        if let ListEntry::SymbolicGroup {
            trace_indices,
            group_idx: g_idx,
            ..
        } = entry
        {
            if *g_idx == group_idx && trace_indices.contains(&trace_idx) {
                let pos = trace_indices
                    .iter()
                    .position(|&i| i == trace_idx)
                    .map(|p| p + 1)
                    .unwrap_or(0);
                return (trace_indices.len(), pos);
            }
        }
    }
    (0, 0)
}
