//! Decompile diff view rendering.

use azoth_analysis::decompile_diff::{StructureKind, StructuredDiffItem};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, DiffState};

/// Render the diff section list.
pub(super) fn render_diff_list(f: &mut Frame<'_>, area: Rect, app: &mut App) {
    app.list_area = area;

    let items: Vec<ListItem<'_>> = match &app.diff_state {
        DiffState::Unavailable => {
            vec![ListItem::new(Line::from(Span::styled(
                "No bytecode snapshots available",
                Style::default().fg(Color::DarkGray),
            )))]
        }
        DiffState::Pending(_) => {
            vec![ListItem::new(Line::from(Span::styled(
                "Press Tab to compute diff...",
                Style::default().fg(Color::Yellow),
            )))]
        }
        DiffState::Computing => {
            vec![ListItem::new(Line::from(Span::styled(
                "Computing decompile diff...",
                Style::default().fg(Color::Cyan),
            )))]
        }
        DiffState::Failed(err) => {
            vec![ListItem::new(Line::from(Span::styled(
                format!("Diff failed: {err}"),
                Style::default().fg(Color::Red),
            )))]
        }
        DiffState::Ready(diff) => diff
            .items
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                let (icon, name) = format_diff_item_name(item);
                let has_changes = item.has_changes();

                // Build styled line
                let style = if idx == app.diff_selected {
                    Style::default()
                        .bg(Color::Blue)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else if !has_changes {
                    Style::default().fg(Color::DarkGray)
                } else {
                    Style::default()
                };

                let change_indicator = if has_changes {
                    Span::styled(
                        format!(
                            " (+{}/-{})",
                            item.diff.stats.lines_added, item.diff.stats.lines_removed
                        ),
                        Style::default().fg(if idx == app.diff_selected {
                            Color::Yellow
                        } else {
                            Color::Cyan
                        }),
                    )
                } else {
                    Span::styled(" (no changes)", Style::default().fg(Color::DarkGray))
                };

                ListItem::new(Line::from(vec![
                    Span::styled(icon, style),
                    Span::styled(name, style),
                    change_indicator,
                ]))
            })
            .collect(),
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Sections ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .highlight_style(Style::default().bg(Color::Blue));

    f.render_stateful_widget(list, area, &mut app.diff_list_state);
}

/// Render the diff detail view.
pub(super) fn render_diff_detail(f: &mut Frame<'_>, area: Rect, app: &mut App) {
    app.detail_area = area;

    let lines = match &app.diff_state {
        DiffState::Unavailable => {
            vec![Line::from(Span::styled(
                "No bytecode snapshots available in trace",
                Style::default().fg(Color::DarkGray),
            ))]
        }
        DiffState::Pending(_) => {
            vec![
                Line::from(Span::styled(
                    "Decompile diff not yet computed",
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Press Tab to compute the diff analysis.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "This will decompile both original and obfuscated bytecode.",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        }
        DiffState::Computing => {
            vec![
                Line::from(Span::styled(
                    "Computing decompile diff...",
                    Style::default().fg(Color::Cyan),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Decompiling bytecode with Heimdall...",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        }
        DiffState::Failed(err) => {
            vec![
                Line::from(Span::styled(
                    "Decompile diff failed",
                    Style::default().fg(Color::Red),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!("Error: {err}"),
                    Style::default().fg(Color::Red),
                )),
            ]
        }
        DiffState::Ready(diff) => {
            if let Some(item) = diff.items.get(app.diff_selected) {
                format_diff_detail(item)
            } else {
                vec![Line::from(Span::styled(
                    "No item selected",
                    Style::default().fg(Color::DarkGray),
                ))]
            }
        }
    };

    app.detail_content_height = lines.len() as u16;

    let title = build_diff_title(app);

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .scroll((app.diff_detail_scroll, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

/// Format a diff item name for list display.
fn format_diff_item_name(item: &StructuredDiffItem) -> (&'static str, String) {
    match &item.kind {
        StructureKind::Header => ("\u{f0219} ", "Header".to_string()),
        StructureKind::Storage => ("\u{f01bc} ", "Storage".to_string()),
        StructureKind::Function {
            name,
            original_selector,
            obfuscated_selector,
        } => (
            "\u{f0295} ",
            if original_selector == obfuscated_selector {
                format!("{name} (0x{original_selector:08x})")
            } else {
                format!("{name} (0x{original_selector:08x} \u{2192} 0x{obfuscated_selector:08x})")
            },
        ),
        StructureKind::UnmatchedOriginal { name, selector } => {
            ("\u{f0156} ", format!("{name} (0x{selector:08x}) [removed]"))
        }
        StructureKind::UnmatchedObfuscated { name, selector } => {
            ("\u{f0415} ", format!("{name} (0x{selector:08x}) [added]"))
        }
    }
}

/// Build the title for the diff detail panel.
fn build_diff_title(app: &App) -> Line<'static> {
    let mut spans = Vec::new();
    spans.push(Span::raw(" "));

    match &app.diff_state {
        DiffState::Computing => {
            spans.push(Span::styled(
                "Computing...",
                Style::default().fg(Color::Cyan),
            ));
        }
        DiffState::Failed(_) => {
            spans.push(Span::styled("Error", Style::default().fg(Color::Red)));
        }
        DiffState::Ready(diff) => {
            if let Some(item) = diff.items.get(app.diff_selected) {
                let (icon, name) = format_diff_item_name(item);
                spans.push(Span::styled(
                    format!("{icon}{name}"),
                    Style::default().add_modifier(Modifier::BOLD),
                ));

                // Add stats
                let stats = &item.diff.stats;
                spans.push(Span::styled(
                    format!(
                        " - {} hunks, +{} -{} lines",
                        stats.hunk_count, stats.lines_added, stats.lines_removed
                    ),
                    Style::default().fg(Color::DarkGray),
                ));
            }
        }
        _ => {
            spans.push(Span::styled(
                "Decompile Diff",
                Style::default().fg(Color::DarkGray),
            ));
        }
    }

    spans.push(Span::raw(" "));
    Line::from(spans)
}

/// Format the diff detail content as colored lines.
fn format_diff_detail(item: &StructuredDiffItem) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Show structure kind header
    lines.push(Line::from(vec![
        Span::styled("Structure: ", Style::default().fg(Color::Cyan)),
        Span::styled(
            item.kind.to_string(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(""));

    // Stats summary
    let stats = &item.diff.stats;
    lines.push(Line::from(vec![
        Span::styled("Changes: ", Style::default().fg(Color::Cyan)),
        Span::styled(
            format!("{} hunks", stats.hunk_count),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("+{}", stats.lines_added),
            Style::default().fg(Color::Green),
        ),
        Span::styled(" / ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("-{}", stats.lines_removed),
            Style::default().fg(Color::Red),
        ),
        Span::styled(
            format!(" ({} unchanged)", stats.lines_unchanged),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    lines.push(Line::from(""));

    // If no changes, show a message
    if !item.has_changes() {
        lines.push(Line::from(Span::styled(
            "No changes in this section",
            Style::default().fg(Color::DarkGray),
        )));
        return lines;
    }

    // Show the unified diff with colors
    lines.push(Line::from(Span::styled(
        "\u{2500}\u{2500}\u{2500} Unified Diff \u{2500}\u{2500}\u{2500}",
        Style::default().fg(Color::Cyan),
    )));
    lines.push(Line::from(""));

    // Parse and colorize the unified diff
    for line in item.diff.unified_diff.lines() {
        let styled_line = if line.starts_with("@@") {
            Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::Cyan),
            ))
        } else if line.starts_with('+') {
            Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::Green),
            ))
        } else if line.starts_with('-') {
            Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::Red),
            ))
        } else {
            Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::DarkGray),
            ))
        };
        lines.push(styled_line);
    }

    lines
}
