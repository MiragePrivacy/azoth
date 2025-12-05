//! Azoth TUI - Debug trace viewer for obfuscation output.

use std::io;
use std::path::PathBuf;

use clap::Parser;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseButton,
        MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};

use azoth_core::cfg_ir::{
    BlockControlSnapshot, BlockModification, BlockSnapshotKind, CfgIrDiff, JumpEncoding,
    JumpTargetSnapshot, OperationKind, TraceEvent, TraceJumpTargetKind,
};
use serde::Deserialize;

/// Debug output format - subset of ObfuscationResult
#[derive(Debug, Deserialize)]
struct DebugOutput {
    #[allow(dead_code)]
    metadata: DebugMetadata,
    trace: Vec<TraceEvent>,
}

/// Metadata from obfuscation
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DebugMetadata {
    transforms_applied: Vec<String>,
    #[serde(default)]
    size_limit_exceeded: bool,
    #[serde(default)]
    unknown_opcodes_preserved: bool,
}

/// A displayable item in the list (either a group header or an operation).
#[derive(Debug, Clone)]
enum ListEntry {
    /// Transform group header
    GroupHeader {
        name: String,
        op_count: usize,
        expanded: bool,
        group_idx: usize,
    },
    /// Individual operation
    Operation {
        trace_idx: usize,
        #[allow(dead_code)]
        group_idx: usize,
    },
}

/// Azoth TUI - Debug trace viewer
#[derive(Parser, Debug)]
#[command(name = "azoth-tui")]
#[command(about = "View obfuscation debug traces")]
struct Args {
    /// Path to the debug JSON file
    #[arg(default_value = "debug.json")]
    file: PathBuf,
}

/// A group of trace events belonging to a transform phase.
struct TraceGroup {
    name: String,
    event_indices: Vec<usize>,
    expanded: bool,
}

/// Application state.
struct App {
    /// The loaded debug output
    debug: DebugOutput,
    /// Grouped trace events
    groups: Vec<TraceGroup>,
    /// Flattened list of visible entries
    visible_entries: Vec<ListEntry>,
    /// Selected index in visible_entries
    selected: usize,
    /// List state for navigation
    list_state: ListState,
    /// Scroll position within detail view
    detail_scroll: u16,
    /// Area of the list widget (for mouse hit testing)
    list_area: Rect,
    /// Area of the detail widget (for mouse scrolling)
    detail_area: Rect,
}

impl App {
    fn new(debug: DebugOutput) -> Self {
        let groups = build_trace_groups(&debug.trace);
        let visible_entries = build_visible_entries(&groups);
        let mut list_state = ListState::default();
        if !visible_entries.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            debug,
            groups,
            visible_entries,
            selected: 0,
            list_state,
            detail_scroll: 0,
            list_area: Rect::default(),
            detail_area: Rect::default(),
        }
    }

    fn rebuild_visible(&mut self) {
        self.visible_entries = build_visible_entries(&self.groups);
        // Clamp selection
        if self.selected >= self.visible_entries.len() {
            self.selected = self.visible_entries.len().saturating_sub(1);
        }
        self.list_state.select(Some(self.selected));
    }

    fn current_entry(&self) -> Option<&ListEntry> {
        self.visible_entries.get(self.selected)
    }

    #[allow(dead_code)]
    fn current_trace(&self) -> Option<&TraceEvent> {
        match self.current_entry()? {
            ListEntry::Operation { trace_idx, .. } => self.debug.trace.get(*trace_idx),
            ListEntry::GroupHeader { .. } => None,
        }
    }

    fn select_next(&mut self) {
        if self.selected < self.visible_entries.len().saturating_sub(1) {
            self.selected += 1;
            self.list_state.select(Some(self.selected));
            self.detail_scroll = 0;
        }
    }

    fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            self.list_state.select(Some(self.selected));
            self.detail_scroll = 0;
        }
    }

    fn toggle_expand(&mut self) {
        if let Some(ListEntry::GroupHeader { group_idx, .. }) = self.current_entry().cloned() {
            if let Some(group) = self.groups.get_mut(group_idx) {
                group.expanded = !group.expanded;
                self.rebuild_visible();
            }
        }
    }

    const fn scroll_down(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_add(1);
    }

    const fn scroll_up(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_sub(1);
    }
}

/// Build trace groups from TransformStart/TransformEnd markers
fn build_trace_groups(trace: &[TraceEvent]) -> Vec<TraceGroup> {
    let mut groups = Vec::new();
    let mut current_group: Option<TraceGroup> = None;
    let mut pending_events = Vec::new();
    let mut pending_name = "Setup".to_string();

    for (i, event) in trace.iter().enumerate() {
        match &event.kind {
            OperationKind::TransformStart { name } => {
                // Push any accumulated pending events as their own group
                if !pending_events.is_empty() {
                    groups.push(TraceGroup {
                        name: std::mem::take(&mut pending_name),
                        event_indices: std::mem::take(&mut pending_events),
                        expanded: true,
                    });
                }
                // Start new transform group
                current_group = Some(TraceGroup {
                    name: name.clone(),
                    event_indices: Vec::new(),
                    expanded: true,
                });
            }
            OperationKind::TransformEnd { .. } => {
                // Close current group
                if let Some(group) = current_group.take() {
                    groups.push(group);
                }
            }
            OperationKind::FinalizeStart => {
                // Push any accumulated pending events as their own group
                if !pending_events.is_empty() {
                    groups.push(TraceGroup {
                        name: std::mem::take(&mut pending_name),
                        event_indices: std::mem::take(&mut pending_events),
                        expanded: true,
                    });
                }
                // Start Finalize group
                current_group = Some(TraceGroup {
                    name: "Finalize".to_string(),
                    event_indices: Vec::new(),
                    expanded: true,
                });
            }
            OperationKind::Finalize => {
                // Add to current group (should be Finalize)
                if let Some(ref mut group) = current_group {
                    group.event_indices.push(i);
                } else {
                    pending_events.push(i);
                }
            }
            _ => {
                // Add to current transform group or pending
                if let Some(ref mut group) = current_group {
                    group.event_indices.push(i);
                } else {
                    pending_events.push(i);
                }
            }
        }
    }

    // Handle remaining pending events
    if !pending_events.is_empty() {
        if groups.is_empty() {
            groups.push(TraceGroup {
                name: "All Operations".to_string(),
                event_indices: pending_events,
                expanded: true,
            });
        } else {
            groups.push(TraceGroup {
                name: pending_name,
                event_indices: pending_events,
                expanded: true,
            });
        }
    }

    // Handle any unclosed transform group
    if let Some(group) = current_group {
        groups.push(group);
    }

    groups
}

fn build_visible_entries(groups: &[TraceGroup]) -> Vec<ListEntry> {
    let mut entries = Vec::new();
    for (gi, group) in groups.iter().enumerate() {
        entries.push(ListEntry::GroupHeader {
            name: group.name.clone(),
            op_count: group.event_indices.len(),
            expanded: group.expanded,
            group_idx: gi,
        });
        if group.expanded {
            for &trace_idx in &group.event_indices {
                entries.push(ListEntry::Operation {
                    trace_idx,
                    group_idx: gi,
                });
            }
        }
    }
    entries
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Load the debug JSON
    let content = std::fs::read_to_string(&args.file)?;
    let debug: DebugOutput = serde_json::from_str(&content)?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run app
    let app = App::new(debug);
    let res = run_app(&mut terminal, app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Error: {err}");
    }

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        match event::read()? {
            Event::Key(key) => {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            return Ok(());
                        }
                        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
                        KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
                        KeyCode::Enter | KeyCode::Tab | KeyCode::Char(' ') => {
                            app.toggle_expand();
                        }
                        KeyCode::PageDown | KeyCode::Char('d') => {
                            for _ in 0..10 {
                                app.scroll_down();
                            }
                        }
                        KeyCode::PageUp | KeyCode::Char('u') => {
                            for _ in 0..10 {
                                app.scroll_up();
                            }
                        }
                        KeyCode::Char('J') => app.scroll_down(),
                        KeyCode::Char('K') => app.scroll_up(),
                        _ => {}
                    }
                }
            }
            Event::Mouse(mouse) => {
                let x = mouse.column;
                let y = mouse.row;

                match mouse.kind {
                    MouseEventKind::Down(MouseButton::Left) => {
                        // Check if click is in list area
                        if x >= app.list_area.x
                            && x < app.list_area.x + app.list_area.width
                            && y >= app.list_area.y
                            && y < app.list_area.y + app.list_area.height
                        {
                            // Calculate which item was clicked (accounting for border and scroll offset)
                            let relative_y = y.saturating_sub(app.list_area.y + 1);
                            let scroll_offset = app.list_state.offset();
                            let clicked_idx = relative_y as usize + scroll_offset;
                            if clicked_idx < app.visible_entries.len() {
                                if app.selected == clicked_idx {
                                    // Double-click effect: toggle expand
                                    app.toggle_expand();
                                } else {
                                    app.selected = clicked_idx;
                                    app.list_state.select(Some(clicked_idx));
                                    app.detail_scroll = 0;
                                }
                            }
                        }
                    }
                    MouseEventKind::ScrollUp => {
                        // Check if in detail area
                        if x >= app.detail_area.x
                            && x < app.detail_area.x + app.detail_area.width
                            && y >= app.detail_area.y
                            && y < app.detail_area.y + app.detail_area.height
                        {
                            app.scroll_up();
                        } else if x >= app.list_area.x
                            && x < app.list_area.x + app.list_area.width
                            && y >= app.list_area.y
                            && y < app.list_area.y + app.list_area.height
                        {
                            app.select_prev();
                        }
                    }
                    MouseEventKind::ScrollDown => {
                        // Check if in detail area
                        if x >= app.detail_area.x
                            && x < app.detail_area.x + app.detail_area.width
                            && y >= app.detail_area.y
                            && y < app.detail_area.y + app.detail_area.height
                        {
                            app.scroll_down();
                        } else if x >= app.list_area.x
                            && x < app.list_area.x + app.list_area.width
                            && y >= app.list_area.y
                            && y < app.list_area.y + app.list_area.height
                        {
                            app.select_next();
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

fn ui(f: &mut Frame<'_>, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Header
            Constraint::Min(0),    // Main content
        ])
        .split(f.area());

    render_header(f, chunks[0], app);
    render_main(f, chunks[1], app);
}

fn render_header(f: &mut Frame<'_>, area: Rect, _app: &App) {
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

fn render_main(f: &mut Frame<'_>, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    render_list(f, chunks[0], app);
    render_detail(f, chunks[1], app);
}

fn render_list(f: &mut Frame<'_>, area: Rect, app: &mut App) {
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

fn render_detail(f: &mut Frame<'_>, area: Rect, app: &mut App) {
    // Store area for mouse scrolling
    app.detail_area = area;

    let lines = match app.current_entry() {
        Some(ListEntry::GroupHeader { name, op_count, .. }) => {
            format_group_detail_lines(name, *op_count, &app.groups, &app.debug.trace)
        }
        Some(ListEntry::Operation { trace_idx, .. }) => {
            if let Some(event) = app.debug.trace.get(*trace_idx) {
                format_operation_detail_lines(event)
            } else {
                vec![Line::from("No event found")]
            }
        }
        None => vec![Line::from("No selection")],
    };

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Detail ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .scroll((app.detail_scroll, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

// === Formatting functions ===

fn format_operation_kind_short(kind: &OperationKind) -> String {
    match kind {
        OperationKind::TransformStart { name } => format!("▶ {name}"),
        OperationKind::TransformEnd { name } => format!("◀ {name}"),
        OperationKind::Build { body_blocks, .. } => format!("Build({body_blocks})"),
        OperationKind::OverwriteBlock { node } => format!("Overwrite({node})"),
        OperationKind::OverwriteBlocks { blocks_modified } => {
            format!("Overwrite({blocks_modified})")
        }
        OperationKind::SetUnconditionalJump { source, target } => {
            format!("Jump({source}->{target})")
        }
        OperationKind::SetConditionalJump { source, .. } => format!("Branch({source})"),
        OperationKind::RebuildEdges { node } => format!("Edges({node})"),
        OperationKind::WriteSymbolicImmediates { node } => format!("Symbolic({node})"),
        OperationKind::ReindexPcs => "ReindexPCs".to_string(),
        OperationKind::PatchJumpImmediates => "PatchJumps".to_string(),
        OperationKind::PatchDispatcher { blocks_modified } => {
            format!("PatchDispatcher({blocks_modified})")
        }
        OperationKind::ReplaceBody { instruction_count } => format!("Replace({instruction_count})"),
        OperationKind::FinalizeStart => "▶ Finalize".to_string(),
        OperationKind::Finalize => "Finalize".to_string(),
    }
}

fn format_diff_summary(diff: &CfgIrDiff) -> String {
    match diff {
        CfgIrDiff::None => String::new(),
        CfgIrDiff::BlockChanges(changes) => format!("[{}Δ]", changes.changes.len()),
        CfgIrDiff::EdgeChanges(changes) => {
            format!("[+{}-{}e]", changes.added.len(), changes.removed.len())
        }
        CfgIrDiff::PcsRemapped { blocks, .. } => format!("[{}remap]", blocks.len()),
        CfgIrDiff::FullSnapshot(snap) => format!("[{}blk]", snap.blocks.len()),
    }
}

fn format_group_detail_lines(
    name: &str,
    op_count: usize,
    groups: &[TraceGroup],
    trace: &[TraceEvent],
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        format!("═══ {name} ═══"),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(format!("Operations: {op_count}")));
    lines.push(Line::from(""));

    // Find this group and summarize its operations
    for group in groups {
        if group.name == name {
            // Count operation types
            let mut op_counts: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for &idx in &group.event_indices {
                if let Some(event) = trace.get(idx) {
                    let op_type = match &event.kind {
                        OperationKind::Build { .. } => "Build",
                        OperationKind::OverwriteBlock { .. } => "OverwriteBlock",
                        OperationKind::OverwriteBlocks { .. } => "OverwriteBlocks",
                        OperationKind::SetUnconditionalJump { .. } => "SetUnconditionalJump",
                        OperationKind::SetConditionalJump { .. } => "SetConditionalJump",
                        OperationKind::RebuildEdges { .. } => "RebuildEdges",
                        OperationKind::WriteSymbolicImmediates { .. } => "WriteSymbolicImmediates",
                        OperationKind::ReindexPcs => "ReindexPcs",
                        OperationKind::PatchJumpImmediates => "PatchJumpImmediates",
                        OperationKind::PatchDispatcher { .. } => "PatchDispatcher",
                        OperationKind::ReplaceBody { .. } => "ReplaceBody",
                        OperationKind::Finalize => "Finalize",
                        _ => "Other",
                    };
                    *op_counts.entry(op_type).or_insert(0) += 1;
                }
            }

            lines.push(Line::from(Span::styled(
                "Operation breakdown:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            let mut sorted: Vec<_> = op_counts.into_iter().collect();
            // Sort by count descending, then by name ascending for stable ordering
            sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
            for (op_type, count) in sorted {
                lines.push(Line::from(format!("  {op_type}: {count}")));
            }
            break;
        }
    }

    lines
}

fn format_operation_detail_lines(event: &TraceEvent) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Operation header
    lines.push(Line::from(Span::styled(
        format!("═══ {} ═══", format_operation_kind_full(&event.kind)),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    // Diff details
    match &event.diff {
        CfgIrDiff::None => {
            lines.push(Line::from(Span::styled(
                "No changes recorded",
                Style::default().fg(Color::DarkGray),
            )));
        }
        CfgIrDiff::BlockChanges(changes) => {
            lines.push(Line::from(format!(
                "Block Changes: {}",
                changes.changes.len()
            )));
            lines.push(Line::from(""));

            // Sort by node index for consistent display
            let mut sorted_changes: Vec<_> = changes.changes.iter().collect();
            sorted_changes.sort_by_key(|c| c.node);

            for change in sorted_changes {
                lines.push(Line::from(Span::styled(
                    format!("─── Block {} ───", change.node),
                    Style::default().fg(Color::Yellow),
                )));
                lines.push(Line::from(format!(
                    "Instructions: {} → {}",
                    change.before.instructions.len(),
                    change.after.instructions.len()
                )));
                lines.push(Line::from(""));

                // Inline diff with colors
                let diff_lines = format_instruction_diff_colored(change);
                lines.extend(diff_lines);
                lines.push(Line::from(""));

                // Control flow change
                if change.before.control != change.after.control {
                    lines.push(Line::from(Span::styled(
                        "Control flow:",
                        Style::default().add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::from(Span::styled(
                        format!("  - {}", format_control_flow(&change.before.control)),
                        Style::default().fg(Color::Red),
                    )));
                    lines.push(Line::from(Span::styled(
                        format!("  + {}", format_control_flow(&change.after.control)),
                        Style::default().fg(Color::Green),
                    )));
                }
                lines.push(Line::from(""));
            }
        }
        CfgIrDiff::EdgeChanges(changes) => {
            lines.push(Line::from(format!(
                "Edge Changes for node {}",
                changes.node
            )));
            if !changes.removed.is_empty() {
                lines.push(Line::from(format!(
                    "Removed edges: {}",
                    changes.removed.len()
                )));
                for edge in &changes.removed {
                    lines.push(Line::from(Span::styled(
                        format!("  - {edge:?}"),
                        Style::default().fg(Color::Red),
                    )));
                }
            }
            if !changes.added.is_empty() {
                lines.push(Line::from(format!("Added edges: {}", changes.added.len())));
                for edge in &changes.added {
                    lines.push(Line::from(Span::styled(
                        format!("  + {edge:?}"),
                        Style::default().fg(Color::Green),
                    )));
                }
            }
        }
        CfgIrDiff::PcsRemapped {
            blocks,
            instructions,
        } => {
            lines.push(Line::from(Span::styled(
                "PC Remapping:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!("  Blocks remapped: {}", blocks.len())));
            lines.push(Line::from(format!(
                "  Instructions remapped: {}",
                instructions.len()
            )));

            if !blocks.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from("Block PC changes:"));
                for diff in blocks.iter().take(20) {
                    lines.push(Line::from(format!(
                        "  Block {}: {} → {}",
                        diff.node, diff.old_start_pc, diff.new_start_pc
                    )));
                }
                if blocks.len() > 20 {
                    lines.push(Line::from(Span::styled(
                        format!("  ... and {} more", blocks.len() - 20),
                        Style::default().fg(Color::DarkGray),
                    )));
                }
            }
        }
        CfgIrDiff::FullSnapshot(snap) => {
            lines.push(Line::from(Span::styled(
                "Full Snapshot:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!("  Blocks: {}", snap.blocks.len())));
            lines.push(Line::from(format!("  Edges: {}", snap.edges.len())));
            lines.push(Line::from(format!("  Sections: {}", snap.sections.len())));
            if let Some((start, end)) = snap.runtime_bounds {
                lines.push(Line::from(format!("  Runtime bounds: {start} - {end}")));
            }
            lines.push(Line::from(""));

            // Show block summary
            lines.push(Line::from("Blocks:"));
            for block in snap.blocks.iter().take(30) {
                let block_info = match &block.kind {
                    BlockSnapshotKind::Entry => "Entry".to_string(),
                    BlockSnapshotKind::Exit => "Exit".to_string(),
                    BlockSnapshotKind::Body(body) => {
                        let ctrl = format_control_short(&body.control);
                        format!(
                            "PC:{} ({} instr) {}",
                            body.start_pc,
                            body.instructions.len(),
                            ctrl
                        )
                    }
                };
                lines.push(Line::from(format!("  [{}] {}", block.node, block_info)));
            }
            if snap.blocks.len() > 30 {
                lines.push(Line::from(Span::styled(
                    format!("  ... and {} more blocks", snap.blocks.len() - 30),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
    }

    lines
}

fn format_operation_kind_full(kind: &OperationKind) -> String {
    match kind {
        OperationKind::TransformStart { name } => format!("Transform Start: {name}"),
        OperationKind::TransformEnd { name } => format!("Transform End: {name}"),
        OperationKind::Build {
            body_blocks,
            sections,
        } => {
            format!("Build CFG ({body_blocks} blocks, {sections} sections)")
        }
        OperationKind::OverwriteBlock { node } => format!("Overwrite Block {node}"),
        OperationKind::OverwriteBlocks { blocks_modified } => {
            format!("Overwrite Blocks ({blocks_modified} blocks)")
        }
        OperationKind::SetUnconditionalJump { source, target } => {
            format!("Set Jump: {source} → {target}")
        }
        OperationKind::SetConditionalJump {
            source,
            true_target,
            false_target,
        } => {
            format!("Set Branch: {source} → T:{true_target} / F:{false_target:?}")
        }
        OperationKind::RebuildEdges { node } => format!("Rebuild Edges for {node}"),
        OperationKind::WriteSymbolicImmediates { node } => {
            format!("Write Symbolic Immediates for {node}")
        }
        OperationKind::ReindexPcs => "Reindex PCs".to_string(),
        OperationKind::PatchJumpImmediates => "Patch Jump Immediates".to_string(),
        OperationKind::PatchDispatcher { blocks_modified } => {
            format!("Patch Dispatcher ({blocks_modified} blocks)")
        }
        OperationKind::ReplaceBody { instruction_count } => {
            format!("Replace Body ({instruction_count} instructions)")
        }
        OperationKind::FinalizeStart => "Finalize Start".to_string(),
        OperationKind::Finalize => "Finalize".to_string(),
    }
}

fn format_instruction_diff_colored(change: &BlockModification) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    let before: Vec<_> = change
        .before
        .instructions
        .iter()
        .map(|i| {
            let imm = i.imm.as_deref().unwrap_or("");
            format!("{:?} {}", i.op, imm)
        })
        .collect();

    let after: Vec<_> = change
        .after
        .instructions
        .iter()
        .map(|i| {
            let imm = i.imm.as_deref().unwrap_or("");
            format!("{:?} {}", i.op, imm)
        })
        .collect();

    // Simple diff algorithm
    let mut bi = 0;
    let mut ai = 0;

    while bi < before.len() || ai < after.len() {
        if bi < before.len() && ai < after.len() && before[bi] == after[ai] {
            lines.push(Line::from(Span::styled(
                format!("   {}", before[bi]),
                Style::default().fg(Color::DarkGray),
            )));
            bi += 1;
            ai += 1;
        } else if bi < before.len() && ai < after.len() {
            // Look ahead for matches
            let after_match = after[ai..].iter().position(|x| x == &before[bi]);
            let before_match = before[bi..].iter().position(|x| x == &after[ai]);

            match (after_match, before_match) {
                (Some(am), None) if am > 0 => {
                    for j in 0..am {
                        lines.push(Line::from(Span::styled(
                            format!(" + {}", after[ai + j]),
                            Style::default().fg(Color::Green),
                        )));
                    }
                    ai += am;
                }
                (None, Some(bm)) if bm > 0 => {
                    for j in 0..bm {
                        lines.push(Line::from(Span::styled(
                            format!(" - {}", before[bi + j]),
                            Style::default().fg(Color::Red),
                        )));
                    }
                    bi += bm;
                }
                (Some(am), Some(bm)) if am > 0 || bm > 0 => {
                    if am <= bm {
                        for j in 0..am {
                            lines.push(Line::from(Span::styled(
                                format!(" + {}", after[ai + j]),
                                Style::default().fg(Color::Green),
                            )));
                        }
                        ai += am;
                    } else {
                        for j in 0..bm {
                            lines.push(Line::from(Span::styled(
                                format!(" - {}", before[bi + j]),
                                Style::default().fg(Color::Red),
                            )));
                        }
                        bi += bm;
                    }
                }
                _ => {
                    lines.push(Line::from(Span::styled(
                        format!(" - {}", before[bi]),
                        Style::default().fg(Color::Red),
                    )));
                    lines.push(Line::from(Span::styled(
                        format!(" + {}", after[ai]),
                        Style::default().fg(Color::Green),
                    )));
                    bi += 1;
                    ai += 1;
                }
            }
        } else if bi < before.len() {
            lines.push(Line::from(Span::styled(
                format!(" - {}", before[bi]),
                Style::default().fg(Color::Red),
            )));
            bi += 1;
        } else {
            lines.push(Line::from(Span::styled(
                format!(" + {}", after[ai]),
                Style::default().fg(Color::Green),
            )));
            ai += 1;
        }
    }

    lines
}

const fn format_control_short(control: &BlockControlSnapshot) -> &'static str {
    match control {
        BlockControlSnapshot::Unknown => "?",
        BlockControlSnapshot::Fallthrough => "→",
        BlockControlSnapshot::Jump { .. } => "JMP",
        BlockControlSnapshot::Branch { .. } => "BR",
        BlockControlSnapshot::Terminal => "END",
    }
}

/// Format a control flow snapshot in a human-readable way
fn format_control_flow(control: &BlockControlSnapshot) -> String {
    match control {
        BlockControlSnapshot::Unknown => "Unknown".to_string(),
        BlockControlSnapshot::Fallthrough => "Fallthrough (continue to next block)".to_string(),
        BlockControlSnapshot::Terminal => "Terminal (STOP/REVERT/RETURN/etc)".to_string(),
        BlockControlSnapshot::Jump { target } => {
            format!("Jump to {}", format_jump_target(target))
        }
        BlockControlSnapshot::Branch {
            true_target,
            false_target,
        } => {
            format!(
                "Branch (true: {}, false: {})",
                format_jump_target(true_target),
                format_jump_target(false_target)
            )
        }
    }
}

/// Format a jump target snapshot
fn format_jump_target(target: &JumpTargetSnapshot) -> String {
    let dest = match &target.kind {
        TraceJumpTargetKind::Block { node } => format!("block {node}"),
        TraceJumpTargetKind::Raw { value } => format!("pc {value:#x}"),
    };
    let enc = match target.encoding {
        JumpEncoding::Absolute => "absolute",
        JumpEncoding::RuntimeRelative => "runtime-relative",
        JumpEncoding::PcRelative => "pc-relative",
    };
    format!("{dest} ({enc})")
}
