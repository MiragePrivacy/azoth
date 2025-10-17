//! Module for the `debug` subcommand, which provides an interactive TUI for visualizing
//! bytecode transformation mappings.
//!
//! This module implements a terminal user interface that allows developers to explore
//! how bytecode was transformed through each obfuscation pass, inspect block-level
//! and instruction-level changes, and understand the mapping between original and
//! obfuscated code positions.

use async_trait::async_trait;
use azoth_transform::mapping::ObfuscationMapping;
use clap::Args;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind,
        MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Wrap,
    },
    Frame, Terminal,
};
use std::error::Error;
use std::fs;
use std::io;

/// Arguments for the `debug` subcommand.
#[derive(Args)]
pub struct DebugArgs {
    /// Path to the transformation mapping JSON file (generated with --emit-mappings)
    pub mapping_file: String,
}

/// Executes the `debug` subcommand by launching the interactive TUI.
#[async_trait]
impl super::Command for DebugArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        // Load the mapping file
        let mapping_json = fs::read_to_string(&self.mapping_file)?;
        let mapping: ObfuscationMapping = serde_json::from_str(&mapping_json)?;

        // Launch the TUI
        run_tui(mapping)?;

        Ok(())
    }
}

/// Application state for the debugger TUI.
struct App {
    /// The loaded obfuscation mapping
    mapping: ObfuscationMapping,
    /// Current view mode
    view_mode: ViewMode,
    /// Selected transform step (0-indexed)
    selected_step: usize,
    /// List state for transform steps
    transform_list_state: ListState,
    /// Scroll offset for detail view
    detail_scroll: u16,
    /// Maximum scroll for detail view
    detail_scroll_max: u16,
    /// Should the app quit
    should_quit: bool,
    /// Selected block position (index in before list) in block diff view
    selected_block: usize,
    /// Set of expanded block positions (indices) in block diff view
    expanded_blocks: std::collections::HashSet<usize>,
    /// Search mode state
    search_mode: SearchMode,
    /// Current search query
    search_query: String,
    /// Search results (indices of blocks matching the query)
    search_results: Vec<usize>,
    /// Currently selected search result index
    search_result_index: usize,
    /// Scroll offset for the output panel
    output_scroll: u16,
    /// Maximum scroll for the output panel
    output_scroll_max: u16,
    /// Cached layout areas for mouse interaction
    tab_area: Option<Rect>,
    block_list_area: Option<Rect>,
}

/// Search mode state.
#[derive(Debug, Clone, Copy, PartialEq)]
enum SearchMode {
    /// Not searching
    Inactive,
    /// Entering search query
    Active,
}

/// Different view modes in the TUI.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ViewMode {
    /// Detailed view of a specific transform
    Detail,
    /// Block-level diff view
    BlockDiff,
}

impl App {
    /// Creates a new app instance with the given mapping.
    fn new(mapping: ObfuscationMapping) -> Self {
        let mut transform_list_state = ListState::default();
        if !mapping.transform_steps.is_empty() {
            transform_list_state.select(Some(0));
        }

        Self {
            mapping,
            view_mode: ViewMode::BlockDiff,
            selected_step: 0,
            transform_list_state,
            detail_scroll: 0,
            detail_scroll_max: 0,
            should_quit: false,
            selected_block: 0,
            expanded_blocks: std::collections::HashSet::new(),
            search_mode: SearchMode::Inactive,
            search_query: String::new(),
            search_results: Vec::new(),
            search_result_index: 0,
            output_scroll: 0,
            output_scroll_max: 0,
            tab_area: None,
            block_list_area: None,
        }
    }

    /// Handles keyboard input events.
    fn handle_input(&mut self, key: KeyCode) {
        // Handle search mode input separately
        if self.search_mode == SearchMode::Active {
            match key {
                KeyCode::Esc => {
                    // Exit search mode
                    self.search_mode = SearchMode::Inactive;
                    self.search_query.clear();
                    self.search_results.clear();
                }
                KeyCode::Enter => {
                    // Exit search mode and stay on current result
                    self.search_mode = SearchMode::Inactive;
                }
                KeyCode::Backspace => {
                    self.search_query.pop();
                    // Re-execute search dynamically
                    self.execute_search();
                    if !self.search_results.is_empty() {
                        self.selected_block = self.search_results[0];
                        self.search_result_index = 0;
                    }
                }
                KeyCode::Down => {
                    // Navigate to next result while searching
                    self.next_search_result();
                }
                KeyCode::Up => {
                    // Navigate to previous result while searching
                    self.prev_search_result();
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                    // Execute search dynamically as user types
                    self.execute_search();
                    if !self.search_results.is_empty() {
                        self.selected_block = self.search_results[0];
                        self.search_result_index = 0;
                    }
                }
                _ => {}
            }
            return;
        }

        // Normal mode input
        match key {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('/') => {
                // Enter search mode
                self.search_mode = SearchMode::Active;
                self.search_query.clear();
                self.search_results.clear();
            }
            KeyCode::Char('n') => {
                // Go to next search result
                self.next_search_result();
            }
            KeyCode::Char('N') => {
                // Go to previous search result
                self.prev_search_result();
            }
            KeyCode::Char('d') => {
                self.view_mode = ViewMode::Detail;
                self.detail_scroll = 0;
            }
            KeyCode::Char('b') => {
                self.view_mode = ViewMode::BlockDiff;
                self.selected_block = 0;
                self.detail_scroll = 0;
            }
            KeyCode::Up | KeyCode::Char('k') => self.scroll_up(),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_down(),
            KeyCode::Left | KeyCode::Char('h') => self.prev_transform(),
            KeyCode::Right | KeyCode::Char('l') => self.next_transform(),
            KeyCode::PageUp => self.page_up(),
            KeyCode::PageDown => self.page_down(),
            KeyCode::Char('K') => self.scroll_output_up(),
            KeyCode::Char('J') => self.scroll_output_down(),
            KeyCode::Enter | KeyCode::Char(' ') => self.toggle_expansion(),
            _ => {}
        }
    }

    /// Scrolls up in the current view.
    fn scroll_up(&mut self) {
        match self.view_mode {
            ViewMode::BlockDiff => {
                if self.selected_block > 0 {
                    self.selected_block -= 1;
                }
            }
            ViewMode::Detail => {
                if self.detail_scroll > 0 {
                    self.detail_scroll -= 1;
                }
            }
        }
    }

    /// Scrolls down in the current view.
    fn scroll_down(&mut self) {
        match self.view_mode {
            ViewMode::BlockDiff => {
                if self.selected_step < self.mapping.transform_steps.len() {
                    let step = &self.mapping.transform_steps[self.selected_step];
                    let max_blocks = step.before.blocks.len().max(step.after.blocks.len());
                    if self.selected_block < max_blocks.saturating_sub(1) {
                        self.selected_block += 1;
                    }
                }
            }
            ViewMode::Detail => {
                if self.detail_scroll < self.detail_scroll_max {
                    self.detail_scroll += 1;
                }
            }
        }
    }

    /// Scrolls up by a page.
    fn page_up(&mut self) {
        if self.detail_scroll >= 10 {
            self.detail_scroll -= 10;
        } else {
            self.detail_scroll = 0;
        }
    }

    /// Scrolls down by a page.
    fn page_down(&mut self) {
        let new_scroll = self.detail_scroll + 10;
        self.detail_scroll = new_scroll.min(self.detail_scroll_max);
    }

    /// Toggles expansion of the currently selected block position.
    fn toggle_expansion(&mut self) {
        match self.view_mode {
            ViewMode::BlockDiff => {
                if self.selected_step < self.mapping.transform_steps.len() {
                    let step = &self.mapping.transform_steps[self.selected_step];
                    if self.selected_block < step.before.blocks.len() {
                        let position = self.selected_block;
                        if self.expanded_blocks.contains(&position) {
                            self.expanded_blocks.remove(&position);
                        } else {
                            self.expanded_blocks.insert(position);
                        }
                    }
                }
            }
            ViewMode::Detail => {}
        }
    }

    /// Switches to the previous transform step.
    fn prev_transform(&mut self) {
        if self.selected_step > 0 {
            // Get the currently selected block's logical_id before switching
            let current_logical_id = if self.view_mode == ViewMode::BlockDiff {
                self.get_selected_block_id()
            } else {
                None
            };

            self.selected_step -= 1;

            // If we have a logical_id, try to find it in the new step
            if let Some(logical_id) = current_logical_id {
                self.select_block_by_id(logical_id);
            }
        }
    }

    /// Switches to the next transform step.
    fn next_transform(&mut self) {
        if self.selected_step < self.mapping.transform_steps.len().saturating_sub(1) {
            // Get the currently selected block's logical_id before switching
            let current_logical_id = if self.view_mode == ViewMode::BlockDiff {
                self.get_selected_block_id()
            } else {
                None
            };

            self.selected_step += 1;

            // If we have a logical_id, try to find it in the new step
            if let Some(logical_id) = current_logical_id {
                self.select_block_by_id(logical_id);
            }
        }
    }

    /// Gets the logical_id of the currently selected block.
    fn get_selected_block_id(&self) -> Option<usize> {
        if self.selected_step >= self.mapping.transform_steps.len() {
            return None;
        }

        let step = &self.mapping.transform_steps[self.selected_step];
        let before_blocks: Vec<_> = step.before.blocks.iter().collect();

        if self.selected_block < before_blocks.len() {
            Some(before_blocks[self.selected_block].block_id)
        } else {
            None
        }
    }

    /// Selects a block by its logical_id in the current transform step.
    /// If the block is not found, keeps the current selection.
    fn select_block_by_id(&mut self, logical_id: usize) {
        if self.selected_step >= self.mapping.transform_steps.len() {
            return;
        }

        let step = &self.mapping.transform_steps[self.selected_step];
        let before_blocks: Vec<_> = step.before.blocks.iter().collect();

        // Find the block with matching logical_id
        if let Some(index) = before_blocks.iter().position(|b| b.block_id == logical_id) {
            self.selected_block = index;
        }
        // If not found, keep current selection (which might be out of bounds,
        // but scroll_down/scroll_up will handle that)
    }

    /// Executes a search for blocks matching the query.
    /// Query can be:
    /// - A decimal number (e.g., "42") - matches block ID only
    /// - A hex number with 0x prefix (e.g., "0x2a") - matches PC (start_pc or within range)
    fn execute_search(&mut self) {
        self.search_results.clear();

        if self.search_query.is_empty() {
            return;
        }

        if self.selected_step >= self.mapping.transform_steps.len() {
            return;
        }

        let step = &self.mapping.transform_steps[self.selected_step];
        let before_blocks: Vec<_> = step.before.blocks.iter().collect();

        let query_lower = self.search_query.to_lowercase();

        // Check if it's a hex search (0x prefix) - search by PC (exact start_pc match only)
        if let Some(hex_str) = query_lower.strip_prefix("0x") {
            if let Ok(pc_value) = usize::from_str_radix(hex_str, 16) {
                // Search for blocks where PC matches start_pc exactly
                for (idx, block) in before_blocks.iter().enumerate() {
                    if block.start_pc == pc_value {
                        self.search_results.push(idx);
                    }
                }
            }
        }
        // Otherwise try decimal - search by block ID only
        else if let Ok(id_value) = self.search_query.parse::<usize>() {
            // Search for blocks where block_id matches
            for (idx, block) in before_blocks.iter().enumerate() {
                if block.block_id == id_value {
                    self.search_results.push(idx);
                }
            }
        }
    }

    /// Navigate to the next search result.
    fn next_search_result(&mut self) {
        if self.search_results.is_empty() {
            return;
        }

        self.search_result_index = (self.search_result_index + 1) % self.search_results.len();
        self.selected_block = self.search_results[self.search_result_index];
    }

    /// Navigate to the previous search result.
    fn prev_search_result(&mut self) {
        if self.search_results.is_empty() {
            return;
        }

        if self.search_result_index == 0 {
            self.search_result_index = self.search_results.len() - 1;
        } else {
            self.search_result_index -= 1;
        }
        self.selected_block = self.search_results[self.search_result_index];
    }

    /// Scrolls the output panel up.
    fn scroll_output_up(&mut self) {
        if self.output_scroll > 0 {
            self.output_scroll -= 1;
        }
    }

    /// Scrolls the output panel down.
    fn scroll_output_down(&mut self) {
        if self.output_scroll < self.output_scroll_max {
            self.output_scroll += 1;
        }
    }

    /// Handles mouse input events.
    fn handle_mouse(&mut self, kind: MouseEventKind, column: u16, row: u16) {
        match kind {
            MouseEventKind::ScrollUp => {
                // Check if mouse is over block list area
                if let Some(area) = self.block_list_area {
                    if column >= area.x
                        && column < area.x + area.width
                        && row >= area.y
                        && row < area.y + area.height
                    {
                        // Scroll block list up
                        self.scroll_up();
                        return;
                    }
                }

                // Otherwise scroll the mnemonic diff view up
                if self.detail_scroll > 0 {
                    self.detail_scroll -= 1;
                }
            }
            MouseEventKind::ScrollDown => {
                // Check if mouse is over block list area
                if let Some(area) = self.block_list_area {
                    if column >= area.x
                        && column < area.x + area.width
                        && row >= area.y
                        && row < area.y + area.height
                    {
                        // Scroll block list down
                        self.scroll_down();
                        return;
                    }
                }

                // Otherwise scroll the mnemonic diff view down
                if self.detail_scroll < self.detail_scroll_max {
                    self.detail_scroll += 1;
                }
            }
            MouseEventKind::Down(_button) => {
                // Check if click is in the tab area
                if let Some(area) = self.tab_area {
                    if row >= area.y && row < area.y + area.height {
                        // Calculate which tab was clicked based on column position
                        self.handle_tab_click(column, area);
                    }
                }
            }
            _ => {}
        }
    }

    /// Handles a mouse click on the view mode tab bar.
    fn handle_tab_click(&mut self, column: u16, area: Rect) {
        // Calculate click position relative to the area
        let click_x = column.saturating_sub(area.x);

        // Tab layout: " [d]etail  │  [b]locks "
        // Detail tab is approximately first 50%, blocks tab is second 50%
        let area_width = area.width.saturating_sub(2); // Account for borders

        // Simple heuristic: if click is in left half, select Detail; right half, select Blocks
        if click_x < area_width / 2 {
            self.view_mode = ViewMode::Detail;
            self.detail_scroll = 0;
        } else {
            self.view_mode = ViewMode::BlockDiff;
            self.selected_block = 0;
            self.detail_scroll = 0;
        }
    }
}

/// Runs the terminal user interface.
fn run_tui(mapping: ObfuscationMapping) -> Result<(), Box<dyn Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new(mapping);

    // Main loop
    let res = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

/// Main application loop.
fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<(), Box<dyn Error>> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind == KeyEventKind::Press {
                        app.handle_input(key.code);
                    }
                }
                Event::Mouse(mouse) => {
                    app.handle_mouse(mouse.kind, mouse.column, mouse.row);
                }
                _ => {}
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

/// Renders the UI.
fn ui(f: &mut Frame, app: &mut App) {
    let size = f.area();

    // Create main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Main content
            Constraint::Length(3), // Footer
        ])
        .split(size);

    // Render header
    render_header(f, chunks[0], app);

    // Render main content based on view mode
    match app.view_mode {
        ViewMode::Detail => render_detail(f, chunks[1], app),
        ViewMode::BlockDiff => render_block_diff(f, chunks[1], app),
    }

    // Render footer
    render_footer(f, chunks[2], app);
}

/// Renders the header bar with view mode tabs.
fn render_header(f: &mut Frame, area: Rect, app: &mut App) {
    // Split header into title and tabs
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(70), // Title
            Constraint::Percentage(30), // View mode tabs
        ])
        .split(area);

    // Render title
    let title = format!(
        "Azoth Bytecode Debugger | {} → {} bytes ({:+} bytes)",
        app.mapping.original_size,
        app.mapping.final_size,
        app.mapping.final_size as i64 - app.mapping.original_size as i64
    );

    let title_widget = Paragraph::new(title)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Left)
        .block(Block::default().borders(Borders::LEFT | Borders::TOP | Borders::BOTTOM));

    f.render_widget(title_widget, header_chunks[0]);

    // Render view mode tabs
    let mut tab_spans = Vec::new();

    // Detail tab
    let detail_style = if app.view_mode == ViewMode::Detail {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    tab_spans.push(Span::styled(" [d]etail ", detail_style));

    // Separator
    tab_spans.push(Span::raw(" │ "));

    // Blocks tab
    let blocks_style = if app.view_mode == ViewMode::BlockDiff {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    tab_spans.push(Span::styled(" [b]locks ", blocks_style));

    let tabs = Paragraph::new(Line::from(tab_spans))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::RIGHT | Borders::TOP | Borders::BOTTOM));

    f.render_widget(tabs, header_chunks[1]);

    // Cache the tab area for mouse interaction
    app.tab_area = Some(header_chunks[1]);
}

/// Renders the footer with keybindings.
fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    // If in search mode, show search input
    if app.search_mode == SearchMode::Active {
        let match_info = if app.search_results.is_empty() {
            "No matches".to_string()
        } else {
            format!(
                "Match {}/{}",
                app.search_result_index + 1,
                app.search_results.len()
            )
        };

        let search_text = format!("Search: {}_ | {}", app.search_query, match_info);
        let footer = Paragraph::new(search_text)
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Left)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title("Block ID (decimal) or PC (0x hex) | [↑/↓] Navigate | [Enter] Confirm | [Esc] Cancel"),
            );
        f.render_widget(footer, area);
    } else {
        // Normal mode keybindings
        let keybindings = match app.view_mode {
            ViewMode::BlockDiff => {
                if app.search_results.is_empty() {
                    "[↑/↓/k/j] Navigate | [J/K] Scroll Output | [←/→/h/l] Transform | [/] Search | [d]etail | [b]locks | [q]uit".to_string()
                } else {
                    format!(
                        "[↑/↓/k/j] Navigate | [J/K] Scroll Output | [←/→/h/l] Transform | [/] Search | [n/N] Result ({}/{}) | [d]etail | [b]locks | [q]uit",
                        app.search_result_index + 1,
                        app.search_results.len()
                    )
                }
            }
            ViewMode::Detail => {
                "[↑/↓/k/j/PgUp/PgDn] Scroll | [←/→/h/l] Transform | [/] Search | [d]etail | [b]locks | [q]uit".to_string()
            }
        };

        let footer = Paragraph::new(keybindings)
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));

        f.render_widget(footer, area);
    }
}

/// Renders the transform tabs for navigation.
fn render_transform_tabs(f: &mut Frame, area: Rect, app: &App) {
    let mut tab_titles = Vec::new();

    for (i, step) in app.mapping.transform_steps.iter().enumerate() {
        let is_selected = i == app.selected_step;
        let changed_marker = if step.changed { "✓" } else { "○" };

        let title = format!(" {} {} {} ", changed_marker, i, step.transform_name);

        let style = if is_selected {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if step.changed {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        tab_titles.push(Span::styled(title, style));

        // Add separator if not the last tab
        if i < app.mapping.transform_steps.len() - 1 {
            tab_titles.push(Span::raw("│"));
        }
    }

    let tabs = Paragraph::new(Line::from(tab_titles))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title("Transform Steps"),
        )
        .alignment(Alignment::Left);

    f.render_widget(tabs, area);
}

/// Renders detailed view of a specific transform step.
fn render_detail(f: &mut Frame, area: Rect, app: &mut App) {
    if app.selected_step >= app.mapping.transform_steps.len() {
        return;
    }

    let step = &app.mapping.transform_steps[app.selected_step];

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Transform: ", Style::default().fg(Color::Yellow)),
            Span::raw(&step.transform_name),
        ]),
        Line::from(vec![
            Span::styled("Changed: ", Style::default().fg(Color::Yellow)),
            Span::raw(if step.changed { "Yes" } else { "No" }),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Statistics:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "  Blocks: {} → {} ({:+})",
            step.statistics.blocks_before,
            step.statistics.blocks_after,
            step.statistics.blocks_delta
        )),
        Line::from(format!(
            "  Instructions: {} → {} ({:+})",
            step.statistics.instructions_before,
            step.statistics.instructions_after,
            step.statistics.instructions_delta
        )),
        Line::from(format!(
            "  Bytes: {} → {} ({:+})",
            step.statistics.bytes_before, step.statistics.bytes_after, step.statistics.bytes_delta
        )),
        Line::from(""),
    ];

    // Add blocks added
    if !step.blocks_added.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("Blocks Added ({}):", step.blocks_added.len()),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )));
        for block in &step.blocks_added {
            lines.push(Line::from(format!(
                "  Block {} @ PC {:#x}: {} instructions, {} bytes",
                block.block_id, block.start_pc, block.instruction_count, block.byte_size
            )));
        }
        lines.push(Line::from(""));
    }

    // Add blocks removed
    if !step.blocks_removed.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("Blocks Removed ({}):", step.blocks_removed.len()),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        for block in &step.blocks_removed {
            lines.push(Line::from(format!(
                "  Block {} @ PC {:#x}: {} instructions, {} bytes",
                block.block_id, block.start_pc, block.instruction_count, block.byte_size
            )));
        }
        lines.push(Line::from(""));
    }

    // Add blocks modified
    if !step.blocks_modified.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("Blocks Modified ({}):", step.blocks_modified.len()),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        for block_mod in &step.blocks_modified {
            lines.push(Line::from(format!(
                "  Block {}: PC {:#x} → {:#x}, Δinstr:{:+}, Δbytes:{:+}",
                block_mod.block_id,
                block_mod.old_start_pc,
                block_mod.new_start_pc,
                block_mod.instruction_delta,
                block_mod.byte_delta
            )));
        }
        lines.push(Line::from(""));
    }

    // Add semantic changes
    if let Some(ref semantic) = step.semantic_changes {
        lines.push(Line::from(Span::styled(
            "Semantic Changes:",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )));

        if let Some(ref selectors) = semantic.selector_mapping {
            lines.push(Line::from(format!(
                "  Function Selectors Remapped: {}",
                selectors.len()
            )));
            for (selector, token) in selectors.iter().take(5) {
                lines.push(Line::from(format!(
                    "    0x{} → {}",
                    selector,
                    hex::encode(token)
                )));
            }
            if selectors.len() > 5 {
                lines.push(Line::from(format!(
                    "    ... and {} more",
                    selectors.len() - 5
                )));
            }
        }

        if !semantic.jump_target_remapping.is_empty() {
            lines.push(Line::from(format!(
                "  Jump Targets Remapped: {}",
                semantic.jump_target_remapping.len()
            )));
        }
        lines.push(Line::from(""));
    }

    // Add PC mapping info
    if !step.pc_mapping.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("PC Mappings ({}):", step.pc_mapping.len()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));

        let mut sorted_mappings: Vec<_> = step.pc_mapping.iter().collect();
        sorted_mappings.sort_by_key(|(old_pc, _)| *old_pc);

        for (old_pc, new_pc) in sorted_mappings.iter().take(10) {
            let delta = **new_pc as i64 - **old_pc as i64;
            lines.push(Line::from(format!(
                "  {:#06x} → {:#06x} ({:+})",
                old_pc, new_pc, delta
            )));
        }
        if step.pc_mapping.len() > 10 {
            lines.push(Line::from(format!(
                "  ... and {} more",
                step.pc_mapping.len() - 10
            )));
        }
    }

    let total_lines = lines.len() as u16;
    let visible_lines = area.height.saturating_sub(2); // Account for borders
    app.detail_scroll_max = total_lines.saturating_sub(visible_lines);

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(format!("Transform Step {} Details", app.selected_step))
                .borders(Borders::ALL),
        )
        .scroll((app.detail_scroll, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);

    // Render scrollbar if needed
    if total_lines > visible_lines {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));

        let mut scrollbar_state = ScrollbarState::new(app.detail_scroll_max as usize)
            .position(app.detail_scroll as usize);

        f.render_stateful_widget(
            scrollbar,
            area.inner(ratatui::layout::Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

/// Renders block-level diff view: [block list] [mnemonic diff] [output]
fn render_block_diff(f: &mut Frame, area: Rect, app: &mut App) {
    if app.selected_step >= app.mapping.transform_steps.len() {
        return;
    }

    let step = &app.mapping.transform_steps[app.selected_step];

    // Create three-column layout: [blocks] [diff] [output]
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20), // Block list
            Constraint::Percentage(50), // Mnemonic diff
            Constraint::Percentage(30), // Output/results
        ])
        .split(area);

    // Get before blocks (we use these as the canonical block list)
    let before_blocks: Vec<&azoth_transform::mapping::BlockInfo> =
        step.before.blocks.iter().collect();

    // Determine if search filtering is active
    let search_active = app.search_mode == SearchMode::Active || !app.search_results.is_empty();

    // Cache block list area for mouse interaction
    app.block_list_area = Some(chunks[0]);

    // Render block list on the left
    render_block_list(
        f,
        chunks[0],
        &before_blocks,
        app.selected_block,
        &app.search_results,
        search_active,
    );

    // Render mnemonic diff in the middle
    if app.selected_block < before_blocks.len() {
        let selected_before_block = before_blocks[app.selected_block];

        // Find the corresponding block in after (by block_id)
        let selected_after_block = step
            .after
            .blocks
            .iter()
            .find(|b| b.block_id == selected_before_block.block_id);

        render_mnemonic_diff(
            f,
            chunks[1],
            selected_before_block,
            selected_after_block,
            app.detail_scroll,
        );

        // Update scroll max based on instruction count
        let before_count = selected_before_block.instructions.len();
        let after_count = selected_after_block
            .map(|b| b.instructions.len())
            .unwrap_or(0);
        let max_instructions = before_count.max(after_count) as u16;
        let visible_lines = chunks[1].height.saturating_sub(2);
        app.detail_scroll_max = max_instructions.saturating_sub(visible_lines);
    }

    // Render output/results on the right
    render_block_output(f, chunks[2], app);
}

/// Renders the block list (left panel)
fn render_block_list(
    f: &mut Frame,
    area: Rect,
    blocks: &[&azoth_transform::mapping::BlockInfo],
    selected_idx: usize,
    search_results: &[usize],
    search_active: bool,
) {
    // Create a set for fast lookup of search results
    let search_set: std::collections::HashSet<usize> = search_results.iter().copied().collect();

    let items: Vec<ListItem> = blocks
        .iter()
        .enumerate()
        .filter_map(|(idx, block)| {
            // If search is active and this block is not in results, skip it
            if search_active && !search_results.is_empty() && !search_set.contains(&idx) {
                return None;
            }

            let content = format!(
                "Block {} @ {:#06x}\n{} instr, {} bytes",
                block.block_id, block.start_pc, block.instruction_count, block.byte_size
            );

            // Highlight search matches
            let item = if search_active && search_set.contains(&idx) {
                ListItem::new(content).style(Style::default().fg(Color::Yellow))
            } else {
                ListItem::new(content)
            };

            Some(item)
        })
        .collect();

    // Find the relative position of selected_idx in the filtered list
    let filtered_selected = if search_active && !search_results.is_empty() {
        search_results.iter().position(|&idx| idx == selected_idx)
    } else {
        Some(selected_idx)
    };

    let mut list_state = ListState::default();
    list_state.select(filtered_selected);

    let title = if search_active && !search_results.is_empty() {
        format!("Bytecode Blocks ({} matches)", search_results.len())
    } else {
        "Bytecode Blocks".to_string()
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("► ");

    f.render_stateful_widget(list, area, &mut list_state);
}

/// Renders the mnemonic diff (middle panel)
fn render_mnemonic_diff(
    f: &mut Frame,
    area: Rect,
    before_block: &azoth_transform::mapping::BlockInfo,
    after_block: Option<&azoth_transform::mapping::BlockInfo>,
    scroll_offset: u16,
) {
    let title = format!(
        "Block {} | PC {:#06x}..{:#06x}",
        before_block.block_id, before_block.start_pc, before_block.end_pc
    );

    // Create side-by-side diff
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 1,
        }));

    // Render border and title for the whole area
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    f.render_widget(block, area);

    // Before instructions (left)
    let before_lines: Vec<Line> = before_block
        .instructions
        .iter()
        .map(|instr| {
            let imm_str = instr
                .immediate
                .as_ref()
                .map(|i| {
                    if i.len() > 8 {
                        format!(" 0x{}...", &i[..8])
                    } else {
                        format!(" 0x{}", i)
                    }
                })
                .unwrap_or_default();
            Line::from(vec![
                Span::styled(
                    format!("{:#06x}: ", instr.pc),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(&instr.opcode, Style::default().fg(Color::Red)),
                Span::styled(imm_str, Style::default().fg(Color::Gray)),
            ])
        })
        .collect();

    let before_paragraph = Paragraph::new(before_lines)
        .block(Block::default().title("Before"))
        .scroll((scroll_offset, 0));

    f.render_widget(before_paragraph, chunks[0]);

    // After instructions (right)
    if let Some(after) = after_block {
        let after_lines: Vec<Line> = after
            .instructions
            .iter()
            .map(|instr| {
                let imm_str = instr
                    .immediate
                    .as_ref()
                    .map(|i| {
                        if i.len() > 8 {
                            format!(" 0x{}...", &i[..8])
                        } else {
                            format!(" 0x{}", i)
                        }
                    })
                    .unwrap_or_default();
                Line::from(vec![
                    Span::styled(
                        format!("{:#06x}: ", instr.pc),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(&instr.opcode, Style::default().fg(Color::Green)),
                    Span::styled(imm_str, Style::default().fg(Color::Gray)),
                ])
            })
            .collect();

        let after_paragraph = Paragraph::new(after_lines)
            .block(Block::default().title("After"))
            .scroll((scroll_offset, 0));

        f.render_widget(after_paragraph, chunks[1]);
    } else {
        let removed = Paragraph::new("[Block Removed]")
            .block(Block::default().title("After"))
            .style(Style::default().fg(Color::Red));
        f.render_widget(removed, chunks[1]);
    }
}

/// Renders the output/results panel (right panel)
fn render_block_output(f: &mut Frame, area: Rect, app: &mut App) {
    if app.selected_step >= app.mapping.transform_steps.len() {
        return;
    }

    let step = &app.mapping.transform_steps[app.selected_step];
    let before_blocks: Vec<&azoth_transform::mapping::BlockInfo> =
        step.before.blocks.iter().collect();

    let mut lines = vec![
        Line::from(Span::styled(
            "Block Information",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    if app.selected_block < before_blocks.len() {
        let before_block = before_blocks[app.selected_block];
        let after_block = step
            .after
            .blocks
            .iter()
            .find(|b| b.block_id == before_block.block_id);

        lines.push(Line::from(vec![
            Span::styled("Block ID: ", Style::default().fg(Color::Yellow)),
            Span::raw(format!("{}", before_block.block_id)),
        ]));

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Before:",
            Style::default().fg(Color::Red),
        )));
        lines.push(Line::from(format!(
            "  PC: {:#06x}..{:#06x}",
            before_block.start_pc, before_block.end_pc
        )));
        lines.push(Line::from(format!(
            "  Instructions: {}",
            before_block.instruction_count
        )));
        lines.push(Line::from(format!("  Bytes: {}", before_block.byte_size)));

        // Find blocks that this block jumps to
        let referenced_blocks = find_referenced_blocks(before_block, &before_blocks, step);
        if !referenced_blocks.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("References {} block(s):", referenced_blocks.len()),
                Style::default().fg(Color::Yellow),
            )));
            for ref_info in referenced_blocks.iter().take(5) {
                let status_marker = if ref_info.valid { "✓" } else { "✗" };
                lines.push(Line::from(format!(
                    "  {} Block {} @ {:#06x} → {:#06x}",
                    status_marker, ref_info.block_id, ref_info.before_pc, ref_info.after_pc
                )));
            }
            if referenced_blocks.len() > 5 {
                lines.push(Line::from(format!(
                    "  ... and {} more",
                    referenced_blocks.len() - 5
                )));
            }
        }

        // Find blocks that reference this block (by checking for jumps to start_pc)
        let referencing_blocks = find_referencing_blocks(before_block, &before_blocks);
        if !referencing_blocks.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("Referenced by {} block(s):", referencing_blocks.len()),
                Style::default().fg(Color::Cyan),
            )));
            for (ref_block_id, ref_start_pc) in referencing_blocks.iter().take(5) {
                lines.push(Line::from(format!(
                    "  Block {} @ {:#06x}",
                    ref_block_id, ref_start_pc
                )));
            }
            if referencing_blocks.len() > 5 {
                lines.push(Line::from(format!(
                    "  ... and {} more",
                    referencing_blocks.len() - 5
                )));
            }
        }

        lines.push(Line::from(""));
        if let Some(after) = after_block {
            lines.push(Line::from(Span::styled(
                "After:",
                Style::default().fg(Color::Green),
            )));
            lines.push(Line::from(format!(
                "  PC: {:#06x}..{:#06x}",
                after.start_pc, after.end_pc
            )));
            lines.push(Line::from(format!(
                "  Instructions: {}",
                after.instruction_count
            )));
            lines.push(Line::from(format!("  Bytes: {}", after.byte_size)));

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Changes:",
                Style::default().fg(Color::Magenta),
            )));
            let pc_delta = after.start_pc as i64 - before_block.start_pc as i64;
            let instr_delta =
                after.instruction_count as i64 - before_block.instruction_count as i64;
            let byte_delta = after.byte_size as i64 - before_block.byte_size as i64;
            lines.push(Line::from(format!("  PC offset: {:+}", pc_delta)));
            lines.push(Line::from(format!("  Instructions: {:+}", instr_delta)));
            lines.push(Line::from(format!("  Bytes: {:+}", byte_delta)));
        } else {
            lines.push(Line::from(Span::styled(
                "Block was removed",
                Style::default().fg(Color::Red),
            )));
        }
    }

    // Calculate scroll max
    let total_lines = lines.len() as u16;
    let visible_lines = area.height.saturating_sub(2); // Account for borders
    app.output_scroll_max = total_lines.saturating_sub(visible_lines);

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title("Output")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta)),
        )
        .scroll((app.output_scroll, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);

    // Render scrollbar if needed
    if total_lines > visible_lines {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));

        let mut scrollbar_state = ScrollbarState::new(app.output_scroll_max as usize)
            .position(app.output_scroll as usize);

        f.render_stateful_widget(
            scrollbar,
            area.inner(ratatui::layout::Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

/// Information about a block reference with validation.
struct BlockReference {
    /// Block ID of the referenced block
    block_id: usize,
    /// PC of the referenced block before transformation
    before_pc: usize,
    /// PC of the referenced block after transformation
    after_pc: usize,
    /// Whether the block still exists with the same logical ID after transformation
    valid: bool,
}

/// Finds blocks that the given block references (jumps to).
///
/// Searches for PUSH + JUMP/JUMPI patterns in the block and validates that
/// the target blocks still exist after transformation.
///
/// Returns a vector of BlockReference structs with validation status.
fn find_referenced_blocks(
    source_block: &azoth_transform::mapping::BlockInfo,
    all_before_blocks: &[&azoth_transform::mapping::BlockInfo],
    step: &azoth_transform::mapping::TransformStep,
) -> Vec<BlockReference> {
    let mut references = Vec::new();
    let instructions = &source_block.instructions;

    // Look for PUSH + JUMP/JUMPI patterns
    for i in 0..instructions.len().saturating_sub(1) {
        let current = &instructions[i];
        let next = &instructions[i + 1];

        // Check if current is PUSH and next is JUMP or JUMPI
        if current.opcode.starts_with("PUSH")
            && !current.opcode.starts_with("PUSH0")
            && (next.opcode == "JUMP" || next.opcode == "JUMPI")
        {
            // Try to parse the immediate value as the jump target
            if let Some(ref immediate) = current.immediate {
                // Remove 0x prefix if present and parse as hex
                let hex_str = immediate.trim_start_matches("0x");
                if let Ok(jump_target_pc) = usize::from_str_radix(hex_str, 16) {
                    // Find the target block in before state
                    if let Some(target_block) = all_before_blocks
                        .iter()
                        .find(|b| b.start_pc == jump_target_pc)
                    {
                        // Check if the block still exists in after state with same block_id
                        let after_block = step
                            .after
                            .blocks
                            .iter()
                            .find(|b| b.block_id == target_block.block_id);

                        let (after_pc, valid) = if let Some(after) = after_block {
                            (after.start_pc, true)
                        } else {
                            (jump_target_pc, false) // Block was removed
                        };

                        references.push(BlockReference {
                            block_id: target_block.block_id,
                            before_pc: jump_target_pc,
                            after_pc,
                            valid,
                        });
                    }
                }
            }
        }
    }

    references
}

/// Finds blocks that reference (jump to) the given block.
///
/// Searches through all blocks looking for:
/// 1. PUSH + JUMP/JUMPI patterns that target the start_pc of the given block
/// 2. JUMPI blocks where the target block is the fallthrough (false branch)
///
/// Returns a vector of (block_id, start_pc) tuples for referencing blocks.
fn find_referencing_blocks(
    target_block: &azoth_transform::mapping::BlockInfo,
    all_blocks: &[&azoth_transform::mapping::BlockInfo],
) -> Vec<(usize, usize)> {
    let mut references = Vec::new();
    let target_pc = target_block.start_pc;

    for block in all_blocks {
        let instructions = &block.instructions;

        if instructions.is_empty() {
            continue;
        }

        let last_instr = &instructions[instructions.len() - 1];

        // Check for PUSH + JUMP/JUMPI patterns
        for i in 0..instructions.len().saturating_sub(1) {
            let current = &instructions[i];
            let next = &instructions[i + 1];

            // Check if current is PUSH and next is JUMP or JUMPI
            if current.opcode.starts_with("PUSH")
                && !current.opcode.starts_with("PUSH0")
                && (next.opcode == "JUMP" || next.opcode == "JUMPI")
            {
                // Try to parse the immediate value as the jump target
                if let Some(ref immediate) = current.immediate {
                    // Remove 0x prefix if present and parse as hex
                    let hex_str = immediate.trim_start_matches("0x");
                    if let Ok(jump_target) = usize::from_str_radix(hex_str, 16) {
                        if jump_target == target_pc {
                            references.push((block.block_id, block.start_pc));
                            break; // Only count each block once
                        }
                    }
                }
            }
        }

        // If we already found this block as a reference, skip fallthrough check
        if references.iter().any(|(id, _)| *id == block.block_id) {
            continue;
        }

        // Check if this block ends with JUMPI and target is the fallthrough (false branch)
        if last_instr.opcode == "JUMPI" {
            // Calculate where this block ends
            let block_end_pc = block.end_pc;

            // If the target block starts right after this block ends, it's the fallthrough
            if target_pc == block_end_pc {
                references.push((block.block_id, block.start_pc));
            }
        }
    }

    references
}

/// Renders instruction-level diff view.
fn render_instruction_diff(f: &mut Frame, area: Rect, app: &mut App) {
    if app.selected_step >= app.mapping.transform_steps.len() {
        return;
    }

    let step = &app.mapping.transform_steps[app.selected_step];

    // Create main layout with tab bar
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tab bar
            Constraint::Min(0),    // Content
        ])
        .split(area);

    // Render tab bar
    render_transform_tabs(f, main_chunks[0], app);

    // Create side-by-side layout for content
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[1]);

    // Calculate total instructions for scroll max
    let before_count: usize = step
        .before
        .blocks
        .iter()
        .map(|b| b.instructions.len())
        .sum();
    let after_count: usize = step.after.blocks.iter().map(|b| b.instructions.len()).sum();
    let max_instructions = before_count.max(after_count) as u16;
    let visible_lines = area.height.saturating_sub(2);
    app.detail_scroll_max = max_instructions.saturating_sub(visible_lines);

    // Collect all instructions from before state
    let before_instructions: Vec<Line> = step
        .before
        .blocks
        .iter()
        .flat_map(|block| {
            block.instructions.iter().map(|instr| {
                let imm_str = instr
                    .immediate
                    .as_ref()
                    .map(|i| format!(" 0x{}", i))
                    .unwrap_or_default();
                Line::from(format!("{:#06x}: {}{}", instr.pc, instr.opcode, imm_str))
            })
        })
        .collect();

    let before_paragraph = Paragraph::new(before_instructions)
        .block(
            Block::default()
                .title("Before Transform")
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::Red)),
        )
        .scroll((app.detail_scroll, 0));

    f.render_widget(before_paragraph, chunks[0]);

    // Collect all instructions from after state
    let after_instructions: Vec<Line> = step
        .after
        .blocks
        .iter()
        .flat_map(|block| {
            block.instructions.iter().map(|instr| {
                let imm_str = instr
                    .immediate
                    .as_ref()
                    .map(|i| format!(" 0x{}", i))
                    .unwrap_or_default();
                Line::from(format!("{:#06x}: {}{}", instr.pc, instr.opcode, imm_str))
            })
        })
        .collect();

    let after_paragraph = Paragraph::new(after_instructions)
        .block(
            Block::default()
                .title("After Transform")
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::Green)),
        )
        .scroll((app.detail_scroll, 0));

    f.render_widget(after_paragraph, chunks[1]);
}
