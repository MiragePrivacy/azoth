//! Application state and core logic.

use std::collections::HashSet;

use azoth_analysis::decompile_diff::{StructureKind, StructuredDiffResult};
use ratatui::layout::Rect;
use ratatui::widgets::ListState;

use azoth_core::cfg_ir::TraceEvent;

use crate::data::{DebugOutput, DetailCache, ListEntry, TraceGroup, ViewMode};
use crate::decompile::BytecodeSnapshots;
use crate::format::build_detail_cache;
use crate::trace::{build_trace_groups, build_visible_entries};

/// Diff computation state.
#[derive(Debug, Default)]
pub enum DiffState {
    /// No bytecode snapshots available.
    #[default]
    Unavailable,
    /// Snapshots available, diff not yet computed.
    Pending(BytecodeSnapshots),
    /// Diff computation in progress.
    Computing,
    /// Diff computed successfully.
    Ready(StructuredDiffResult),
    /// Diff computation failed.
    Failed(String),
}

/// Application state.
#[allow(missing_docs, missing_debug_implementations)]
pub struct App {
    /// Current view mode.
    pub view_mode: ViewMode,
    /// The loaded debug output.
    pub debug: DebugOutput,
    /// Filename being viewed (for display in header).
    pub filename: Option<String>,
    /// Grouped trace events
    pub groups: Vec<TraceGroup>,
    /// Expanded edge groups (keyed by first trace index)
    pub expanded_edge_groups: HashSet<usize>,
    /// Expanded symbolic groups (keyed by first trace index)
    pub expanded_symbolic_groups: HashSet<usize>,
    /// Flattened list of visible entries
    pub visible_entries: Vec<ListEntry>,
    /// Pre-computed detail content for all entries
    pub detail_cache: DetailCache,
    /// Selected index in visible_entries
    pub selected: usize,
    /// List state for navigation
    pub list_state: ListState,
    /// Scroll position within detail view
    pub detail_scroll: u16,
    /// Area of the list widget (for mouse hit testing)
    pub list_area: Rect,
    /// Area of the detail widget (for mouse scrolling)
    pub detail_area: Rect,
    /// Height of the current detail content (for scroll bounds)
    pub detail_content_height: u16,
    /// Decompile diff state (lazy computation).
    pub diff_state: DiffState,
    /// Selected diff item index (for diff view).
    pub diff_selected: usize,
    /// List state for diff navigation.
    pub diff_list_state: ListState,
    /// Scroll position for diff detail view.
    pub diff_detail_scroll: u16,
}

impl App {
    /// Create a new application with the given debug output.
    pub(crate) fn new(
        debug: DebugOutput,
        snapshots: Option<BytecodeSnapshots>,
        filename: Option<String>,
    ) -> Self {
        let groups = build_trace_groups(&debug.trace);

        let expanded_edge_groups = HashSet::new();
        let expanded_symbolic_groups = HashSet::new();
        let visible_entries = build_visible_entries(
            &groups,
            &debug.trace,
            &expanded_edge_groups,
            &expanded_symbolic_groups,
        );

        // Pre-compute all detail content at startup
        let detail_cache = build_detail_cache(&debug, &groups);

        // Find Finalize group and select it
        let selected = visible_entries
            .iter()
            .position(|e| matches!(e, ListEntry::GroupHeader { name, .. } if name == "Finalize"))
            .unwrap_or(0);

        let mut list_state = ListState::default();
        if !visible_entries.is_empty() {
            list_state.select(Some(selected));
        }

        let diff_list_state = ListState::default();

        // Initialize diff state based on whether snapshots are available
        let diff_state = match snapshots {
            Some(s) => DiffState::Pending(s),
            None => DiffState::Unavailable,
        };

        Self {
            view_mode: ViewMode::default(),
            debug,
            filename,
            groups,
            expanded_edge_groups,
            expanded_symbolic_groups,
            visible_entries,
            detail_cache,
            selected,
            list_state,
            detail_scroll: 0,
            list_area: Rect::default(),
            detail_area: Rect::default(),
            detail_content_height: 0,
            diff_state,
            diff_selected: 0,
            diff_list_state,
            diff_detail_scroll: 0,
        }
    }

    /// Toggle between view modes.
    ///
    /// Returns true if async diff computation should be triggered.
    #[allow(clippy::missing_const_for_fn)]
    pub(crate) fn toggle_view_mode(&mut self) -> bool {
        match &self.diff_state {
            DiffState::Unavailable => false,
            DiffState::Pending(_) => {
                // Switch to diff view and signal that computation is needed
                self.view_mode = ViewMode::DecompileDiff;
                self.detail_scroll = 0;
                self.diff_detail_scroll = 0;
                true
            }
            DiffState::Computing => {
                // Already computing, switch view
                self.view_mode = ViewMode::DecompileDiff;
                false
            }
            DiffState::Ready(_) | DiffState::Failed(_) => {
                // Toggle normally
                self.view_mode = match self.view_mode {
                    ViewMode::Trace => ViewMode::DecompileDiff,
                    ViewMode::DecompileDiff => ViewMode::Trace,
                };
                self.detail_scroll = 0;
                self.diff_detail_scroll = 0;
                false
            }
        }
    }

    /// Check if decompile diff is potentially available (snapshots exist).
    pub(crate) const fn has_diff(&self) -> bool {
        !matches!(self.diff_state, DiffState::Unavailable)
    }

    /// Get the diff result if ready.
    pub(crate) const fn get_diff(&self) -> Option<&StructuredDiffResult> {
        match &self.diff_state {
            DiffState::Ready(diff) => Some(diff),
            _ => None,
        }
    }

    /// Take snapshots for computation (sets state to Computing).
    pub(crate) fn take_snapshots_for_computation(&mut self) -> Option<BytecodeSnapshots> {
        match std::mem::replace(&mut self.diff_state, DiffState::Computing) {
            DiffState::Pending(snapshots) => Some(snapshots),
            other => {
                self.diff_state = other;
                None
            }
        }
    }

    /// Set the computed diff result.
    pub(crate) fn set_diff_result(&mut self, result: Option<StructuredDiffResult>) {
        self.diff_state = match result {
            Some(mut diff) => {
                // Filter out Header section (always matches, not useful to display)
                diff.items
                    .retain(|item| !matches!(item.kind, StructureKind::Header));
                DiffState::Ready(diff)
            }
            None => DiffState::Failed("Decompilation failed".to_string()),
        };
    }

    /// Rebuild visible entries after expansion state changes.
    pub(crate) fn rebuild_visible(&mut self) {
        self.visible_entries = build_visible_entries(
            &self.groups,
            &self.debug.trace,
            &self.expanded_edge_groups,
            &self.expanded_symbolic_groups,
        );
        // Clamp selection
        if self.selected >= self.visible_entries.len() {
            self.selected = self.visible_entries.len().saturating_sub(1);
        }
        self.list_state.select(Some(self.selected));
    }

    /// Get the currently selected entry.
    pub(crate) fn current_entry(&self) -> Option<&ListEntry> {
        self.visible_entries.get(self.selected)
    }

    /// Get the trace event for the current selection (if applicable).
    #[allow(dead_code)]
    pub(crate) fn current_trace(&self) -> Option<&TraceEvent> {
        match self.current_entry()? {
            ListEntry::Operation { trace_idx, .. }
            | ListEntry::EdgeOperation { trace_idx, .. }
            | ListEntry::SymbolicOperation { trace_idx, .. } => self.debug.trace.get(*trace_idx),
            ListEntry::GroupHeader { .. }
            | ListEntry::EdgeGroup { .. }
            | ListEntry::SymbolicGroup { .. } => None,
        }
    }

    /// Select the next item in the list.
    pub(crate) fn select_next(&mut self) {
        if self.selected < self.visible_entries.len().saturating_sub(1) {
            self.selected += 1;
            self.list_state.select(Some(self.selected));
            self.detail_scroll = 0;
        }
    }

    /// Select the previous item in the list.
    pub(crate) fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            self.list_state.select(Some(self.selected));
            self.detail_scroll = 0;
        }
    }

    /// Toggle expansion of the current entry.
    pub(crate) fn toggle_expand(&mut self) {
        match self.current_entry().cloned() {
            Some(ListEntry::GroupHeader { group_idx, .. }) => {
                if let Some(group) = self.groups.get_mut(group_idx) {
                    group.expanded = !group.expanded;
                    self.rebuild_visible();
                }
            }
            Some(ListEntry::EdgeGroup { key, .. }) => {
                if self.expanded_edge_groups.contains(&key) {
                    self.expanded_edge_groups.remove(&key);
                } else {
                    self.expanded_edge_groups.insert(key);
                }
                self.rebuild_visible();
            }
            Some(ListEntry::SymbolicGroup { key, .. }) => {
                if self.expanded_symbolic_groups.contains(&key) {
                    self.expanded_symbolic_groups.remove(&key);
                } else {
                    self.expanded_symbolic_groups.insert(key);
                }
                self.rebuild_visible();
            }
            _ => {}
        }
    }

    /// Select an item by index.
    pub(crate) fn select_index(&mut self, index: usize) {
        if index < self.visible_entries.len() {
            self.selected = index;
            self.list_state.select(Some(index));
            self.detail_scroll = 0;
        }
    }

    /// Scroll detail view down by one line.
    pub(crate) const fn scroll_down(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_add(1);
    }

    /// Scroll detail view up by one line.
    pub(crate) const fn scroll_up(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_sub(1);
    }

    /// Scroll detail view to the beginning.
    pub(crate) const fn scroll_home(&mut self) {
        self.detail_scroll = 0;
    }

    /// Scroll detail view to the end.
    pub(crate) const fn scroll_end(&mut self, content_height: u16) {
        let visible_height = self.detail_area.height.saturating_sub(2); // Account for borders
        if content_height > visible_height {
            self.detail_scroll = content_height.saturating_sub(visible_height);
        }
    }

    // --- Diff view navigation ---

    /// Get the number of diff items.
    pub(crate) fn diff_item_count(&self) -> usize {
        self.get_diff().map(|d| d.items.len()).unwrap_or(0)
    }

    /// Select the next diff item.
    pub(crate) fn diff_select_next(&mut self) {
        let count = self.diff_item_count();
        if count > 0 && self.diff_selected < count.saturating_sub(1) {
            self.diff_selected += 1;
            self.diff_list_state.select(Some(self.diff_selected));
            self.diff_detail_scroll = 0;
        }
    }

    /// Select the previous diff item.
    pub(crate) fn diff_select_prev(&mut self) {
        if self.diff_selected > 0 {
            self.diff_selected -= 1;
            self.diff_list_state.select(Some(self.diff_selected));
            self.diff_detail_scroll = 0;
        }
    }

    /// Select a diff item by index.
    pub(crate) fn diff_select_index(&mut self, index: usize) {
        let count = self.diff_item_count();
        if index < count {
            self.diff_selected = index;
            self.diff_list_state.select(Some(index));
            self.diff_detail_scroll = 0;
        }
    }

    /// Scroll diff detail view down.
    pub(crate) const fn diff_scroll_down(&mut self) {
        self.diff_detail_scroll = self.diff_detail_scroll.saturating_add(1);
    }

    /// Scroll diff detail view up.
    pub(crate) const fn diff_scroll_up(&mut self) {
        self.diff_detail_scroll = self.diff_detail_scroll.saturating_sub(1);
    }

    /// Scroll diff detail to beginning.
    pub(crate) const fn diff_scroll_home(&mut self) {
        self.diff_detail_scroll = 0;
    }

    /// Scroll diff detail to end.
    pub(crate) const fn diff_scroll_end(&mut self, content_height: u16) {
        let visible_height = self.detail_area.height.saturating_sub(2);
        if content_height > visible_height {
            self.diff_detail_scroll = content_height.saturating_sub(visible_height);
        }
    }
}
