//! Application state and core logic.

use std::collections::HashSet;

use ratatui::layout::Rect;
use ratatui::widgets::ListState;

use azoth_core::cfg_ir::TraceEvent;

use crate::data::{DebugOutput, DetailCache, ListEntry, TraceGroup};
use crate::format::build_detail_cache;
use crate::trace::{build_trace_groups, build_visible_entries};

/// Application state.
#[allow(missing_docs, missing_debug_implementations)]
pub struct App {
    /// The loaded debug output.
    pub debug: DebugOutput,
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
}

impl App {
    /// Create a new application with the given debug output.
    pub(crate) fn new(debug: DebugOutput) -> Self {
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

        let mut list_state = ListState::default();
        if !visible_entries.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            debug,
            groups,
            expanded_edge_groups,
            expanded_symbolic_groups,
            visible_entries,
            detail_cache,
            selected: 0,
            list_state,
            detail_scroll: 0,
            list_area: Rect::default(),
            detail_area: Rect::default(),
            detail_content_height: 0,
        }
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
}
