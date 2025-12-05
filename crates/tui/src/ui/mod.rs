//! UI rendering modules for the TUI application.

mod detail;
mod header;
mod list;

pub use detail::render_detail;
pub use header::render_header;
pub use list::render_list;

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Frame;

use crate::app::App;

/// Main UI function that renders all components.
pub fn ui(f: &mut Frame<'_>, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Header
            Constraint::Min(0),    // Main content
        ])
        .split(f.area());

    render_header(f, chunks[0]);
    render_main(f, chunks[1], app);
}

/// Render the main content area with list and detail panels.
fn render_main(f: &mut Frame<'_>, area: ratatui::layout::Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    render_list(f, chunks[0], app);
    render_detail(f, chunks[1], app);
}
