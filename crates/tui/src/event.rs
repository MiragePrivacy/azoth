//! Event handling for keyboard and mouse input.

use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, MouseButton, MouseEventKind};

use crate::app::App;
use crate::data::ViewMode;
use crate::decompile::compute_decompile_diff;

/// Handle keyboard events. Returns true if the application should quit.
///
/// The second return value indicates whether diff computation should be triggered.
pub fn handle_key_event(app: &mut App, key: crossterm::event::KeyEvent) -> (bool, bool) {
    if key.kind != KeyEventKind::Press {
        return (false, false);
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return (true, false),
        // Tab toggles view mode (only if diff is available)
        KeyCode::Tab => {
            let needs_compute = app.toggle_view_mode();
            return (false, needs_compute);
        }
        // Navigation depends on view mode
        KeyCode::Down | KeyCode::Char('j') => match app.view_mode {
            ViewMode::Trace => app.select_next(),
            ViewMode::DecompileDiff => app.diff_select_next(),
        },
        KeyCode::Up | KeyCode::Char('k') => match app.view_mode {
            ViewMode::Trace => app.select_prev(),
            ViewMode::DecompileDiff => app.diff_select_prev(),
        },
        KeyCode::Enter | KeyCode::Char(' ') => {
            if app.view_mode == ViewMode::Trace {
                app.toggle_expand();
            }
        }
        KeyCode::PageDown | KeyCode::Char('d') => {
            for _ in 0..10 {
                match app.view_mode {
                    ViewMode::Trace => app.scroll_down(),
                    ViewMode::DecompileDiff => app.diff_scroll_down(),
                }
            }
        }
        KeyCode::PageUp | KeyCode::Char('u') => {
            for _ in 0..10 {
                match app.view_mode {
                    ViewMode::Trace => app.scroll_up(),
                    ViewMode::DecompileDiff => app.diff_scroll_up(),
                }
            }
        }
        KeyCode::Char('J') => match app.view_mode {
            ViewMode::Trace => app.scroll_down(),
            ViewMode::DecompileDiff => app.diff_scroll_down(),
        },
        KeyCode::Char('K') => match app.view_mode {
            ViewMode::Trace => app.scroll_up(),
            ViewMode::DecompileDiff => app.diff_scroll_up(),
        },
        KeyCode::Home | KeyCode::Char('g') => match app.view_mode {
            ViewMode::Trace => app.scroll_home(),
            ViewMode::DecompileDiff => app.diff_scroll_home(),
        },
        KeyCode::End | KeyCode::Char('G') => {
            let height = app.detail_content_height;
            match app.view_mode {
                ViewMode::Trace => app.scroll_end(height),
                ViewMode::DecompileDiff => app.diff_scroll_end(height),
            }
        }
        _ => {}
    }

    (false, false)
}

/// Handle mouse events.
pub fn handle_mouse_event(app: &mut App, mouse: crossterm::event::MouseEvent) {
    let x = mouse.column;
    let y = mouse.row;

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            handle_mouse_click(app, x, y);
        }
        MouseEventKind::ScrollUp => {
            handle_scroll_up(app, x, y);
        }
        MouseEventKind::ScrollDown => {
            handle_scroll_down(app, x, y);
        }
        _ => {}
    }
}

/// Handle mouse click in list area.
fn handle_mouse_click(app: &mut App, x: u16, y: u16) {
    // Check if click is in list area
    if x >= app.list_area.x
        && x < app.list_area.x + app.list_area.width
        && y >= app.list_area.y
        && y < app.list_area.y + app.list_area.height
    {
        // Calculate which item was clicked (accounting for border and scroll offset)
        let relative_y = y.saturating_sub(app.list_area.y + 1);

        match app.view_mode {
            ViewMode::Trace => {
                let scroll_offset = app.list_state.offset();
                let clicked_idx = relative_y as usize + scroll_offset;
                if clicked_idx < app.visible_entries.len() {
                    if app.selected == clicked_idx {
                        // Double-click effect: toggle expand
                        app.toggle_expand();
                    } else {
                        app.select_index(clicked_idx);
                    }
                }
            }
            ViewMode::DecompileDiff => {
                let scroll_offset = app.diff_list_state.offset();
                let clicked_idx = relative_y as usize + scroll_offset;
                if clicked_idx < app.diff_item_count() {
                    app.diff_select_index(clicked_idx);
                }
            }
        }
    }
}

/// Handle scroll up event.
fn handle_scroll_up(app: &mut App, x: u16, y: u16) {
    if is_in_detail_area(app, x, y) {
        match app.view_mode {
            ViewMode::Trace => app.scroll_up(),
            ViewMode::DecompileDiff => app.diff_scroll_up(),
        }
    } else if is_in_list_area(app, x, y) {
        match app.view_mode {
            ViewMode::Trace => app.select_prev(),
            ViewMode::DecompileDiff => app.diff_select_prev(),
        }
    }
}

/// Handle scroll down event.
fn handle_scroll_down(app: &mut App, x: u16, y: u16) {
    if is_in_detail_area(app, x, y) {
        match app.view_mode {
            ViewMode::Trace => app.scroll_down(),
            ViewMode::DecompileDiff => app.diff_scroll_down(),
        }
    } else if is_in_list_area(app, x, y) {
        match app.view_mode {
            ViewMode::Trace => app.select_next(),
            ViewMode::DecompileDiff => app.diff_select_next(),
        }
    }
}

/// Check if position is in the detail area.
const fn is_in_detail_area(app: &App, x: u16, y: u16) -> bool {
    x >= app.detail_area.x
        && x < app.detail_area.x + app.detail_area.width
        && y >= app.detail_area.y
        && y < app.detail_area.y + app.detail_area.height
}

/// Check if position is in the list area.
const fn is_in_list_area(app: &App, x: u16, y: u16) -> bool {
    x >= app.list_area.x
        && x < app.list_area.x + app.list_area.width
        && y >= app.list_area.y
        && y < app.list_area.y + app.list_area.height
}

/// Run the main event loop. Returns when the user quits.
pub fn run_event_loop<B: ratatui::backend::Backend>(
    terminal: &mut ratatui::Terminal<B>,
    mut app: App,
    ui_fn: fn(&mut ratatui::Frame<'_>, &mut App),
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui_fn(f, &mut app))?;

        match event::read()? {
            Event::Key(key) => {
                let (quit, needs_compute) = handle_key_event(&mut app, key);
                if quit {
                    return Ok(());
                }
                if needs_compute {
                    // Compute diff when switching to diff view
                    if let Some(snapshots) = app.take_snapshots_for_computation() {
                        // Redraw to show "Computing..." state before blocking
                        terminal.draw(|f| ui_fn(f, &mut app))?;

                        // Use block_in_place to allow blocking within an async context
                        // This works whether we're in a runtime or not
                        let result = tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current()
                                .block_on(compute_decompile_diff(snapshots))
                        });
                        app.set_diff_result(result);
                    }
                }
            }
            Event::Mouse(mouse) => {
                handle_mouse_event(&mut app, mouse);
            }
            _ => {}
        }
    }
}
