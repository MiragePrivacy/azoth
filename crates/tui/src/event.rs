//! Event handling for keyboard and mouse input.

use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, MouseButton, MouseEventKind};

use crate::app::App;

/// Handle keyboard events. Returns true if the application should quit.
pub fn handle_key_event(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    if key.kind != KeyEventKind::Press {
        return false;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return true,
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
        KeyCode::Home | KeyCode::Char('g') => app.scroll_home(),
        KeyCode::End | KeyCode::Char('G') => {
            let height = app.detail_content_height;
            app.scroll_end(height);
        }
        _ => {}
    }

    false
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
}

/// Handle scroll up event.
fn handle_scroll_up(app: &mut App, x: u16, y: u16) {
    if is_in_detail_area(app, x, y) {
        app.scroll_up();
    } else if is_in_list_area(app, x, y) {
        app.select_prev();
    }
}

/// Handle scroll down event.
fn handle_scroll_down(app: &mut App, x: u16, y: u16) {
    if is_in_detail_area(app, x, y) {
        app.scroll_down();
    } else if is_in_list_area(app, x, y) {
        app.select_next();
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
                if handle_key_event(&mut app, key) {
                    return Ok(());
                }
            }
            Event::Mouse(mouse) => {
                handle_mouse_event(&mut app, mouse);
            }
            _ => {}
        }
    }
}
