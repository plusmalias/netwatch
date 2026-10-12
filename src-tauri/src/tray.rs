//! Menu-bar (tray) icon, so NetWatch keeps monitoring with its window closed.
//! Right click shows a status menu; left click toggles a small dashboard
//! popover (the "mini" window) under the icon.

use crate::core::Core;
use crate::util::now_ms;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, LogicalPosition, Manager, Rect, Runtime, WebviewWindow, WindowEvent};

/// The tray menu's first line, which shows a one-line status.
pub struct TrayStatus<R: Runtime>(pub MenuItem<R>);

const MINI: &str = "mini";
/// The popover's size in points, as set in tauri.conf.json.
const MINI_SIZE: (f64, f64) = (360.0, 480.0);
/// Space between the menu bar and the popover.
const MINI_GAP: f64 = 6.0;
/// The popover keeps this far from the edges of the screen's work area.
const MINI_MARGIN: f64 = 8.0;
/// Pressing the icon takes focus from the popover, which closes it. The
/// click's release that follows within this time is the click that closed
/// it, so it must not open it again.
const MINI_REOPEN_GUARD_MS: u64 = 400;
/// A macOS menu bar is about this tall in points (see `locate`).
const BAR_HEIGHT: f64 = 24.0;

/// When the popover last closed because it lost focus (ms since epoch).
static MINI_BLURRED_AT: AtomicU64 = AtomicU64::new(0);
/// Dev builds: `NETWATCH_SHOW_MINI` keeps the popover open for screenshots.
#[cfg(debug_assertions)]
static MINI_PINNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

pub fn build(app: &tauri::App) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "Starting…", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open NetWatch", true, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", "Scan network now", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit NetWatch", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&status, &sep, &open, &scan, &sep2, &quit])?;
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("NetWatch")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                rect,
                ..
            } = event
            {
                toggle_mini(tray.app_handle(), &rect);
            }
        })
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "scan" => {
                if let Some(core) = app.try_state::<Arc<Core>>() {
                    core.scan();
                }
            }
            "quit" => app.exit(0),
            _ => {}
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    app.manage(TrayStatus(status));
    Ok(())
}

/// Sets the text beside the menu-bar icon, or clears it.
pub fn set_title<R: Runtime>(app: &AppHandle<R>, title: Option<&str>) {
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_title(title);
    }
}

// ------------------------------------------------------------------ menu-bar text

/// A speed in Mb/s, short enough for the menu bar: "0.3", "12", "1.5G".
fn fmt_mbps(bps: u64) -> String {
    let mbps = bps as f64 / 1e6;
    if mbps < 0.05 {
        "0".into()
    } else if mbps >= 999.5 {
        format!("{:.1}G", mbps / 1000.0)
    } else if mbps < 9.95 {
        format!("{mbps:.1}")
    } else {
        format!("{mbps:.0}")
    }
}

/// What to show beside the icon. `rates` is (down, up) in bits/s, if known.
/// `None` means no text.
pub fn title_text(
    mode: &str,
    rates: Option<(u64, u64)>,
    online: usize,
    internet_ms: Option<f32>,
    internet_down: bool,
) -> Option<String> {
    match mode {
        "speed" => Some(match rates {
            Some((down, up)) => format!("↓{} ↑{}", fmt_mbps(down), fmt_mbps(up)),
            None => "↓– ↑–".into(),
        }),
        "devices" => Some(match (internet_down, internet_ms) {
            (true, _) => format!("{online} · down"),
            (false, Some(ms)) if ms < 10.0 => format!("{online} · {ms:.1} ms"),
            (false, Some(ms)) => format!("{online} · {} ms", ms.round()),
            (false, None) => format!("{online} · —"),
        }),
        _ => None,
    }
}

// ------------------------------------------------------------------ popover

/// A rectangle in global points (y grows downwards), the unit macOS lays
/// windows out in.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Area {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

impl Area {
    fn right(&self) -> f64 {
        self.x + self.w
    }

    fn bottom(&self) -> f64 {
        self.y + self.h
    }

    fn contains(&self, x: f64, y: f64) -> bool {
        x >= self.x && x < self.right() && y >= self.y && y < self.bottom()
    }
}

/// One display, in points: all of it, and the part the menu bar and Dock leave free.
struct Screen {
    scale: f64,
    bounds: Area,
    work: Area,
}

/// `v` within `lo..=hi`. If the range is empty (the window is bigger than the
/// space), `lo` wins, which keeps the window's top-left corner on screen.
fn clamp_into(v: f64, lo: f64, hi: f64) -> f64 {
    v.min(hi).max(lo)
}

/// Where the popover's top-left corner goes: centred under the icon and kept
/// inside the work area.
fn popover_origin(icon: Area, size: (f64, f64), work: Area) -> (f64, f64) {
    let x = icon.x + icon.w / 2.0 - size.0 / 2.0;
    let y = icon.bottom() + MINI_GAP;
    (
        clamp_into(x, work.x + MINI_MARGIN, work.right() - size.0 - MINI_MARGIN),
        clamp_into(y, work.y, work.bottom() - size.1 - MINI_MARGIN),
    )
}

/// The icon's rectangle in points, for a rectangle that is physical pixels of
/// a screen with `scale` (or already in points).
fn icon_area(icon: &Rect, scale: f64) -> Area {
    let p = icon.position.to_logical::<f64>(scale);
    let s = icon.size.to_logical::<f64>(scale);
    Area { x: p.x, y: p.y, w: s.width, h: s.height }
}

/// The icon in points, and the screen it sits on.
///
/// macOS reports the icon in physical pixels of its own screen, so the scale
/// to undo is that screen's. A pixel position alone can fit two screens (a 2x
/// and a 1x display side by side), so among the screens the icon would land
/// on, the one that makes it as tall as a menu bar wins.
fn locate<'a>(icon: &Rect, screens: &'a [Screen]) -> Option<(Area, &'a Screen)> {
    screens
        .iter()
        .map(|s| (icon_area(icon, s.scale), s))
        .filter(|(a, s)| s.bounds.contains(a.x + a.w / 2.0, a.y + a.h / 2.0))
        .min_by(|(a, _), (b, _)| (a.h - BAR_HEIGHT).abs().total_cmp(&(b.h - BAR_HEIGHT).abs()))
}

/// The popover's top-left corner in points for a click on `icon`.
fn popover_spot(icon: &Rect, screens: &[Screen], size: (f64, f64)) -> Option<(f64, f64)> {
    let (area, screen) = locate(icon, screens).or_else(|| {
        // Not on any screen we know: trust the first (main) one.
        let s = screens.first()?;
        Some((icon_area(icon, s.scale), s))
    })?;
    Some(popover_origin(area, size, screen.work))
}

fn screens<R: Runtime>(app: &AppHandle<R>) -> Vec<Screen> {
    let area = |x: f64, y: f64, w: f64, h: f64, k: f64| Area { x: x / k, y: y / k, w: w / k, h: h / k };
    app.available_monitors()
        .unwrap_or_default()
        .iter()
        .map(|m| {
            let k = m.scale_factor().max(1.0);
            let (p, s, wa) = (m.position(), m.size(), m.work_area());
            Screen {
                scale: k,
                bounds: area(p.x as f64, p.y as f64, s.width as f64, s.height as f64, k),
                work: area(
                    wa.position.x as f64,
                    wa.position.y as f64,
                    wa.size.width as f64,
                    wa.size.height as f64,
                    k,
                ),
            }
        })
        .collect()
}

fn mini_size<R: Runtime>(w: &WebviewWindow<R>) -> (f64, f64) {
    match (w.outer_size(), w.scale_factor()) {
        (Ok(s), Ok(k)) if k > 0.0 => (s.width as f64 / k, s.height as f64 / k),
        _ => MINI_SIZE,
    }
}

fn should_reopen(now: u64, blurred_at: u64) -> bool {
    now.saturating_sub(blurred_at) > MINI_REOPEN_GUARD_MS
}

/// A click on the tray icon: open the popover under it, or close it.
fn toggle_mini<R: Runtime>(app: &AppHandle<R>, icon: &Rect) {
    let Some(w) = app.get_webview_window(MINI) else { return };
    if w.is_visible().unwrap_or(false) {
        hide_mini(app);
    } else if should_reopen(now_ms(), MINI_BLURRED_AT.load(Ordering::Relaxed)) {
        let origin = popover_spot(icon, &screens(app), mini_size(&w));
        open_mini(app, &w, origin);
    }
}

fn open_mini<R: Runtime>(app: &AppHandle<R>, w: &WebviewWindow<R>, origin: Option<(f64, f64)>) {
    if let Some((x, y)) = origin {
        // Points, not pixels: the window may sit on a screen with another scale.
        let _ = w.set_position(LogicalPosition::new(x, y));
    }
    let _ = w.show();
    let _ = w.set_focus();
    let _ = app.emit("mini-shown", ());
}

/// Hides the popover. Returns whether it was showing.
pub fn hide_mini<R: Runtime>(app: &AppHandle<R>) -> bool {
    let Some(w) = app.get_webview_window(MINI) else { return false };
    if !w.is_visible().unwrap_or(false) {
        return false;
    }
    let _ = w.hide();
    let _ = app.emit("mini-hidden", ());
    true
}

/// Window events for the popover: it closes when it loses focus, and a
/// close request only hides it.
pub fn on_mini_event<R: Runtime>(app: &AppHandle<R>, event: &WindowEvent) {
    match event {
        WindowEvent::Focused(false) => {
            #[cfg(debug_assertions)]
            if MINI_PINNED.load(Ordering::Relaxed) {
                return;
            }
            if hide_mini(app) {
                MINI_BLURRED_AT.store(now_ms(), Ordering::Relaxed);
            }
        }
        WindowEvent::CloseRequested { api, .. } => {
            api.prevent_close();
            hide_mini(app);
        }
        _ => {}
    }
}

/// Dev builds only: opens the popover near the top-right of the main screen
/// and keeps it open, so it can be screenshotted without clicking the icon.
#[cfg(debug_assertions)]
pub fn show_mini_top_right<R: Runtime>(app: &AppHandle<R>) {
    let Some(w) = app.get_webview_window(MINI) else { return };
    let screens = screens(app);
    let origin = screens.first().map(|s| {
        let icon = Area { x: s.bounds.right() - 80.0, y: s.bounds.y, w: BAR_HEIGHT, h: BAR_HEIGHT };
        popover_origin(icon, mini_size(&w), s.work)
    });
    MINI_PINNED.store(true, Ordering::Relaxed);
    open_mini(app, &w, origin);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tauri::{PhysicalPosition, PhysicalSize, Position, Size};

    const SIZE: (f64, f64) = (360.0, 480.0);

    fn area(x: f64, y: f64, w: f64, h: f64) -> Area {
        Area { x, y, w, h }
    }

    fn physical(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect {
            position: Position::Physical(PhysicalPosition::new(x, y)),
            size: Size::Physical(PhysicalSize::new(w, h)),
        }
    }

    /// A 2x laptop screen with an external 1x display to its right.
    fn two_screens() -> Vec<Screen> {
        vec![
            Screen { scale: 2.0, bounds: area(0.0, 0.0, 1440.0, 900.0), work: area(0.0, 24.0, 1440.0, 876.0) },
            Screen { scale: 1.0, bounds: area(1440.0, 0.0, 1920.0, 1080.0), work: area(1440.0, 24.0, 1920.0, 1056.0) },
        ]
    }

    #[test]
    fn formats_speeds_for_the_menu_bar() {
        assert_eq!(fmt_mbps(0), "0");
        assert_eq!(fmt_mbps(30_000), "0");
        assert_eq!(fmt_mbps(300_000), "0.3");
        assert_eq!(fmt_mbps(1_200_000), "1.2");
        assert_eq!(fmt_mbps(9_940_000), "9.9");
        assert_eq!(fmt_mbps(9_960_000), "10");
        assert_eq!(fmt_mbps(12_400_000), "12");
        assert_eq!(fmt_mbps(345_000_000), "345");
        assert_eq!(fmt_mbps(1_500_000_000), "1.5G");
    }

    #[test]
    fn builds_the_menu_bar_text() {
        assert_eq!(title_text("off", Some((1, 1)), 5, Some(20.0), false), None);
        assert_eq!(title_text("bogus", Some((1, 1)), 5, Some(20.0), false), None);
        assert_eq!(
            title_text("speed", Some((1_200_000, 300_000)), 5, None, false).as_deref(),
            Some("↓1.2 ↑0.3")
        );
        assert_eq!(title_text("speed", None, 5, None, false).as_deref(), Some("↓– ↑–"));
        assert_eq!(title_text("devices", None, 5, Some(23.4), false).as_deref(), Some("5 · 23 ms"));
        assert_eq!(title_text("devices", None, 12, Some(4.3), false).as_deref(), Some("12 · 4.3 ms"));
        assert_eq!(title_text("devices", None, 5, None, false).as_deref(), Some("5 · —"));
        assert_eq!(title_text("devices", None, 5, Some(23.0), true).as_deref(), Some("5 · down"));
    }

    #[test]
    fn centres_the_popover_under_the_icon() {
        let work = area(0.0, 24.0, 1440.0, 876.0);
        let (x, y) = popover_origin(area(700.0, 0.0, 24.0, 24.0), SIZE, work);
        assert_eq!((x, y), (532.0, 30.0));
    }

    #[test]
    fn keeps_the_popover_inside_the_work_area() {
        let work = area(0.0, 24.0, 1440.0, 876.0);
        // Icon at the right edge: the popover's right edge stops short of the screen's.
        assert_eq!(popover_origin(area(1416.0, 0.0, 24.0, 24.0), SIZE, work).0, 1440.0 - 360.0 - MINI_MARGIN);
        // Icon at the left edge.
        assert_eq!(popover_origin(area(0.0, 0.0, 24.0, 24.0), SIZE, work).0, MINI_MARGIN);
        // On a second display, relative to that display's work area.
        let ext = area(1440.0, 24.0, 1920.0, 1056.0);
        assert_eq!(popover_origin(area(1450.0, 0.0, 24.0, 24.0), SIZE, ext).0, 1440.0 + MINI_MARGIN);
        // A taskbar at the bottom: the popover sits above it instead of covering the icon.
        let desk = area(0.0, 0.0, 1920.0, 1040.0);
        let (_, y) = popover_origin(area(1200.0, 1050.0, 30.0, 30.0), SIZE, desk);
        assert_eq!(y, 1040.0 - 480.0 - MINI_MARGIN);
        // Taller than the space: the top-left corner stays on screen.
        let short = area(0.0, 24.0, 1440.0, 400.0);
        assert_eq!(popover_origin(area(700.0, 0.0, 24.0, 24.0), SIZE, short).1, 24.0);
    }

    #[test]
    fn converts_the_icon_rectangle_to_points() {
        assert_eq!(icon_area(&physical(2600, 0, 48, 48), 2.0), area(1300.0, 0.0, 24.0, 24.0));
        let points = Rect {
            position: Position::Logical(tauri::LogicalPosition::new(1300.0, 0.0)),
            size: Size::Logical(tauri::LogicalSize::new(24.0, 24.0)),
        };
        assert_eq!(icon_area(&points, 2.0), area(1300.0, 0.0, 24.0, 24.0));
    }

    #[test]
    fn finds_the_screen_the_icon_is_on() {
        let screens = two_screens();
        // Icon on the 2x screen: 48 physical pixels tall is a 24 point menu bar.
        let (a, s) = locate(&physical(2600, 0, 48, 48), &screens).unwrap();
        assert_eq!((a.x, s.scale), (1300.0, 2.0));
        // Icon on the 1x display, at a pixel position that also fits the 2x screen.
        let (a, s) = locate(&physical(1500, 0, 24, 24), &screens).unwrap();
        assert_eq!((a.x, s.scale), (1500.0, 1.0));
        // Off every screen.
        assert!(locate(&physical(9000, 0, 24, 24), &screens).is_none());
    }

    #[test]
    fn places_the_popover_for_a_click() {
        let screens = two_screens();
        let main = popover_spot(&physical(2600, 0, 48, 48), &screens, SIZE).unwrap();
        assert_eq!(main, (1440.0 - 360.0 - MINI_MARGIN, 30.0));
        let ext = popover_spot(&physical(3000, 0, 24, 24), &screens, SIZE).unwrap();
        assert_eq!(ext, (3012.0 - 180.0, 30.0));
        // An unknown spot falls back to the first screen, still clamped into it.
        let (x, _) = popover_spot(&physical(9000, 0, 24, 24), &screens, SIZE).unwrap();
        assert_eq!(x, 1440.0 - 360.0 - MINI_MARGIN);
        assert_eq!(popover_spot(&physical(0, 0, 24, 24), &[], SIZE), None);
    }

    #[test]
    fn the_click_that_closed_the_popover_does_not_reopen_it() {
        assert!(!should_reopen(10_100, 10_000));
        assert!(should_reopen(10_000 + MINI_REOPEN_GUARD_MS + 1, 10_000));
        // Never closed by losing focus.
        assert!(should_reopen(5_000, 0));
    }
}
