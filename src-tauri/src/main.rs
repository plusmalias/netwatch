#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod alerts;
mod apps;
mod audit;
mod blocklist;
mod bluetooth;
mod bt_bands;
mod bt_presence;
mod bt_types;
mod capture;
mod certs;
mod conns;
mod core;
mod corewlan;
mod detect;
mod discovery;
mod expert;
mod export;
mod health;
mod history;
mod internet;
mod location;
mod login;
mod mifi;
mod net;
mod oui;
mod ping;
mod settings;
mod store;
mod tools;
mod tray;
mod upnp;
mod usage;
mod util;
mod wifi;

use crate::capture::CaptureStatus;
use crate::conns::Conn;
use crate::core::{Core, MiniSummary, Snapshot};
use crate::settings::Settings;
use std::sync::Arc;
use tauri::{Emitter, Manager, RunEvent, State, WindowEvent};

type Ctx<'a> = State<'a, Arc<Core>>;

#[tauri::command]
fn get_snapshot(core: Ctx) -> Snapshot {
    core.snapshot()
}

#[tauri::command]
fn get_mini(core: Ctx) -> MiniSummary {
    core.mini()
}

/// Brings the main window forward, on `view` (a page name) if one is given.
#[tauri::command]
fn show_main(app: tauri::AppHandle, view: Option<String>) {
    tray::show_main(&app);
    tray::hide_mini(&app);
    if let Some(view) = view {
        let _ = app.emit("goto", view);
    }
}

#[tauri::command]
fn scan_network(core: Ctx) -> bool {
    core.scan()
}

#[tauri::command]
fn check_ports(core: Ctx, mac: String) -> Result<(), String> {
    core.check_ports(mac)
}

/// "Run audit now" on the Audit page: the port audit over every online device.
#[tauri::command]
fn run_port_audit(core: Ctx) -> Result<(), String> {
    core.inner().run_port_audit()
}

/// "Check now": watched sites' certificates and the HTTPS-interception check.
#[tauri::command]
fn run_cert_check(core: Ctx) -> Result<(), String> {
    core.inner().run_cert_check()
}

#[tauri::command]
fn set_trusted(core: Ctx, mac: String, trusted: bool) -> Result<(), String> {
    core.update_device(&mac, |d| d.trusted = trusted)
}

#[tauri::command]
fn set_notify_presence(core: Ctx, mac: String, on: bool) -> Result<(), String> {
    core.update_device(&mac, |d| d.notify_presence = on)
}

#[tauri::command]
fn trust_all(core: Ctx) {
    core.trust_all()
}

#[tauri::command]
fn set_label(core: Ctx, mac: String, label: String) -> Result<(), String> {
    let label = label.trim().to_string();
    core.update_device(&mac, |d| d.label = (!label.is_empty()).then_some(label))
}

#[tauri::command]
fn forget_device(core: Ctx, mac: String) {
    core.forget_device(&mac)
}

#[tauri::command]
fn ack_alert(core: Ctx, id: Option<u64>) {
    core.acknowledge(id)
}

#[tauri::command]
fn clear_alerts(core: Ctx) {
    core.clear_alerts()
}

#[tauri::command]
async fn list_connections(core: State<'_, Arc<Core>>) -> Result<Vec<Conn>, String> {
    let core = core.inner().clone();
    tauri::async_runtime::spawn_blocking(move || core.connections())
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
fn start_capture(core: Ctx) -> CaptureStatus {
    core.start_capture()
}

#[tauri::command]
fn stop_capture(core: Ctx) -> CaptureStatus {
    core.stop_capture()
}

#[tauri::command]
async fn grant_capture_access(core: State<'_, Arc<Core>>) -> Result<CaptureStatus, String> {
    let core = core.inner().clone();
    tauri::async_runtime::spawn_blocking(move || core.grant_capture_access())
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
fn update_feeds(core: Ctx) {
    core.update_feeds(true)
}

#[tauri::command]
fn get_custom_blocklist(core: Ctx) -> String {
    core.custom_blocklist()
}

#[tauri::command]
fn set_custom_blocklist(core: Ctx, text: String) -> Result<(), String> {
    core.set_custom_blocklist(&text)
}

#[tauri::command]
fn run_speed_test(core: Ctx) -> Result<(), String> {
    core.run_speed_test()
}

#[tauri::command]
fn get_settings(core: Ctx) -> Settings {
    core.settings()
}

#[tauri::command]
fn set_settings(core: Ctx, settings: Settings) -> Result<Settings, String> {
    core.set_settings(settings)
}

/// Sends one test event to the configured SIEM target (UDP, no reply expected).
#[tauri::command]
async fn send_test_event(core: State<'_, Arc<Core>>) -> Result<String, String> {
    let core = core.inner().clone();
    tauri::async_runtime::spawn_blocking(move || core.send_test_event())
        .await
        .map_err(|e| e.to_string())?
}

/// Expert mode's table of what each alert kind means (see expert.rs).
#[tauri::command]
fn get_expert_info() -> Vec<expert::KindView> {
    expert::all()
}

#[tauri::command]
fn refresh_public(core: Ctx) {
    core.refresh_public()
}

#[tauri::command]
fn set_ble_scan(core: Ctx, on: bool) -> Result<(), String> {
    core.inner().set_ble_scan(on)
}

#[tauri::command]
fn set_ble_locate(core: Ctx, id: Option<String>) {
    core.set_ble_locate(id)
}

#[tauri::command]
fn set_ble_mine(core: Ctx, id: String, mine: bool) {
    core.set_ble_mine(&id, mine)
}

#[tauri::command]
fn set_device_meta(core: Ctx, mac: String, notes: String, tags: Vec<String>) -> Result<(), String> {
    let notes = notes.trim().to_string();
    let tags: std::collections::BTreeSet<String> = tags
        .iter()
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty() && t.len() <= 32)
        .take(12)
        .collect();
    core.update_device(&mac, |d| {
        d.notes = (!notes.is_empty()).then(|| notes.chars().take(2000).collect());
        d.tags = tags;
    })
}

#[tauri::command]
fn wake_device(core: Ctx, mac: String) -> Result<(), String> {
    core.wake_device(&mac)
}

#[tauri::command]
async fn run_traceroute(target: String) -> Result<Vec<tools::Hop>, String> {
    tauri::async_runtime::spawn_blocking(move || tools::traceroute(&target))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn run_dns_check(core: State<'_, Arc<Core>>) -> Result<Vec<tools::DnsResult>, String> {
    let core = core.inner().clone();
    tauri::async_runtime::spawn_blocking(move || core.dns_check())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_history(core: Ctx, range: String) -> Vec<history::Point> {
    core.history(&range)
}

#[tauri::command]
async fn run_leak_test() -> Result<tools::LeakResult, String> {
    tauri::async_runtime::spawn_blocking(tools::dns_leak_test)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
fn vpn_status() -> tools::VpnStatus {
    tools::vpn_status()
}

#[tauri::command]
fn open_export(core: Ctx, path: String) -> Result<(), String> {
    core.open_export(&path)
}

#[tauri::command]
fn save_export(core: Ctx, name: String, content: String) -> Result<String, String> {
    core.save_export(&name, &content)
}

/// Opens Finder (or Explorer) with the file selected.
#[tauri::command]
fn reveal_file(path: String) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg("-R").arg(&path).spawn();
    #[cfg(windows)]
    let _ = util::quiet_command("explorer").arg(format!("/select,{path}")).spawn();
    #[cfg(target_os = "linux")]
    if let Some(dir) = std::path::Path::new(&path).parent() {
        let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
    }
}

/// Opens System Settings at Privacy & Security → Location Services. A fixed
/// address, not one from the window.
#[tauri::command]
fn open_location_settings() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices")
            .spawn()
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    #[cfg(not(target_os = "macos"))]
    Err("Location Services settings are on macOS only".into())
}

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    // Only plain http(s) links to the router or well-known pages.
    if !(url.starts_with("http://") || url.starts_with("https://")) || url.contains(['"', '\'', ' ']) {
        return Err("unsupported link".into());
    }
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(&url).spawn();
    #[cfg(windows)]
    let r = util::quiet_command("rundll32").args(["url.dll,FileProtocolHandler", &url]).spawn();
    #[cfg(target_os = "linux")]
    let r = std::process::Command::new("xdg-open").arg(&url).spawn();
    r.map(|_| ()).map_err(|e| e.to_string())
}

/// Dev builds only: runs `NETWATCH_EVAL` in the window once it has loaded,
/// e.g. `NETWATCH_EVAL='setView("devices")'`, for scripted screenshots.
#[cfg(debug_assertions)]
fn dev_eval(app: tauri::AppHandle) {
    let Ok(js) = std::env::var("NETWATCH_EVAL") else { return };
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(3));
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.eval(&js);
        }
    });
}

/// Dev builds only: `NETWATCH_SHOW_MINI=1` opens the menu-bar popover at the
/// top-right of the screen, since nobody can click the icon in a screenshot run.
#[cfg(debug_assertions)]
fn dev_show_mini(app: tauri::AppHandle) {
    if std::env::var("NETWATCH_SHOW_MINI").as_deref() != Ok("1") {
        return;
    }
    std::thread::spawn(move || {
        // Give the page time to load and listen.
        std::thread::sleep(std::time::Duration::from_secs(3));
        tray::show_mini_top_right(&app);
    });
}

fn main() {
    tauri::Builder::default()
        // Must come first: a second launch (say, a double-click while the
        // login-started copy runs) just brings the existing window forward.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| tray::show_main(app)))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--hidden"]),
        ))
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let core = Core::new(app.handle().clone(), dir);
            app.manage(core.clone());
            let tray_ok = tray::build(app)
                .map_err(|e| eprintln!("tray icon unavailable: {e}"))
                .is_ok();
            // A login start (see login.rs) stays in the menu bar. Without a
            // tray icon there would be no way back in, so show the window then.
            let hidden = std::env::args().any(|a| a == "--hidden");
            if !hidden || !tray_ok {
                tray::show_main(app.handle());
            }
            login::apply(app.handle(), core.settings().launch_at_login);
            core.start(hidden);
            #[cfg(debug_assertions)]
            {
                dev_eval(app.handle().clone());
                dev_show_mini(app.handle().clone());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            get_mini,
            show_main,
            scan_network,
            check_ports,
            run_port_audit,
            run_cert_check,
            set_trusted,
            set_notify_presence,
            trust_all,
            set_label,
            forget_device,
            ack_alert,
            clear_alerts,
            list_connections,
            start_capture,
            stop_capture,
            grant_capture_access,
            update_feeds,
            get_custom_blocklist,
            set_custom_blocklist,
            run_speed_test,
            get_settings,
            set_settings,
            send_test_event,
            get_expert_info,
            refresh_public,
            save_export,
            open_export,
            set_ble_scan,
            set_ble_mine,
            set_ble_locate,
            set_device_meta,
            wake_device,
            run_traceroute,
            run_dns_check,
            get_history,
            run_leak_test,
            vpn_status,
            reveal_file,
            open_location_settings,
            open_url,
        ])
        .on_window_event(|window, event| {
            if window.label() == "mini" {
                tray::on_mini_event(window.app_handle(), event);
                return;
            }
            // With "keep running" on, closing the window leaves monitoring
            // going in the menu bar / tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                let keep = window
                    .try_state::<Arc<Core>>()
                    .is_some_and(|c| c.settings().keep_running);
                if keep {
                    api.prevent_close();
                    let _ = window.hide();
                } else {
                    // The hidden menu-bar popover would otherwise keep the app alive.
                    window.app_handle().exit(0);
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building NetWatch")
        .run(|app, event| {
            // Clicking the Dock icon brings a hidden window back.
            #[cfg(target_os = "macos")]
            if let RunEvent::Reopen { .. } = event {
                tray::show_main(app);
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (app, event);
        });
}
