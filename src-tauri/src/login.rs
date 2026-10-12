//! "Open at login": a macOS Launch Agent that starts NetWatch quietly (with
//! `--hidden`) in the menu bar. Only the installed app does this. Dev builds
//! and a bare binary never register or remove anything.

use std::path::Path;
use tauri::{AppHandle, Manager};
use tauri_plugin_autostart::AutoLaunchManager;

/// Whether `exe` is the executable of an app bundle that stays where it is.
/// Apps run from a quarantined download are copied to a random read-only
/// path first (App Translocation), which would make a dead login item.
fn in_app_bundle(exe: &Path) -> bool {
    let path = exe.to_string_lossy();
    path.contains(".app/Contents/MacOS/") && !path.contains("/AppTranslocation/")
}

/// Whether this process may register or remove the login item.
fn may_manage(exe: Option<&Path>) -> bool {
    !cfg!(debug_assertions) && exe.is_some_and(in_app_bundle)
}

/// Makes the login item match the setting. Turning it on re-registers it
/// every time, so it follows the app if it was moved; turning it off removes it.
pub fn apply(app: &AppHandle, on: bool) {
    if !may_manage(std::env::current_exe().ok().as_deref()) {
        return;
    }
    let Some(manager) = app.try_state::<AutoLaunchManager>() else { return };
    // Rewriting an unchanged Launch Agent can make macOS announce a new
    // background item on every launch, so only write it when it's missing
    // or points at an old copy of the app.
    if on && manager.is_enabled().unwrap_or(false) && registered_here() {
        return;
    }
    let result = if on { manager.enable() } else { manager.disable() };
    if let Err(e) = result {
        eprintln!("login item: {e}");
    }
}

/// Whether a Launch Agent already starts this very executable.
fn registered_here() -> bool {
    let (Ok(exe), Some(home)) = (std::env::current_exe(), std::env::var_os("HOME")) else {
        return false;
    };
    let exe = exe.to_string_lossy().into_owned();
    let dir = Path::new(&home).join("Library/LaunchAgents");
    std::fs::read_dir(dir).into_iter().flatten().flatten().any(|e| {
        e.path().extension().is_some_and(|x| x == "plist")
            && std::fs::read_to_string(e.path()).is_ok_and(|t| t.contains(&exe))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_stable_app_bundle_counts() {
        assert!(in_app_bundle(Path::new("/Users/me/Desktop/NetWatch.app/Contents/MacOS/netwatch")));
        assert!(in_app_bundle(Path::new("/Applications/NetWatch.app/Contents/MacOS/netwatch")));
        assert!(!in_app_bundle(Path::new("/Users/me/Projects/netwatch/src-tauri/target/debug/netwatch")));
        assert!(!in_app_bundle(Path::new("/Users/me/Projects/netwatch/src-tauri/target/release/netwatch")));
        assert!(!in_app_bundle(Path::new("/private/var/folders/x/AppTranslocation/ABC/d/NetWatch.app/Contents/MacOS/netwatch")));
    }

    #[test]
    fn debug_builds_never_manage_the_login_item() {
        let exe = Path::new("/Applications/NetWatch.app/Contents/MacOS/netwatch");
        assert_eq!(may_manage(Some(exe)), !cfg!(debug_assertions));
        assert!(!may_manage(None));
    }
}
