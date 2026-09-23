#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! Proxy Router dashboard + tray.
//!
//! The tray used to seed the `disconnected` glyph and only ever update from a
//! build-time fixture, so it reported "Disconnected" while the router was up.
//! It now polls the real controller through [`controller`] and paints
//! connected / degraded / failed / disconnected from live state
//! (Emanboiee/proxy-router#144).

mod controller;

use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tauri::{
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem, Submenu},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, Runtime,
};

struct LaunchTime(Instant);

/// Latest live controller reading, shared with the frontend.
#[derive(Default)]
struct LiveStatus {
    state: Mutex<String>,
    payload: Mutex<Option<Value>>,
    detail: Mutex<Option<String>>,
    at: Mutex<Option<Instant>>,
}

impl LiveStatus {
    /// One consistent read of the cache: state, payload, error, age.
    fn snapshot(&self) -> (String, Option<Value>, Option<String>, Option<u128>) {
        let state = self.state.lock().map(|s| s.clone()).unwrap_or_default();
        let payload = self.payload.lock().ok().and_then(|p| p.clone());
        let detail = self.detail.lock().ok().and_then(|d| d.clone());
        let age = self.at.lock().ok().and_then(|a| *a).map(|t| t.elapsed().as_millis());
        (state, payload, detail, age)
    }
}

/// Seconds between live controller polls.
///
/// The poll spawns the Python CLI, so this is the engine's background cost:
/// at 5s it was burning most of a core. The window refreshes on demand and
/// the tray only needs a truthful icon, so 15s is the useful floor.
const POLL_SECONDS: u64 = 15;

/// A cached reading younger than this is served without re-running the CLI.
const CACHE_FRESH_MS: u128 = 2500;

#[tauri::command]
fn preview_rendered(start: tauri::State<LaunchTime>) {
    eprintln!("preview_first_frame_ms={}", start.0.elapsed().as_millis());
}

/// Build-time fixture, kept for the non-Tauri browser preview contract.
#[tauri::command]
fn get_preview_status() -> Result<serde_json::Value, String> {
    serde_json::from_str(include_str!("../../src/status.json"))
        .map_err(|_| "Preview status unavailable".to_string())
}

fn show_dashboard<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn tray_icon_bytes(state: &str) -> &'static [u8] {
    match state {
        "connected" => include_bytes!("../icons/tray-connected.rgba"),
        "degraded" | "stale" => include_bytes!("../icons/tray-degraded.rgba"),
        "failed" => include_bytes!("../icons/tray-failed.rgba"),
        _ => include_bytes!("../icons/tray-disconnected.rgba"),
    }
}

fn tray_icon(state: &str) -> Result<Image<'static>, String> {
    Ok(Image::new(tray_icon_bytes(state), 32, 32))
}

fn tray_tooltip(state: &str) -> Result<&'static str, String> {
    match state {
        "connected" => Ok("Proxy Router · Connected"),
        "degraded" | "stale" => Ok("Proxy Router · Needs attention"),
        "failed" => Ok("Proxy Router · Controller unavailable"),
        "disconnected" | "offline" | "empty" | "loading" => Ok("Proxy Router · Disconnected"),
        _ => Err("Unknown connection state".to_string()),
    }
}

/// Paint the tray from a connection state.
fn apply_tray_state<R: Runtime>(app: &AppHandle<R>, state: &str) -> Result<(), String> {
    let tray = app
        .tray_by_id("proxy-router")
        .ok_or_else(|| "Tray unavailable".to_string())?;
    tray.set_icon(Some(tray_icon(state)?))
        .map_err(|error| format!("Could not update tray icon: {error}"))?;
    tray.set_tooltip(Some(tray_tooltip(state)?))
        .map_err(|error| format!("Could not update tray tooltip: {error}"))
}

/// Poll the controller once and publish the result to the tray and the UI.
fn refresh_live_status<R: Runtime>(
    app: &AppHandle<R>,
    full: bool,
) -> (String, Option<Value>, Option<String>) {
    let root = controller::router_root();
    let result = if full {
        controller::live_status(&root)
    } else {
        controller::live_status_fast(&root)
    };
    let state = controller::state_for_result(&result).to_string();
    let (payload, detail) = match result {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error)),
    };
    if let Some(live) = app.try_state::<LiveStatus>() {
        if let Ok(mut slot) = live.state.lock() {
            *slot = state.clone();
        }
        if let Ok(mut slot) = live.payload.lock() {
            *slot = payload.clone();
        }
        if let Ok(mut slot) = live.detail.lock() {
            *slot = detail.clone();
        }
        if let Ok(mut slot) = live.at.lock() {
            *slot = Some(Instant::now());
        }
    }
    if let Err(error) = apply_tray_state(app, &state) {
        eprintln!("tray: {error}");
    }
    (state, payload, detail)
}

/// Live reading, served from the cache when it is still fresh.
///
/// `force` (menu "Refresh status", post-action reconciliation) always runs the
/// controller; otherwise a reading younger than [`CACHE_FRESH_MS`] is returned
/// as-is, so a click never waits on a CLI spawn the poller just paid for.
#[tauri::command]
fn get_live_status<R: Runtime>(app: AppHandle<R>, force: Option<bool>) -> Result<Value, String> {
    if !force.unwrap_or(false) {
        if let Some(live) = app.try_state::<LiveStatus>() {
            let (state, Some(payload), _, age) = live.snapshot() else {
                return after_refresh(&app);
            };
            if age.map(|ms| ms < CACHE_FRESH_MS).unwrap_or(false) {
                return Ok(serde_json::json!({
                    "state": state, "status": payload, "age_ms": age,
                }));
            }
        }
    }
    after_refresh(&app)
}

fn after_refresh<R: Runtime>(app: &AppHandle<R>) -> Result<Value, String> {
    let (state, payload, detail) = refresh_live_status(app, false);
    match payload {
        Some(value) => Ok(serde_json::json!({"state": state, "status": value, "age_ms": 0})),
        None => Err(detail.unwrap_or_else(|| "Controller unavailable".to_string())),
    }
}

/// Cached reading, so the UI can paint before the next poll lands.
#[tauri::command]
fn cached_live_status(live: tauri::State<LiveStatus>) -> Value {
    let (state, payload, detail, age) = live.snapshot();
    serde_json::json!({"state": state, "status": payload, "error": detail, "age_ms": age})
}

/// Tray/menu actions, whitelisted to explicit engine verbs.
///
/// Connect/Disconnect map to `start`/`stop` so the window and the tray can
/// actually change engine state; `stop` writes the manual-off marker the
/// keepalive honors, so a deliberate Disconnect stays disconnected.
fn action_args(action: &str, payload: Option<&Value>) -> Result<Vec<String>, String> {
    match action {
        // `start` (not just `ensure`) so a deliberate Disconnect is undone
        // explicitly: start clears the manual-off marker the keepalive honors.
        "connect" => Ok(vec!["start".to_string()]),
        "reconnect" => Ok(vec!["ensure".to_string()]),
        // `stop` writes the manual-off marker, so the keepalive will not
        // resurrect the engine behind the user's back.
        "disconnect" => Ok(vec!["stop".to_string()]),
        "rotate" => {
            let provider = payload
                .and_then(|value| value.get("active_providers"))
                .and_then(Value::as_object)
                .and_then(|map| map.keys().next().cloned());
            match provider {
                Some(name) => Ok(vec!["rotate".to_string(), name]),
                None => Err("no active provider to rotate".to_string()),
            }
        }
        "sweep" => Ok(vec!["egress".to_string(), "sweep".to_string()]),
        // Network-detection verbs (read-only or recovery; no engine restart).
        "network-check" => Ok(vec!["network-check".to_string()]),
        "network-reconnect" => Ok(vec!["network-reconnect".to_string()]),
        "network-disconnect" => Ok(vec!["network-disconnect".to_string()]),
        other => Err(format!("unsupported action: {other}")),
    }
}

#[tauri::command]
fn run_router_action<R: Runtime>(app: AppHandle<R>, action: String) -> Result<String, String> {
    let payload = app
        .try_state::<LiveStatus>()
        .and_then(|live| live.payload.lock().ok().and_then(|slot| slot.clone()));
    let args = action_args(&action, payload.as_ref())?;
    let root = controller::router_root();
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = controller::run_controller(&root, &borrowed)?;
    refresh_live_status(&app, false);
    Ok(output)
}

/// Presets the dashboard may apply. Keeps the command from being a generic
/// CLI passthrough while still letting an explicit profile choice stick.
const ALLOWED_PRESETS: [&str; 4] = ["opencode", "school-warp", "roblox", "default"];

/// Apply a named preset to the live config and reload the engine.
///
/// Profile switches in the window used to be browser-local only, so the tray
/// kept reporting the old real state and the UI looked like it "reverted".
#[tauri::command]
fn apply_preset(app: AppHandle, name: String) -> Result<String, String> {
    if !ALLOWED_PRESETS.contains(&name.as_str()) {
        return Err(format!("unsupported preset: {name}"));
    }
    let root = controller::router_root();
    let applied = controller::run_controller(&root, &["setup", "--preset", &name])?;
    controller::run_controller(&root, &["reload"])?;
    refresh_live_status(&app, false);
    Ok(applied)
}

/// Config keys the dashboard may read. Explicit allowlist: router.json is
/// handed to the webview, so no key is exposed implicitly.
const CONFIG_KEYS: [&str; 8] = [
    "port", "preset", "providers", "routes", "routing", "vpn", "keepalive", "rotation",
];

/// Preset/SSID slug rules, mirrored from the engine's validation.
fn valid_slug(value: &str, max: usize) -> bool {
    // The engine (router.py cmd_network_preset_set) is the authority: any
    // non-empty SSID without control characters, up to the length cap. Real
    // networks contain spaces and non-ASCII; the old alnum-only rule made
    // them unmappable from the UI.
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= max
        && !trimmed.contains(|c: char| c.is_control())
}

/// Redacted router.json view for Profiles / Providers / Routing / Settings.
#[tauri::command]
fn get_config() -> Result<Value, String> {
    let root = controller::router_root();
    let path = root.join("router.json");
    let raw = std::fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let parsed: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("invalid router.json: {error}"))?;
    let mut out = serde_json::Map::new();
    for key in CONFIG_KEYS {
        if let Some(value) = parsed.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    Ok(Value::Object(out))
}

/// Live network detection: current Wi-Fi + the SSID -> preset mapping.
#[tauri::command]
fn get_network() -> Result<Value, String> {
    let root = controller::router_root();
    let status = controller::json_command(&root, &["network-status", "--json"])?;
    let presets = controller::json_command(&root, &["network-preset", "show"])?;
    Ok(serde_json::json!({ "status": status, "presets": presets }))
}

/// Map the current (or a named) Wi-Fi network to a preset.
#[tauri::command]
fn set_network_preset(ssid: String, preset: String) -> Result<Value, String> {
    if !valid_slug(&ssid, 255) {
        return Err("network name must be 1-255 characters without control characters".into());
    }
    if !valid_slug(&preset, 64) {
        return Err("preset name must be 1-64 characters of letters, digits, dot, dash or underscore".into());
    }
    let root = controller::router_root();
    controller::run_controller(&root, &["network-preset", "set", "--ssid", &ssid, "--preset", &preset])?;
    controller::json_command(&root, &["network-preset", "show"])
}

/// Enable or disable automatic preset switching on network change.
#[tauri::command]
fn set_network_auto(state: String) -> Result<Value, String> {
    if state != "on" && state != "off" {
        return Err("state must be 'on' or 'off'".into());
    }
    let root = controller::router_root();
    controller::run_controller(&root, &["network-preset", "auto", "--state", &state])?;
    controller::json_command(&root, &["network-preset", "show"])
}

/// Remove a Wi-Fi network's preset mapping.
#[tauri::command]
fn remove_network_preset(ssid: String) -> Result<Value, String> {
    if !valid_slug(&ssid, 255) {
        return Err("network name must be 1-255 characters without control characters".into());
    }
    let root = controller::router_root();
    controller::run_controller(&root, &["network-preset", "remove", "--ssid", &ssid])?;
    controller::json_command(&root, &["network-preset", "show"])
}

/// Effective routing mode and lists (`router.py routing show`).
#[tauri::command]
fn get_routing() -> Result<Value, String> {
    let root = controller::router_root();
    controller::json_command(&root, &["routing", "show"])
}

/// Switch the routing mode (safe-list | vpn-list | default).
#[tauri::command]
fn set_routing_mode(mode: String) -> Result<Value, String> {
    if !matches!(mode.as_str(), "safe-list" | "vpn-list" | "default") {
        return Err(format!("unsupported routing mode: {mode}"));
    }
    let root = controller::router_root();
    controller::run_controller(&root, &["routing", "set", "--mode", &mode])?;
    controller::json_command(&root, &["routing", "show"])
}

/// Add a domain route to a provider.
#[tauri::command]
fn add_route(domain: String, provider: String, id: Option<String>) -> Result<Value, String> {
    if !valid_slug(&domain, 253) || domain.contains("..") {
        return Err("domain must be a hostname of 1-253 characters".into());
    }
    if !valid_slug(&provider, 64) {
        return Err("provider must be 1-64 characters of letters, digits, dot, dash or underscore".into());
    }
    let root = controller::router_root();
    let mut args = vec!["add", "--domain", domain.as_str(), "--provider", provider.as_str()];
    if let Some(id) = id.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        if !valid_slug(id, 64) {
            return Err("route id must be 1-64 characters of letters, digits, dot, dash or underscore".into());
        }
        args.push("--id");
        args.push(id);
    }
    controller::run_controller(&root, &args)?;
    Ok(serde_json::json!({ "added": domain }))
}

/// Remove a route by id.
#[tauri::command]
fn remove_route(id: String) -> Result<Value, String> {
    if !valid_slug(&id, 64) {
        return Err("route id must be 1-64 characters of letters, digits, dot, dash or underscore".into());
    }
    let root = controller::router_root();
    controller::run_controller(&root, &["remove", &id])?;
    Ok(serde_json::json!({ "removed": id }))
}

/// Dashboard CRUD is served by a small allowlisted router.py surface. These
/// commands only write saved configuration; they never start or reload the
/// engine, so choosing or editing a profile cannot connect the machine.
fn dashboard_json(args: &[&str]) -> Result<Value, String> {
    let root = controller::router_root();
    let output = controller::run_controller(&root, args)?;
    serde_json::from_str(&output).map_err(|error| format!("invalid dashboard response: {error}"))
}

#[tauri::command]
fn get_dashboard_state() -> Result<Value, String> {
    dashboard_json(&["dashboard", "state"])
}

#[tauri::command]
fn save_dashboard_profile(profile: Value, profile_id: Option<String>) -> Result<Value, String> {
    let data = serde_json::to_string(&profile).map_err(|error| error.to_string())?;
    let root = controller::router_root();
    let mut args = vec!["dashboard", "profile-save", "--json", data.as_str()];
    if let Some(id) = profile_id.as_deref() {
        args.extend(["--id", id]);
    }
    let output = controller::run_controller(&root, &args)?;
    serde_json::from_str(&output).map_err(|error| format!("invalid dashboard response: {error}"))
}

#[tauri::command]
fn delete_dashboard_profile(profile_id: String) -> Result<Value, String> {
    dashboard_json(&["dashboard", "profile-delete", "--id", &profile_id])
}

#[tauri::command]
fn apply_dashboard_profile(profile_id: String) -> Result<Value, String> {
    dashboard_json(&["dashboard", "profile-apply", "--id", &profile_id])
}

#[tauri::command]
fn save_dashboard_provider(
    provider: Value,
    provider_id: Option<String>,
    source_path: Option<String>,
) -> Result<Value, String> {
    let data = serde_json::to_string(&provider).map_err(|error| error.to_string())?;
    let root = controller::router_root();
    let mut args = vec!["dashboard", "provider-save", "--json", data.as_str()];
    if let Some(id) = provider_id.as_deref() {
        args.extend(["--id", id]);
    }
    if let Some(path) = source_path.as_deref() {
        args.extend(["--path", path]);
    }
    let output = controller::run_controller(&root, &args)?;
    serde_json::from_str(&output).map_err(|error| format!("invalid dashboard response: {error}"))
}

#[tauri::command]
fn delete_dashboard_provider(provider_id: String) -> Result<Value, String> {
    dashboard_json(&["dashboard", "provider-delete", "--id", &provider_id])
}

#[tauri::command]
fn set_tray_status<R: Runtime>(app: AppHandle<R>, state: String) -> Result<(), String> {
    apply_tray_state(&app, &state)
}

fn main() {
    tauri::Builder::default()
        .manage(LaunchTime(Instant::now()))
        .manage(LiveStatus::default())
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            show_dashboard(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.handle()
                .set_activation_policy(tauri::ActivationPolicy::Accessory)?;

            let open = MenuItem::with_id(app, "open", "Open Dashboard", true, None::<&str>)?;
            let connect = MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?;
            let disconnect =
                MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;
            let rotate = MenuItem::with_id(app, "rotate", "Rotate exit", true, None::<&str>)?;
            let sweep = MenuItem::with_id(app, "sweep", "Health sweep", true, None::<&str>)?;
            let refresh = MenuItem::with_id(app, "refresh", "Refresh status", true, None::<&str>)?;
            // Presets and routing mode live in the tray too, so the classic
            // actions do not require opening the window.
            let mut preset_items = Vec::new();
            for name in ALLOWED_PRESETS {
                preset_items.push(MenuItem::with_id(
                    app, format!("preset:{name}"), name, true, None::<&str>)?);
            }
            let preset_refs: Vec<&dyn tauri::menu::IsMenuItem<_>> =
                preset_items.iter().map(|item| item as &dyn tauri::menu::IsMenuItem<_>).collect();
            let presets_menu = Submenu::with_items(app, "Presets", true, &preset_refs)?;

            let mut mode_items = Vec::new();
            for mode in ["safe-list", "vpn-list", "default"] {
                mode_items.push(MenuItem::with_id(
                    app, format!("routing:{mode}"), mode, true, None::<&str>)?);
            }
            let mode_refs: Vec<&dyn tauri::menu::IsMenuItem<_>> =
                mode_items.iter().map(|item| item as &dyn tauri::menu::IsMenuItem<_>).collect();
            let routing_menu = Submenu::with_items(app, "Routing mode", true, &mode_refs)?;
            let separator = PredefinedMenuItem::separator(app)?;
            let quit = MenuItem::with_id(app, "quit", "Quit Proxy Router", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &open, &connect, &disconnect, &rotate, &sweep, &refresh,
                    &presets_menu, &routing_menu, &separator, &quit,
                ],
            )?;

            let mut tray = TrayIconBuilder::with_id("proxy-router")
                .menu(&menu)
                .tooltip("Proxy Router")
                // A primary click should behave like a VPN client: reveal
                // the dashboard immediately. The context menu remains
                // available from the tray's secondary click.
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| {
                    let id = event.id().as_ref().to_string();
                    match id.as_str() {
                        "open" => show_dashboard(app),
                        "quit" => app.exit(0),
                        "refresh" => {
                            refresh_live_status(app, true);
                        }
                        _ if id.starts_with("preset:") => {
                            let handle = app.clone();
                            let name = id["preset:".len()..].to_string();
                            std::thread::spawn(move || {
                                if let Err(error) = apply_preset(handle.clone(), name) {
                                    eprintln!("tray preset failed: {error}");
                                }
                            });
                        }
                        _ if id.starts_with("routing:") => {
                            let handle = app.clone();
                            let mode = id["routing:".len()..].to_string();
                            std::thread::spawn(move || {
                                if let Err(error) = set_routing_mode(mode) {
                                    eprintln!("tray routing mode failed: {error}");
                                }
                                refresh_live_status(&handle, false);
                            });
                        }
                        action => {
                            // Controller calls can block: never stall the menu.
                            let handle = app.clone();
                            let action = action.to_string();
                            std::thread::spawn(move || {
                                if let Err(error) = run_router_action(handle.clone(), action) {
                                    eprintln!("tray action failed: {error}");
                                }
                            });
                        }
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_dashboard(tray.app_handle());
                    }
                });

            tray = tray.icon(tray_icon("disconnected").expect("bundled tray icon must decode"));
            tray.build(app)?;

            // Live status poller: keeps the tray truthful even while the
            // dashboard window is hidden or closed.
            let handle = app.handle().clone();
            thread::spawn(move || loop {
                refresh_live_status(&handle, false);
                thread::sleep(Duration::from_secs(POLL_SECONDS));
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_preview_status,
            get_live_status,
            cached_live_status,
            run_router_action,
            apply_preset,
            get_config,
            get_network,
            set_network_preset,
            set_network_auto,
            remove_network_preset,
            get_routing,
            set_routing_mode,
            add_route,
            remove_route,
            get_dashboard_state,
            save_dashboard_profile,
            delete_dashboard_profile,
            apply_dashboard_profile,
            save_dashboard_provider,
            delete_dashboard_provider,
            set_tray_status,
            preview_rendered
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.hide().is_ok() {
                    api.prevent_close();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("Unable to open dashboard preview");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_returns_only_the_fixture_contract() {
        let status = get_preview_status().unwrap();
        assert_eq!(status["version"], 1);
        assert_eq!(status["source"], "fixture");
        assert_eq!(status["route_mode"], "selective");
        assert_eq!(status.as_object().unwrap().len(), 11);
    }

    #[test]
    fn tray_assets_cover_the_connection_states() {
        for state in ["connected", "disconnected", "degraded", "failed", "offline"] {
            assert_eq!(tray_icon_bytes(state).len(), 32 * 32 * 4);
            assert_eq!(
                tray_icon(state).expect("tray asset").rgba().len(),
                32 * 32 * 4
            );
        }
    }

    #[test]
    fn tray_tooltips_are_specific_per_state() {
        assert_eq!(
            tray_tooltip("connected").unwrap(),
            "Proxy Router · Connected"
        );
        assert!(tray_tooltip("degraded").unwrap().contains("attention"));
        assert!(tray_tooltip("failed").unwrap().contains("unavailable"));
        assert!(tray_tooltip("disconnected")
            .unwrap()
            .contains("Disconnected"));
        assert!(tray_tooltip("nonsense").is_err());
    }

    #[test]
    fn tray_actions_are_whitelisted() {
        let payload = serde_json::json!({"active_providers": {"proton": "13-US-FREE-2"}});
        assert_eq!(action_args("connect", None).unwrap(), vec!["start"]);
        assert_eq!(action_args("sweep", None).unwrap(), vec!["egress", "sweep"]);
        assert_eq!(
            action_args("rotate", Some(&payload)).unwrap(),
            vec!["rotate", "proton"]
        );
        // Unrouted tray verbs stay out on purpose; disconnect is a UI action
        // (main-thread command), not a tray-menu verb.
        assert!(action_args("stop", None).is_err());
        assert!(action_args("rotate", Some(&serde_json::json!({}))).is_err());
    }
}
