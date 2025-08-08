use std::{process::Stdio, sync::{Arc, Mutex}};
use tauri::{Emitter, Manager, State};

struct NodeProcess(Arc<Mutex<Option<tauri::process::CommandChild>>>);

#[tauri::command]
async fn start_node(state: State<'_, NodeProcess>, handle: tauri::AppHandle, args: Option<Vec<String>>) -> Result<(), String> {
  let mut guard = state.0.lock().unwrap();
  if guard.is_some() { return Ok(()); }
  let bin = std::env::var("UNCHAINED_BIN").unwrap_or_else(|_| "/workspace/target/release/unchained".into());
  let mut cmd = tauri::process::Command::new(bin);
  if let Some(a) = args { cmd = cmd.args(a); }
  let (mut rx, child) = cmd
    .stdin(Stdio::null())
    .stderr(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn()
    .map_err(|e| e.to_string())?;
  let app = handle.clone();
  tauri::async_runtime::spawn(async move {
    while let Some(event) = rx.recv().await {
      match event {
        tauri::process::CommandEvent::Stdout(line) => { let _ = app.emit("node:stdout", line); }
        tauri::process::CommandEvent::Stderr(line) => { let _ = app.emit("node:stderr", line); }
        tauri::process::CommandEvent::Terminated(payload) => { let _ = app.emit("node:exit", payload.code.unwrap_or_default()); break; }
        _ => {}
      }
    }
  });
  *guard = Some(child);
  Ok(())
}

#[tauri::command]
async fn stop_node(state: State<'_, NodeProcess>) -> Result<(), String> {
  let mut guard = state.0.lock().unwrap();
  if let Some(child) = guard.as_mut() {
    child.kill().map_err(|e| e.to_string())?;
  }
  *guard = None;
  Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .manage(NodeProcess(Arc::new(Mutex::new(None))))
    .invoke_handler(tauri::generate_handler![start_node, stop_node])
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
