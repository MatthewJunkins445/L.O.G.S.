// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::Mutex,
    time::Duration,
};
use tauri::Manager;
use tauri_plugin_shell::{process::CommandChild, ShellExt};

struct AppState {
    backend_child: Mutex<Option<CommandChild>>,
}

const BACKEND_HOST: &str = "127.0.0.1";
const BACKEND_PORT: u16 = 8080;

#[tauri::command]
fn check_backend_health() -> Result<String, String> {
    if backend_is_healthy() {
        Ok("Backend is healthy".to_string())
    } else {
        Err("Backend is not responding".to_string())
    }
}

fn backend_is_healthy() -> bool {
    let addr = match (BACKEND_HOST, BACKEND_PORT).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => return false,
        },
        Err(_) => return false,
    };

    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(350)) {
        Ok(stream) => stream,
        Err(_) => return false,
    };

    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

    let request = format!(
        "GET /api/health HTTP/1.1\r\nHost: {BACKEND_HOST}:{BACKEND_PORT}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }

    let mut response = String::new();
    stream.read_to_string(&mut response).is_ok() && response.starts_with("HTTP/1.1 200")
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            app.manage(AppState {
                backend_child: Mutex::new(None),
            });

            if backend_is_healthy() {
                println!(
                    "[Backend] Existing healthy backend detected on {BACKEND_HOST}:{BACKEND_PORT}"
                );
                return Ok(());
            }

            let sidecar_command = app.shell().sidecar("secureshield-backend")?;
            let (mut rx, child) = sidecar_command.spawn()?;

            if let Some(state) = app.try_state::<AppState>() {
                if let Ok(mut backend_child) = state.backend_child.lock() {
                    *backend_child = Some(child);
                }
            }

            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        tauri_plugin_shell::process::CommandEvent::Stdout(line) => {
                            println!("[Backend] {}", String::from_utf8_lossy(&line));
                        }
                        tauri_plugin_shell::process::CommandEvent::Stderr(line) => {
                            eprintln!("[Backend] {}", String::from_utf8_lossy(&line));
                        }
                        tauri_plugin_shell::process::CommandEvent::Terminated(payload) => {
                            println!("[Backend] Terminated: {:?}", payload);
                            break;
                        }
                        _ => {}
                    }
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                if window.app_handle().webview_windows().is_empty() {
                    if let Some(state) = window.app_handle().try_state::<AppState>() {
                        if let Ok(mut child) = state.backend_child.lock() {
                            if let Some(c) = child.take() {
                                let _ = c.kill();
                            }
                        }
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![check_backend_health])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
