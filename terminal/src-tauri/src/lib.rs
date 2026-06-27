// Each tab is an independent PTY session, keyed by its server terminal id, and
// mirrored to the Go relay so mobile can view/control any of them. The relay
// only ever sees ciphertext; the account key is shared across all sessions.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

mod crypto;

use futures_util::{SinkExt, StreamExt};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_tungstenite::{connect_async, tungstenite::Message};

type Writer = Arc<Mutex<Box<dyn Write + Send>>>;

struct SessionState {
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Writer,
    relay_tx: Mutex<Option<UnboundedSender<Vec<u8>>>>, // outgoing plaintext -> relay task
}

struct Shared {
    sessions: Mutex<HashMap<String, Arc<SessionState>>>,
    key: Mutex<crypto::AccountKey>, // shared account key (pairing can replace it)
}

impl Shared {
    fn new(key: crypto::AccountKey) -> Self {
        Shared { sessions: Mutex::new(HashMap::new()), key: Mutex::new(key) }
    }
    fn session(&self, id: &str) -> Option<Arc<SessionState>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }
}

// pty:data / pty:exit carry the session id so the right xterm tab consumes them.
#[derive(Clone, Serialize)]
struct PtyData {
    session: String,
    data: Vec<u8>,
}

#[derive(Clone, Serialize)]
struct PtyExit {
    session: String,
}

#[tauri::command]
fn pty_spawn(
    app: AppHandle,
    shared: State<Arc<Shared>>,
    id: String,
    cmd: Option<String>,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let pair = native_pty_system()
        .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
        .map_err(|e| e.to_string())?;

    let program = cmd.unwrap_or_else(|| std::env::var("SHELL").unwrap_or_else(|_| "zsh".into()));
    let mut builder = CommandBuilder::new(program);
    if let Some(home) = std::env::var_os("HOME") {
        builder.cwd(home);
    }
    builder.env("TERM", "xterm-256color");

    let _child = pair.slave.spawn_command(builder).map_err(|e| e.to_string())?;
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer: Writer = Arc::new(Mutex::new(pair.master.take_writer().map_err(|e| e.to_string())?));

    let state = Arc::new(SessionState {
        master: Mutex::new(pair.master),
        writer,
        relay_tx: Mutex::new(None),
    });
    shared.sessions.lock().unwrap().insert(id.clone(), Arc::clone(&state));

    // Per-session reader thread: forward bytes to the UI tab and, if connected, the relay.
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = app.emit("pty:exit", PtyExit { session: id.clone() });
                    break;
                }
                Ok(n) => {
                    let chunk = buf[..n].to_vec();
                    if app.emit("pty:data", PtyData { session: id.clone(), data: chunk.clone() }).is_err() {
                        break;
                    }
                    if let Some(tx) = state.relay_tx.lock().unwrap().as_ref() {
                        let _ = tx.send(chunk);
                    }
                }
            }
        }
    });
    Ok(())
}

#[tauri::command]
fn pty_write(shared: State<Arc<Shared>>, id: String, data: Vec<u8>) -> Result<(), String> {
    let state = shared.session(&id).ok_or("no session")?;
    write_session(&state, &data)
}

#[tauri::command]
fn pty_resize(shared: State<Arc<Shared>>, id: String, cols: u16, rows: u16) -> Result<(), String> {
    let state = shared.session(&id).ok_or("no session")?;
    let master = state.master.lock().unwrap();
    master
        .resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn pty_close(shared: State<Arc<Shared>>, id: String) {
    shared.sessions.lock().unwrap().remove(&id); // dropping the master closes the PTY
}

fn write_session(state: &Arc<SessionState>, data: &[u8]) -> Result<(), String> {
    let mut w = state.writer.lock().unwrap();
    w.write_all(data).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())
}

// relay_connect mirrors one session through the Go relay, reconnecting forever
// with capped backoff. ponytail: host treats every inbound frame as stdin — the
// server's single-host guard keeps a second host off this terminal.
#[tauri::command]
fn relay_connect(
    shared: State<Arc<Shared>>,
    id: String,
    url: String,
    token: String,
    terminal: String,
) -> Result<(), String> {
    let state = shared.session(&id).ok_or("no session")?;
    let shared = Arc::clone(&shared);
    tauri::async_runtime::spawn(async move {
        let mut backoff = 1u64;
        loop {
            if let Ok((ws, _)) = connect_async(&url).await {
                backoff = 1;
                let (mut sink, mut stream) = ws.split();
                let hello = format!(
                    r#"{{"type":"hello","token":"{token}","terminal":"{terminal}","role":"host"}}"#
                );
                if sink.send(Message::Text(hello.into())).await.is_ok() {
                    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    *state.relay_tx.lock().unwrap() = Some(tx);

                    let send_shared = Arc::clone(&shared);
                    let send_task = tauri::async_runtime::spawn(async move {
                        while let Some(bytes) = rx.recv().await {
                            let frame = crypto::seal(&send_shared.key.lock().unwrap(), &bytes);
                            if sink.send(Message::Binary(frame.into())).await.is_err() {
                                break;
                            }
                        }
                    });

                    while let Some(Ok(msg)) = stream.next().await {
                        if let Message::Binary(frame) = msg {
                            let key = *shared.key.lock().unwrap();
                            if let Some(plain) = crypto::open(&key, &frame) {
                                let _ = write_session(&state, &plain);
                            }
                        }
                    }
                    state.relay_tx.lock().unwrap().take();
                    send_task.abort();
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
        }
    });
    Ok(())
}

// Show this device's account key so a second device can pair by pasting it.
#[tauri::command]
fn pairing_code(shared: State<Arc<Shared>>) -> String {
    crypto::pairing_code(&shared.key.lock().unwrap())
}

// Adopt an account key from another device's pairing code.
#[tauri::command]
fn set_account_key(shared: State<Arc<Shared>>, code: String) -> Result<(), String> {
    let key = crypto::key_from_code(&code).ok_or("invalid pairing code")?;
    *shared.key.lock().unwrap() = key;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
            let key = crypto::load_or_create_key(dir)?;
            app.manage(Arc::new(Shared::new(key)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            pty_spawn,
            pty_write,
            pty_resize,
            pty_close,
            relay_connect,
            pairing_code,
            set_account_key
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
