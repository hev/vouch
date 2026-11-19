//! The review panel as a child process, held open for exactly as long as the
//! Touch ID sheet.
//!
//! `AppKit` wants the main thread and a run loop; the agent's main thread is
//! its request loop. So the panel runs as `vouch-agent panel`, a child that
//! reads one [`PanelView`] as JSON on stdin and draws it. The agent starts it
//! when the permit is taken (see [`crate::touchid::Companion`]) and kills it
//! when the sheet resolves. A child that exits by itself with
//! [`vouch_panel::EXIT_DENIED`] was told Esc or Deny, and the attempt is
//! cancelled; any other exit, a crash included, changes nothing — the sheet
//! is still the only approval.

use std::io::Write as _;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::warn;
use vouch_panel::PanelView;

use crate::touchid::Companion;

/// Environment variable that turns the panel off (`0`, `off`, `false`).
pub const PANEL_ENV: &str = "VOUCH_PANEL";

/// Whether the panel is enabled in this process's environment.
pub fn panel_enabled() -> bool {
    !matches!(
        std::env::var(PANEL_ENV).ok().as_deref().map(str::trim),
        Some("0" | "off" | "false" | "no")
    )
}

/// Opens one view in a child `vouch-agent panel` process.
pub struct PanelProcess {
    view: PanelView,
}

impl PanelProcess {
    pub fn new(view: PanelView) -> Self {
        Self { view }
    }
}

struct Open {
    child: Arc<Mutex<Option<Child>>>,
    closed: Arc<AtomicBool>,
}

impl Drop for Open {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.child.lock()
            && let Some(mut child) = guard.take()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Companion for PanelProcess {
    fn open(&self, deny: Box<dyn Fn() + Send + Sync>) -> Box<dyn Send> {
        let closed = Arc::new(AtomicBool::new(false));
        let child = Arc::new(Mutex::new(spawn(&self.view)));
        let watcher = {
            let (child, closed) = (Arc::clone(&child), Arc::clone(&closed));
            move || {
                while !closed.load(Ordering::SeqCst) {
                    let status = {
                        let Ok(mut guard) = child.lock() else { return };
                        let Some(process) = guard.as_mut() else {
                            return;
                        };
                        match process.try_wait() {
                            Ok(Some(status)) => {
                                guard.take();
                                Some(status)
                            }
                            Ok(None) => None,
                            Err(_) => return,
                        }
                    };
                    if let Some(status) = status {
                        if status.code() == Some(vouch_panel::EXIT_DENIED)
                            && !closed.load(Ordering::SeqCst)
                        {
                            deny();
                        }
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        };
        if child.lock().is_ok_and(|guard| guard.is_some()) {
            std::thread::spawn(watcher);
        }
        Box::new(Open { child, closed })
    }
}

fn spawn(view: &PanelView) -> Option<Child> {
    let json = match serde_json::to_vec(view) {
        Ok(json) => json,
        Err(error) => {
            warn!(%error, "could not encode the review panel");
            return None;
        }
    };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            warn!(%error, "could not find this executable to open the review panel");
            return None;
        }
    };
    let mut child = match Command::new(exe)
        .arg("panel")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            warn!(%error, "could not open the review panel; the Touch ID sheet still decides");
            return None;
        }
    };
    if let Some(mut stdin) = child.stdin.take()
        && let Err(error) = stdin.write_all(&json)
    {
        warn!(%error, "could not hand the request to the review panel");
    }
    Some(child)
}
