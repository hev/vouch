//! The review panel that sits beside the Touch ID sheet.
//!
//! The sheet belongs to macOS: one string, capped, with no layout. The panel
//! is ours. It answers three questions in a fixed order — who is asking, why
//! they say they are asking, and what will actually run — and it costs no
//! click: Touch ID on the sheet is the only approval, and the panel has no
//! Approve button at all. Esc or its Deny button cancels the attempt.
//!
//! This crate holds the panel's data model, which every platform builds and
//! tests, and on macOS the `AppKit` window that draws it. Every string in a
//! [`PanelView`] has already been escaped by whoever built it (the agent uses
//! `escape_for_terminal`); the window never interprets text as markup.

use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
mod appkit;

#[cfg(target_os = "macos")]
pub use appkit::run_panel;

/// Exit status of a panel process whose operator pressed Esc or Deny.
pub const EXIT_DENIED: i32 = 10;
/// Exit status of a panel process that reached its own deadline.
pub const EXIT_EXPIRED: i32 = 0;

/// Everything the panel shows, already escaped and formatted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelView {
    /// "sudo request", "sudo authentication", or "tool permission".
    pub kind: String,
    /// Unix seconds the request was issued; with `expires_at`, sizes the
    /// countdown bar.
    pub issued_at: i64,
    /// Unix seconds after which the request is dead and the panel closes.
    pub expires_at: i64,
    pub who: Who,
    /// The agent's own words. `None` shows "No reason given."
    pub why: Option<String>,
    pub what: What,
}

/// The first section: the session as the headline, then where it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Who {
    pub session: String,
    pub chips: Vec<Chip>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chip {
    pub text: String,
    pub tone: ChipTone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChipTone {
    /// How the session runs: tmux, headless.
    Context,
    /// Harness, cwd, this Mac.
    Plain,
    /// A host other than this Mac, in a warmer colour.
    Remote,
}

/// The third section: what the signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct What {
    /// "What will run" or "What it wants".
    pub heading: String,
    /// Small text after the heading: "verified, signed exactly",
    /// "contextual PAM", or "Edit · path".
    pub badge: Option<String>,
    /// A shell-style line: prompt, then `sudo`, then the argv.
    pub command: Option<CommandLine>,
    /// A code block: a diff, a Bash command, a URL.
    pub code: Vec<CodeLine>,
    /// Label and value rows: as, cwd, tty.
    pub rows: Vec<(String, String)>,
    /// The bound environment, collapsed behind "N variables · show".
    pub env: Vec<String>,
    /// A caveat under the block, such as contextual PAM's.
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandLine {
    /// `root@host $ `
    pub prompt: String,
    /// Shown in the warning colour; `sudo`, or empty.
    pub verb: String,
    pub rest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeLine {
    pub text: String,
    pub kind: CodeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeKind {
    Plain,
    Added,
    Removed,
    Context,
}

/// "No reason given." — the gap is stated, never hidden.
pub const NO_REASON: &str = "No reason given.";
/// The label beside the reason, so it is never read as verified.
pub const WHY_CAVEAT: &str = "the agent's own words, not verified";

impl PanelView {
    /// `m:ss` until `expires_at`, never negative.
    pub fn countdown(&self, now: i64) -> String {
        let left = (self.expires_at - now).max(0);
        format!("{}:{:02}", left / 60, left % 60)
    }

    /// Share of the request's lifetime still left, from 0.0 to 1.0.
    pub fn remaining_fraction(&self, now: i64) -> f64 {
        let total = (self.expires_at - self.issued_at).max(1);
        let left = (self.expires_at - now).clamp(0, total);
        #[allow(clippy::cast_precision_loss)]
        let fraction = left as f64 / total as f64;
        fraction
    }

    /// The env row's collapsed text.
    pub fn env_summary(&self) -> Option<String> {
        match self.what.env.len() {
            0 => None,
            1 => Some("1 variable".to_owned()),
            count => Some(format!("{count} variables")),
        }
    }

    /// The panel as plain text, top to bottom, the way the window lays it
    /// out. Tests read this; so can a terminal.
    pub fn text(&self, now: i64) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "vouch  {}  {}", self.kind, self.countdown(now));
        let _ = writeln!(out, "WHO'S ASKING");
        let _ = writeln!(out, "  {}", self.who.session);
        let chips: Vec<_> = self
            .who
            .chips
            .iter()
            .map(|chip| chip.text.as_str())
            .collect();
        if !chips.is_empty() {
            let _ = writeln!(out, "  [{}]", chips.join("] ["));
        }
        if let Some(why) = &self.why {
            let _ = writeln!(out, "WHY ({WHY_CAVEAT})");
            let _ = writeln!(out, "  {why}");
        } else {
            let _ = writeln!(out, "WHY");
            let _ = writeln!(out, "  {NO_REASON}");
        }
        match &self.what.badge {
            Some(badge) => {
                let _ = writeln!(out, "{} ({badge})", self.what.heading.to_uppercase());
            }
            None => {
                let _ = writeln!(out, "{}", self.what.heading.to_uppercase());
            }
        }
        if let Some(command) = &self.what.command {
            let _ = writeln!(out, "  {}{} {}", command.prompt, command.verb, command.rest);
        }
        for line in &self.what.code {
            let _ = writeln!(out, "  {}", line.text);
        }
        for (label, value) in &self.what.rows {
            let _ = writeln!(out, "  {label:<4} {value}");
        }
        if let Some(summary) = self.env_summary() {
            let _ = writeln!(out, "  env  {summary} (collapsed)");
        }
        if let Some(note) = &self.what.note {
            let _ = writeln!(out, "  {note}");
        }
        let _ = writeln!(out, "Touch ID to approve · esc deny");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> PanelView {
        PanelView {
            kind: "sudo request".into(),
            issued_at: 1_000,
            expires_at: 1_090,
            who: Who {
                session: "foh-hev-4".into(),
                chips: vec![Chip {
                    text: "tmux".into(),
                    tone: ChipTone::Context,
                }],
            },
            why: None,
            what: What {
                heading: "What will run".into(),
                badge: None,
                command: None,
                code: vec![],
                rows: vec![],
                env: vec!["PATH=/usr/bin".into(), "HOME=/var/root".into()],
                note: None,
            },
        }
    }

    #[test]
    fn countdown_counts_down_and_stops_at_zero() {
        let view = view();
        assert_eq!(view.countdown(1_000), "1:30");
        assert_eq!(view.countdown(1_047), "0:43");
        assert_eq!(view.countdown(2_000), "0:00");
        assert!((view.remaining_fraction(1_045) - 0.5).abs() < f64::EPSILON);
        assert!(view.remaining_fraction(5_000).abs() < f64::EPSILON);
    }

    #[test]
    fn a_missing_reason_is_stated() {
        let text = view().text(1_000);
        assert!(text.contains("WHY\n  No reason given."), "{text}");
        assert!(!text.contains(WHY_CAVEAT), "{text}");
    }

    #[test]
    fn env_is_collapsed_to_a_count() {
        assert_eq!(view().env_summary().as_deref(), Some("2 variables"));
        assert!(view().text(1_000).contains("env  2 variables (collapsed)"));
    }

    #[test]
    fn the_view_round_trips_as_json() {
        let view = view();
        let json = serde_json::to_string(&view).unwrap();
        assert_eq!(serde_json::from_str::<PanelView>(&json).unwrap(), view);
    }
}
