//! Line-oriented terminal prompts. `install.sh` execs setup with `</dev/tty`,
//! so stdin is the terminal even under `curl | sh`.

use std::io::{self, BufRead, Write};
use std::process::{Command, Stdio};

use anyhow::Context;

fn read_line() -> anyhow::Result<String> {
    let mut line = String::new();
    let n = io::stdin().lock().read_line(&mut line).context("reading from stdin")?;
    anyhow::ensure!(n > 0, "stdin closed: setup is interactive, run it from a terminal");
    Ok(line.trim().to_string())
}

fn show(prompt: &str) -> anyhow::Result<()> {
    print!("{prompt}");
    io::stdout().flush()?;
    Ok(())
}

/// Free-text answer; Enter accepts `default`.
pub fn ask(question: &str, default: &str) -> anyhow::Result<String> {
    if default.is_empty() {
        show(&format!("{question}: "))?;
    } else {
        show(&format!("{question} [{default}]: "))?;
    }
    let answer = read_line()?;
    Ok(if answer.is_empty() { default.to_string() } else { answer })
}

/// `ask` repeated until `parse` accepts the answer.
pub fn ask_with<T>(
    question: &str,
    default: &str,
    parse: impl Fn(&str) -> Result<T, String>,
) -> anyhow::Result<T> {
    loop {
        let answer = ask(question, default)?;
        match parse(&answer) {
            Ok(v) => return Ok(v),
            Err(msg) => eprintln!("  {msg}"),
        }
    }
}

pub fn ask_bool(question: &str, default: bool) -> anyhow::Result<bool> {
    let hint = if default { "Y/n" } else { "y/N" };
    loop {
        show(&format!("{question} [{hint}]: "))?;
        match read_line()?.to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("  answer y or n"),
        }
    }
}

/// Hidden input. Enter keeps `existing`; with no existing value an answer is required.
pub fn ask_secret(question: &str, existing: Option<&str>) -> anyhow::Result<String> {
    let existing = existing.filter(|s| !s.is_empty());
    loop {
        if let Some(current) = existing {
            show(&format!("{question} [Enter keeps the current one, {}]: ", mask(current)))?;
        } else {
            show(&format!("{question}: "))?;
        }
        let answer = {
            let _echo = EchoOff::new();
            read_line()
        };
        // The user's Enter was not echoed.
        println!();
        let answer = answer?;
        if !answer.is_empty() {
            return Ok(answer);
        }
        if let Some(current) = existing {
            return Ok(current.to_string());
        }
        eprintln!("  a value is required");
    }
}

/// `…abcd`: enough to recognize a stored secret, not to use it.
fn mask(secret: &str) -> String {
    let tail: String = secret.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    if secret.chars().count() <= 8 {
        "set".to_string()
    } else {
        format!("ending in {tail}")
    }
}

/// Numbered menu; accepts the number or the option text. Returns the index.
pub fn ask_choice(question: &str, options: &[&str], default: usize) -> anyhow::Result<usize> {
    anyhow::ensure!(default < options.len(), "invalid default choice");
    println!("{question}:");
    for (i, opt) in options.iter().enumerate() {
        println!("  {}) {opt}", i + 1);
    }
    loop {
        show(&format!("Choose [{}]: ", options[default]))?;
        let answer = read_line()?.to_ascii_lowercase();
        if answer.is_empty() {
            return Ok(default);
        }
        if let Ok(n) = answer.parse::<usize>() {
            if (1..=options.len()).contains(&n) {
                return Ok(n - 1);
            }
        }
        if let Some(i) = options.iter().position(|o| o.eq_ignore_ascii_case(&answer)) {
            return Ok(i);
        }
        eprintln!("  enter a number from 1 to {} or an option name", options.len());
    }
}

/// Disables terminal echo for its lifetime. When stdin is not a terminal
/// `stty` fails and input is simply read with echo (nothing to hide it on).
struct EchoOff {
    active: bool,
}

impl EchoOff {
    fn new() -> Self {
        let active = Command::new("stty")
            .arg("-echo")
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        Self { active }
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        if self.active {
            let _ = Command::new("stty").arg("echo").stderr(Stdio::null()).status();
        }
    }
}
