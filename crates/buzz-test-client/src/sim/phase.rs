//! Phase lines: one JSON object per line on stdout, and the same line
//! appended to `<out-dir>/phases.jsonl` once the run has an output folder.
//! Under a service manager stdout goes to a journal mixed with the logs and
//! the summary, so a band driver reads the file instead.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

static FILE: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Sends every later phase line to `path` too, starting it empty.
pub fn set_file(path: PathBuf) -> std::io::Result<()> {
    std::fs::write(&path, b"")?;
    *FILE.lock().unwrap_or_else(|p| p.into_inner()) = Some(path);
    Ok(())
}

/// Prints `line` on stdout, flushed, and appends it to the phases file. A
/// failed append is logged; the line is still on stdout.
pub fn emit(line: &serde_json::Value) {
    println!("{line}");
    let _ = std::io::stdout().flush();
    let file = FILE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(path) = file.as_ref() {
        let res = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .and_then(|mut f| f.write_all(format!("{line}\n").as_bytes()));
        if let Err(e) = res {
            tracing::warn!("phases file {}: {e}", path.display());
        }
    }
}
