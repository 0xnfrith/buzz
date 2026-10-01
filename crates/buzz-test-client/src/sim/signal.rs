//! The band signal: what a band driver tells a running `tenant_sim`, one line
//! at a time, on stdin or on a fifo in the output folder.
//!
//! | Line | Means |
//! |---|---|
//! | `continue [lease]` | setup is done on the driver's side: connect the population |
//! | `band <name> [lease]` | move to that band (`<name>` alone is the same, without a lease) |
//! | `ramp <k> <lease>` | switch on the first k identities of a ramp |
//! | `stop` | end the run |
//!
//! A lease is whole seconds, 1 to 86400. **A run stops on its own when the
//! last lease it was given runs out** with no newer signal: a driver that
//! died can't leave the load running. On a fifo, a `band` or `ramp` line
//! must carry one. A line that can't be read is refused with a phase line
//! (`signal-refused`) and changes nothing.
//!
//! **Stdin** ends the run at its end, as when a driver that started
//! `tenant_sim` went away. **A fifo** is opened again after each writer
//! closes it, so a driver can send each line with its own short-lived
//! writer.

use std::io::BufRead;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use tokio::sync::{oneshot, watch};

use super::phase;
use super::roles::Band;

/// The longest lease a signal may carry.
pub const MAX_LEASE: Duration = Duration::from_secs(86_400);

/// One signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Continue,
    Band(Band),
    Ramp(usize),
    Stop,
}

/// A signal and the lease it carries, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line {
    pub signal: Signal,
    pub lease: Option<Duration>,
}

fn lease(s: &str) -> std::result::Result<Duration, String> {
    let secs: u64 = s
        .parse()
        .map_err(|_| format!("lease {s:?} is not whole seconds"))?;
    let d = Duration::from_secs(secs);
    if secs == 0 || d > MAX_LEASE {
        return Err(format!(
            "lease {secs} s is not 1 to {}",
            MAX_LEASE.as_secs()
        ));
    }
    Ok(d)
}

/// Reads one line. `fifo`: band and ramp lines need a lease.
pub fn parse(line: &str, fifo: bool) -> std::result::Result<Line, String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let (signal, rest) = match words.as_slice() {
        ["continue", rest @ ..] => (Signal::Continue, rest),
        ["stop"] => (Signal::Stop, &[][..]),
        ["ramp", k, rest @ ..] => {
            let k = k
                .parse()
                .map_err(|_| format!("ramp {k:?} is not a whole number of identities"))?;
            (Signal::Ramp(k), rest)
        }
        ["band", name, rest @ ..] => match Band::parse(name) {
            Some(Band::Stop) => (Signal::Stop, rest),
            Some(b) => (Signal::Band(b), rest),
            None => return Err(format!("unknown band {name:?}")),
        },
        [name] => match Band::parse(name) {
            Some(Band::Stop) => (Signal::Stop, &[][..]),
            Some(b) => (Signal::Band(b), &[][..]),
            None => return Err(format!("unknown signal {name:?}")),
        },
        _ => return Err("unknown signal".into()),
    };
    let lease = match rest {
        [] => None,
        [l] => Some(lease(l)?),
        _ => return Err("more than one lease".into()),
    };
    if fifo && lease.is_none() && matches!(signal, Signal::Band(_) | Signal::Ramp(_)) {
        return Err("a band or ramp signal on a fifo needs a lease".into());
    }
    Ok(Line { signal, lease })
}

/// Why a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// A `stop` signal.
    Stop,
    /// The last lease ran out with no newer signal.
    Lease,
    /// Stdin ended without a `stop`.
    Eof,
}

impl Ended {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Lease => "lease",
            Self::Eof => "eof",
        }
    }
}

/// Where phase lines go: [`phase::emit`], or a test's recorder.
type Emit = Box<dyn Fn(&serde_json::Value) + Send + Sync>;

struct Shared {
    emit: Emit,
    band: watch::Sender<Band>,
    ramp: watch::Sender<usize>,
    go: Mutex<Option<oneshot::Sender<()>>>,
    deadline: Mutex<Option<Instant>>,
    ended: Mutex<Option<Ended>>,
}

impl Shared {
    /// Ends the run, once: the first reason is kept.
    fn end(&self, why: Ended) {
        let mut ended = self.ended.lock().unwrap_or_else(|p| p.into_inner());
        if ended.is_none() {
            *ended = Some(why);
        }
        drop(ended);
        let _ = self.band.send(Band::Stop);
    }

    fn ended(&self) -> Option<Ended> {
        *self.ended.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Acts on one line; true when the run has ended.
    fn take(&self, raw: &str, fifo: bool) -> bool {
        let raw = raw.trim();
        if raw.is_empty() {
            return false;
        }
        let line = match parse(raw, fifo) {
            Ok(l) => l,
            Err(why) => {
                eprintln!("tenant_sim: band signal {raw:?} refused: {why}");
                (self.emit)(
                    &serde_json::json!({"phase": "signal-refused", "line": raw, "why": why}),
                );
                return false;
            }
        };
        if let Some(d) = line.lease {
            *self.deadline.lock().unwrap_or_else(|p| p.into_inner()) = Some(Instant::now() + d);
        }
        match line.signal {
            Signal::Continue => {
                if let Some(go) = self.go.lock().unwrap_or_else(|p| p.into_inner()).take() {
                    let _ = go.send(());
                }
            }
            Signal::Band(b) => {
                let _ = self.band.send(b);
            }
            Signal::Ramp(k) => {
                let _ = self.ramp.send(k);
            }
            Signal::Stop => {
                self.end(Ended::Stop);
                return true;
            }
        }
        false
    }
}

/// What the population watches: the band, how many ramp identities are on,
/// the one-shot `continue` after setup, and why the run ended.
pub struct Control {
    pub band: watch::Receiver<Band>,
    pub ramp: watch::Receiver<usize>,
    /// Taken once, to wait for `continue`.
    pub go: Option<oneshot::Receiver<()>>,
    shared: Arc<Shared>,
}

impl Control {
    pub fn ended(&self) -> Option<Ended> {
        self.shared.ended()
    }
}

/// Starts reading signals from `kind` (stdin or fifo; the fifo is
/// `<out_dir>/band.fifo`) before setup, so `continue` is never missed, and
/// a watchdog that ends the run when the last lease runs out. `ramp_start`
/// identities of a ramp are on before any `ramp` signal.
pub fn spawn(kind: &str, out_dir: &Path, ramp_start: usize) -> Result<Control> {
    let fifo = match kind {
        "fifo" => {
            let path = out_dir.join("band.fifo");
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            let status = std::process::Command::new("mkfifo").arg(&path).status()?;
            if !status.success() {
                bail!("mkfifo {} failed", path.display());
            }
            Some(path)
        }
        "stdin" => None,
        other => bail!("--band-signal {other:?}: it is stdin or fifo"),
    };
    let (band_tx, band_rx) = watch::channel(Band::Warmup);
    let (ramp_tx, ramp_rx) = watch::channel(ramp_start);
    let (go_tx, go_rx) = oneshot::channel();
    let shared = Arc::new(Shared {
        emit: Box::new(phase::emit),
        band: band_tx,
        ramp: ramp_tx,
        go: Mutex::new(Some(go_tx)),
        deadline: Mutex::new(None),
        ended: Mutex::new(None),
    });
    {
        let shared = shared.clone();
        std::thread::spawn(move || read(shared, fifo));
    }
    {
        let shared = shared.clone();
        std::thread::spawn(move || watchdog(shared, Duration::from_millis(500)));
    }
    Ok(Control {
        band: band_rx,
        ramp: ramp_rx,
        go: Some(go_rx),
        shared,
    })
}

/// Takes `r`'s lines until one ends the run; true if one did.
fn read_from(shared: &Shared, r: impl BufRead, fifo: bool) -> bool {
    for line in r.lines() {
        let Ok(line) = line else { break };
        if shared.take(&line, fifo) {
            return true;
        }
    }
    false
}

/// Stdin: its end without a `stop` ends the run (the driver went away).
fn read_stdin(shared: &Shared, r: impl BufRead) {
    if !read_from(shared, r, false) {
        shared.end(Ended::Eof);
    }
}

fn read(shared: Arc<Shared>, fifo: Option<std::path::PathBuf>) {
    match fifo {
        None => read_stdin(&shared, std::io::BufReader::new(std::io::stdin())),
        // Opening a fifo blocks until a writer opens it; each writer's
        // close is the end of its lines, never of the run.
        Some(path) => loop {
            let file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("tenant_sim: open {}: {e}", path.display());
                    return;
                }
            };
            if read_from(&shared, std::io::BufReader::new(file), true) {
                return;
            }
            if shared.ended().is_some() {
                return;
            }
        },
    }
}

fn watchdog(shared: Arc<Shared>, every: Duration) {
    loop {
        std::thread::sleep(every);
        if shared.ended().is_some() {
            return;
        }
        let due = *shared.deadline.lock().unwrap_or_else(|p| p.into_inner());
        if due.is_some_and(|d| Instant::now() >= d) {
            (shared.emit)(&serde_json::json!({"phase": "lease-ran-out"}));
            eprintln!("tenant_sim: the band lease ran out with no newer signal; stopping");
            shared.end(Ended::Lease);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn line(signal: Signal, lease: Option<u64>) -> Line {
        Line {
            signal,
            lease: lease.map(Duration::from_secs),
        }
    }

    #[test]
    fn the_lines() {
        for (raw, fifo, want) in [
            ("continue", true, line(Signal::Continue, None)),
            ("continue 600", true, line(Signal::Continue, Some(600))),
            (
                "band floor 720",
                true,
                line(Signal::Band(Band::Floor), Some(720)),
            ),
            (
                "band pause 300",
                true,
                line(Signal::Band(Band::Pause), Some(300)),
            ),
            ("band steady", false, line(Signal::Band(Band::Steady), None)),
            ("steady", false, line(Signal::Band(Band::Steady), None)),
            ("ramp 45 420", true, line(Signal::Ramp(45), Some(420))),
            ("stop", true, line(Signal::Stop, None)),
            ("band stop", false, line(Signal::Stop, None)),
        ] {
            assert_eq!(parse(raw, fifo), Ok(want), "{raw}");
        }
    }

    /// Each refusal has its own reason.
    #[test]
    fn lines_that_are_refused() {
        for (raw, fifo, why) in [
            (
                "band floor",
                true,
                "a band or ramp signal on a fifo needs a lease",
            ),
            (
                "ramp 45",
                true,
                "a band or ramp signal on a fifo needs a lease",
            ),
            ("band lunch 60", true, "unknown band \"lunch\""),
            (
                "ramp many 60",
                true,
                "ramp \"many\" is not a whole number of identities",
            ),
            ("band floor 0", true, "lease 0 s is not 1 to 86400"),
            ("band floor 86401", true, "lease 86401 s is not 1 to 86400"),
            ("band floor 1.5", true, "lease \"1.5\" is not whole seconds"),
            ("band floor 60 60", true, "more than one lease"),
            ("stop 60", true, "unknown signal"),
            ("lunch", false, "unknown signal \"lunch\""),
        ] {
            assert_eq!(parse(raw, fifo), Err(why.to_string()), "{raw}");
        }
    }

    /// A signal reader whose phase lines go to the returned list, not the
    /// process's phases file (rows run side by side in one process).
    fn fresh() -> (Arc<Shared>, Control) {
        fresh_with(Arc::new(Mutex::new(Vec::new())))
    }

    fn fresh_with(phases: Arc<Mutex<Vec<serde_json::Value>>>) -> (Arc<Shared>, Control) {
        let (band_tx, band_rx) = watch::channel(Band::Warmup);
        let (ramp_tx, ramp_rx) = watch::channel(0);
        let (go_tx, go_rx) = oneshot::channel();
        let shared = Arc::new(Shared {
            emit: Box::new(move |v| phases.lock().expect("phases").push(v.clone())),
            band: band_tx,
            ramp: ramp_tx,
            go: Mutex::new(Some(go_tx)),
            deadline: Mutex::new(None),
            ended: Mutex::new(None),
        });
        let c = Control {
            band: band_rx,
            ramp: ramp_rx,
            go: Some(go_rx),
            shared: shared.clone(),
        };
        (shared, c)
    }

    /// A fifo outlives each writer: three writers, one line each, and the
    /// run goes on until `stop`.
    #[test]
    fn a_fifo_is_read_again_after_each_writer_closes() {
        let dir = crate::sim::guard::testsrv::tempdir();
        let control = spawn("fifo", &dir, 0).expect("spawn");
        let fifo = dir.join("band.fifo");
        let send = |l: &str| {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&fifo)
                .expect("open fifo");
            writeln!(f, "{l}").expect("write");
        };
        let wait_for = |want: Band| {
            for _ in 0..200 {
                if *control.band.borrow() == want {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("band never became {want:?}");
        };
        send("band floor 60");
        wait_for(Band::Floor);
        send("ramp 45 60");
        send("band steady 60");
        wait_for(Band::Steady);
        assert_eq!(*control.ramp.borrow(), 45);
        assert_eq!(control.ended(), None, "a writer's close ended the run");
        send("stop");
        wait_for(Band::Stop);
        assert_eq!(control.ended(), Some(Ended::Stop));
    }

    /// No newer signal before the lease runs out ends the run, as a lease.
    #[test]
    fn a_lease_that_runs_out_ends_the_run() {
        let phases = Arc::new(Mutex::new(Vec::new()));
        let (shared, control) = fresh_with(phases.clone());
        assert!(!shared.take("band steady 1", true));
        {
            let shared = shared.clone();
            std::thread::spawn(move || watchdog(shared, Duration::from_millis(50)));
        }
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(control.ended(), None, "ended before the lease ran out");
        assert!(!shared.take("band peak 1", true), "a newer signal");
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(control.ended(), None, "the newer lease was not kept");
        // The newer lease runs out about 1.4 s in; wait up to 3 s more.
        let until = Instant::now() + Duration::from_secs(3);
        while control.ended().is_none() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(control.ended(), Some(Ended::Lease));
        assert_eq!(*control.band.borrow(), Band::Stop);
        assert_eq!(
            *phases.lock().expect("phases"),
            vec![serde_json::json!({"phase": "lease-ran-out"})]
        );
    }

    /// A refused line changes nothing: not the band, not the lease.
    #[test]
    fn a_refused_line_changes_nothing() {
        let phases = Arc::new(Mutex::new(Vec::new()));
        let (shared, control) = fresh_with(phases.clone());
        assert!(!shared.take("band floor 60", true));
        let due = *shared.deadline.lock().expect("lock");
        assert!(!shared.take("band steady", true));
        assert!(!shared.take("band steady 0", true));
        assert_eq!(*control.band.borrow(), Band::Floor);
        assert_eq!(*shared.deadline.lock().expect("lock"), due);
        assert_eq!(
            *phases.lock().expect("phases"),
            vec![
                serde_json::json!({"phase": "signal-refused", "line": "band steady", "why": "a band or ramp signal on a fifo needs a lease"}),
                serde_json::json!({"phase": "signal-refused", "line": "band steady 0", "why": "lease 0 s is not 1 to 86400"}),
            ]
        );
    }

    /// Stdin keeps its old meaning: its end, with no `stop`, ends the run;
    /// a `stop` ends it there, and nothing after it is taken.
    #[test]
    fn stdin_ends_the_run_at_its_end() {
        let (shared, control) = fresh();
        read_stdin(&shared, std::io::Cursor::new("band floor\nband steady\n"));
        assert_eq!(control.ended(), Some(Ended::Eof));
        let (shared, control) = fresh();
        read_stdin(
            &shared,
            std::io::Cursor::new("band floor\nstop\nband peak\n"),
        );
        assert_eq!(control.ended(), Some(Ended::Stop));
        assert_eq!(*control.band.borrow(), Band::Stop);
    }

    /// The first reason a run ended is the one kept.
    #[test]
    fn the_first_end_is_kept() {
        let (shared, control) = fresh();
        assert!(shared.take("stop", true));
        shared.end(Ended::Lease);
        assert_eq!(control.ended(), Some(Ended::Stop));
    }
}
