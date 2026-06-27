//! Live terminal dashboard for the client: the logo, a per-tunnel stats table, and a tail
//! of recent log lines, redrawn in place. Used only on an interactive TTY; otherwise the
//! client just streams plain logs.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::banner;
use crate::client::ClientShared;

const LOG_CAP: usize = 200;
const LOG_SHOWN: usize = 10;

static LOG_BUFFER: OnceLock<Arc<Mutex<VecDeque<String>>>> = OnceLock::new();
static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn log_buffer() -> Arc<Mutex<VecDeque<String>>> {
    LOG_BUFFER
        .get_or_init(|| Arc::new(Mutex::new(VecDeque::new())))
        .clone()
}

pub fn set_enabled(v: bool) {
    ENABLED.store(v, Relaxed);
}

pub fn enabled() -> bool {
    ENABLED.load(Relaxed)
}

/// A `tracing` writer that appends formatted log lines into the shared ring buffer instead
/// of stdout (so the dashboard owns the screen).
#[derive(Clone)]
pub struct LogWriter(Arc<Mutex<VecDeque<String>>>);

pub fn make_writer() -> LogWriter {
    LogWriter(log_buffer())
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let mut q = self.0.lock().unwrap();
        for line in text.lines() {
            let line = line.trim_end();
            if !line.is_empty() {
                q.push_back(line.to_string());
            }
        }
        while q.len() > LOG_CAP {
            q.pop_front();
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Redraw the dashboard on a timer until shutdown.
pub async fn run(shared: Arc<ClientShared>) {
    let buf = log_buffer();
    let mut ticker = tokio::time::interval(Duration::from_millis(1000));
    print!("\x1b[?25l"); // hide cursor
    let _ = std::io::stdout().flush();
    loop {
        tokio::select! {
            _ = shared.shutdown.cancelled() => break,
            _ = ticker.tick() => render(&shared, &buf),
        }
    }
    print!("\x1b[?25h\x1b[0m"); // show cursor, reset
    let _ = std::io::stdout().flush();
}

fn render(shared: &ClientShared, buf: &Arc<Mutex<VecDeque<String>>>) {
    let mut s = String::with_capacity(4096);
    s.push_str("\x1b[2J\x1b[H"); // clear + cursor home

    for (i, line) in banner::LINES.iter().enumerate() {
        let (r, g, b) = banner::gradient(i, banner::LINES.len());
        s.push_str(&format!("  \x1b[1;38;2;{r};{g};{b}m{line}\x1b[0m\n"));
    }
    s.push('\n');

    let connected = shared.connected.load(Relaxed);
    let (min, max) = (shared.min_port.load(Relaxed), shared.max_port.load(Relaxed));
    if connected {
        s.push_str(&format!(
            "  \x1b[32m● connected\x1b[0m to {}    public ports {min}-{max}\n\n",
            shared.server_addr
        ));
    } else {
        s.push_str(&format!(
            "  \x1b[31m○ connecting…\x1b[0m to {}\n\n",
            shared.server_addr
        ));
    }

    // Table (leading colored dot keeps a constant visible prefix, so columns stay aligned).
    s.push_str(&format!(
        "    \x1b[2m{:<14} {:<5} {:<18} {:<20} {:<8} {:>9} {:>9} {:>5}\x1b[0m\n",
        "NAME", "PROTO", "LOCAL", "PUBLIC", "STATUS", "IN", "OUT", "CONNS"
    ));
    let mut names: Vec<String> = shared.status.iter().map(|e| e.key().clone()).collect();
    names.sort();
    if names.is_empty() {
        s.push_str("    \x1b[2m(no tunnels yet — add one in the web UI or config)\x1b[0m\n");
    }
    for name in names {
        let Some(t) = shared.status.get(&name) else {
            continue;
        };
        let public = t.public_addr.lock().unwrap().clone();
        let err = t.error.lock().unwrap().clone();
        let (dot, status) = if err.is_some() {
            ("\x1b[31m●\x1b[0m", "rejected")
        } else if t.up.load(Relaxed) {
            ("\x1b[32m●\x1b[0m", "up")
        } else {
            ("\x1b[33m●\x1b[0m", "pending")
        };
        s.push_str(&format!(
            "  {dot} {:<14} {:<5} {:<18} {:<20} {:<8} {:>9} {:>9} {:>5}\n",
            truncate(&name, 14),
            t.proto.to_string(),
            truncate(&t.local_addr.to_string(), 18),
            truncate(&public.or(err).unwrap_or_else(|| "—".into()), 20),
            status,
            fmt_bytes(t.counters.bytes_in.load(Relaxed)),
            fmt_bytes(t.counters.bytes_out.load(Relaxed)),
            t.counters.active.load(Relaxed),
        ));
    }
    s.push('\n');

    s.push_str("  \x1b[2m── logs ──────────────────────────────────────────────────\x1b[0m\n");
    let q = buf.lock().unwrap();
    let start = q.len().saturating_sub(LOG_SHOWN);
    for line in q.iter().skip(start) {
        s.push_str(&format!("  \x1b[2m{}\x1b[0m\n", truncate(line, 78)));
    }
    drop(q);

    let mut out = std::io::stdout().lock();
    let _ = out.write_all(s.as_bytes());
    let _ = out.flush();
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn fmt_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < 4 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}
