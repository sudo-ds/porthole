//! Startup banner: a purple round-porthole logo, drawn with 24-bit ANSI color when stdout
//! is a color-capable terminal (and plain otherwise, so logs/journald stay clean).

use std::io::{IsTerminal, Write};

pub const LINES: &[&str] = &[
    r#"       .-"""""-."#,
    r#"     .'  o o o  '."#,
    r#"    /  o  ___  o  \"#,
    r#"   |  o  /   \  o  |     p o r t h o l e"#,
    r#"   |  o |     | o  |     self-hosted tunnels"#,
    r#"    \  o  \___/  o  /"#,
    r#"     '.  o o o  .'"#,
    r#"       '-.....-'"#,
];

/// Print the banner unless disabled. `subtitle` is a short mode/version line.
pub fn print(subtitle: &str, show: bool) {
    if !show {
        return;
    }
    #[cfg(windows)]
    let _ = enable_ansi_support::enable_ansi_support();

    let color = std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out);
    for (i, line) in LINES.iter().enumerate() {
        if color {
            let (r, g, b) = gradient(i, LINES.len());
            let _ = writeln!(out, "  \x1b[1;38;2;{r};{g};{b}m{line}\x1b[0m");
        } else {
            let _ = writeln!(out, "  {line}");
        }
    }
    if color {
        let _ = writeln!(out, "  \x1b[2m{subtitle}\x1b[0m");
    } else {
        let _ = writeln!(out, "  {subtitle}");
    }
    let _ = writeln!(out);
    let _ = out.flush();
}

/// Light violet (top) → deep violet (bottom).
pub fn gradient(i: usize, n: usize) -> (u8, u8, u8) {
    let t = if n <= 1 {
        0.0
    } else {
        i as f32 / (n - 1) as f32
    };
    let lerp = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * t).round() as u8;
    (lerp(199, 124), lerp(146, 58), lerp(255, 237))
}

#[cfg(test)]
mod tests {
    #[test]
    fn gradient_endpoints() {
        assert_eq!(super::gradient(0, 8), (199, 146, 255));
        assert_eq!(super::gradient(7, 8), (124, 58, 237));
    }
}
