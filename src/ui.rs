// ui — salida de usuario (texto/JSON). Fase 0: stubs; algunas funciones aún no se usan.
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};

static JSON: AtomicBool = AtomicBool::new(false);

pub fn set_json(v: bool) {
    JSON.store(v, Ordering::Relaxed);
}

pub fn json() -> bool {
    JSON.load(Ordering::Relaxed)
}

fn emit(tag: &str, level: &str, msg: &str) {
    if json() {
        eprintln!("{{\"level\":\"{level}\",\"msg\":\"{m}\"}}", m = esc(msg));
    } else {
        eprintln!("[{tag}] {msg}");
    }
}

pub fn info(msg: &str) {
    emit("i", "info", msg);
}

pub fn ok(msg: &str) {
    emit("+", "ok", msg);
}

pub fn warn(msg: &str) {
    emit("!", "warn", msg);
}

pub fn err(msg: &str) {
    emit("x", "error", msg);
}

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let n = c as u32;
                out.push_str(&format!("\\u{n:04x}"));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::esc;

    #[test]
    fn esc_quotes() {
        assert_eq!(esc("a\"b"), "a\\\"b");
    }

    #[test]
    fn esc_backslash() {
        assert_eq!(esc("a\\b"), "a\\\\b");
    }

    #[test]
    fn esc_newline() {
        assert_eq!(esc("a\nb"), "a\\nb");
    }

    #[test]
    fn esc_control_char() {
        assert_eq!(esc("\x01"), "\\u0001");
        assert_eq!(esc("\x1f"), "\\u001f");
    }

    #[test]
    fn esc_plain_passthrough() {
        assert_eq!(esc("hello world"), "hello world");
    }
}
