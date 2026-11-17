//! sys — helpers de Win32 (advapi32/bcrypt); base para fases 2+.
//! Fase 1: implementación completa. Aún sin llamadores.
#![allow(dead_code)]

use std::path::PathBuf;

/// Convierte `s` a UTF-16LE con NUL final.
pub fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut v: Vec<u16> = std::ffi::OsStr::new(s).encode_wide().collect();
    v.push(0);
    v
}

/// Interpreta `buf` como UTF-16LE, corta en el primer NUL y devuelve String.
/// Descarta un byte sobrante si la longitud es impar.
pub fn from_wide(buf: &[u8]) -> String {
    let (chunks, _rem) = buf.as_chunks::<2>();
    let mut units: Vec<u16> = Vec::with_capacity(chunks.len());
    for c in chunks {
        let u = u16::from_le_bytes(*c);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

/// true si el proceso puede escribir en HKLM\...\CurrentVersion (vista 64).
pub fn is_admin() -> bool {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, KEY_WRITE,
    };
    let subkey = wide(r"SOFTWARE\Microsoft\Windows\CurrentVersion");
    let mut hkey = std::ptr::null_mut();
    // SAFETY: subkey es UTF-16 NUL-terminado; hkey es un out-param válido.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_WRITE | KEY_WOW64_64KEY,
            &mut hkey,
        )
    };
    if rc != 0 {
        return false;
    }
    // SAFETY: hkey fue abierto exitosamente en la llamada anterior.
    let _ = unsafe { RegCloseKey(hkey) };
    true
}

/// `n` bytes pseudo-aleatorios vía BCryptGenRandom (handle NULL, flags 0);
/// fallback xorshift64 si la llamada falla.
pub fn random_bytes(n: usize) -> Vec<u8> {
    use windows_sys::Win32::Security::Cryptography::BCryptGenRandom;
    let mut buf = vec![0u8; n];
    if n == 0 {
        return buf;
    }
    let len: u32 = match u32::try_from(n) {
        Ok(v) => v,
        Err(_) => {
            fallback_random(&mut buf);
            return buf;
        }
    };
    // SAFETY: buf tiene al menos len bytes; puntero y longitud válidos.
    let rc = unsafe { BCryptGenRandom(std::ptr::null_mut(), buf.as_mut_ptr(), len, 0) };
    if rc == 0 {
        return buf;
    }
    fallback_random(&mut buf);
    buf
}

fn fallback_random(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let mut s: u64 = if nanos == 0 { 1 } else { nanos };
    // xorshift64: con semilla != 0 nunca produce 0, así que nunca todo ceros.
    let mut i = 0usize;
    while i < buf.len() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let bytes = s.to_le_bytes();
        let take = (buf.len() - i).min(8);
        buf[i..i + take].copy_from_slice(&bytes[..take]);
        i += take;
    }
}

/// Nombre aleatorio de DLL: `xdrkill_<12 hex>.dll`.
pub fn random_dll_name() -> String {
    let b = random_bytes(6);
    let mut name = String::with_capacity("xdrkill_".len() + 12 + ".dll".len());
    name.push_str("xdrkill_");
    name.push_str(&to_hex(&b));
    name.push_str(".dll");
    name
}

/// `%ProgramData%\xdrkill`, con `C:\ProgramData` como fallback.
pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("xdrkill")
}

/// Hex en minúsculas.
pub fn to_hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        out.push(H[(x >> 4) as usize] as char);
        out.push(H[(x & 0x0f) as usize] as char);
    }
    out
}

/// Decodifica hex; `None` si la longitud es impar o hay caracteres no hex.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_appends_nul() {
        assert_eq!(wide("abc"), vec![0x61u16, 0x62, 0x63, 0]);
    }

    #[test]
    fn wide_empty_is_single_nul() {
        assert_eq!(wide(""), vec![0u16]);
    }

    #[test]
    fn from_wide_ascii() {
        let b = [b'H', 0, b'i', 0];
        assert_eq!(from_wide(&b), "Hi");
    }

    #[test]
    fn from_wide_stops_at_nul() {
        let b = [b'H', 0, b'i', 0, 0, 0, b'X', 0];
        assert_eq!(from_wide(&b), "Hi");
    }

    #[test]
    fn from_wide_odd_length_discards_trailing() {
        let b = [b'A', 0, b'B'];
        assert_eq!(from_wide(&b), "A");
    }

    #[test]
    fn from_wide_empty() {
        assert_eq!(from_wide(&[]), "");
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0u8, 1, 0x0f, 0x10, 0xff];
        let s = to_hex(&data);
        assert_eq!(s, "00010f10ff");
        assert_eq!(from_hex(&s).as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn from_hex_rejects_odd() {
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("0"), None);
    }

    #[test]
    fn from_hex_rejects_non_hex() {
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("0g"), None);
        assert_eq!(from_hex("g0"), None);
        assert_eq!(from_hex("  "), None);
    }

    #[test]
    fn from_hex_uppercase_ok() {
        assert_eq!(from_hex("AB").as_deref(), Some([0xABu8].as_slice()));
    }

    #[test]
    fn from_hex_empty_ok() {
        assert_eq!(from_hex(""), Some(Vec::new()));
    }

    #[test]
    fn dll_name_shape() {
        let n = random_dll_name();
        assert!(n.starts_with("xdrkill_"));
        assert!(n.ends_with(".dll"));
        assert_eq!(n.len(), "xdrkill_".len() + 12 + ".dll".len());
        let mid = &n["xdrkill_".len()..n.len() - ".dll".len()];
        assert!(mid
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn random_bytes_len() {
        assert!(random_bytes(0).is_empty());
        assert_eq!(random_bytes(1).len(), 1);
        assert_eq!(random_bytes(17).len(), 17);
    }

    #[test]
    fn random_bytes_not_all_zero() {
        for _ in 0..8 {
            let b = random_bytes(32);
            assert!(b.iter().any(|&x| x != 0));
        }
    }
}
