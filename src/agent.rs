//! agent — descubrimiento del agente Cortex XDR y sus artefactos.
//! Tolerante a instalaciones parciales: nunca falla por ausencia.
#![allow(dead_code)]

use crate::sys;
use std::path::{Path, PathBuf};

const SERVICES: [&str; 3] = ["Cyverak", "Cyvrlpc", "Cyoptics"];

/// Devuelve `%ProgramFiles%\Palo Alto Networks\Traps` o su variante x86 si
/// el directorio existe.
pub fn traps_dir() -> Option<PathBuf> {
    for var in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(base) = std::env::var_os(var) {
            let p = PathBuf::from(base).join("Palo Alto Networks").join("Traps");
            if p.is_dir() {
                return Some(p);
            }
        }
    }
    None
}

/// `traps_dir()/cytool.exe` si es fichero.
pub fn cytool() -> Option<PathBuf> {
    let p = traps_dir()?.join("cytool.exe");
    if p.is_file() {
        Some(p)
    } else {
        None
    }
}

/// Servicios de la lista `SERVICES` presentes en `HKLM\...\Services\<name>`.
pub fn services_present() -> Vec<&'static str> {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY,
    };
    let mut out = Vec::new();
    for name in SERVICES {
        let path = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
        let key_w = sys::wide(&path);
        let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
        // SAFETY: key_w es UTF-16 NUL-terminado; hkey es out-param válido.
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                key_w.as_ptr(),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut hkey,
            )
        };
        if rc == 0 {
            // SAFETY: hkey fue abierto exitosamente en la llamada anterior.
            let _ = unsafe { RegCloseKey(hkey) };
            out.push(name);
        }
    }
    out
}

/// Bases de datos `agent_settings.db` bajo `%ProgramData%\Cyvera`, ordenadas
/// por tamaño descendente. Nunca falla.
pub fn persistence_dbs() -> Vec<PathBuf> {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Cyvera");
    if !base.is_dir() {
        return Vec::new();
    }
    let mut found = Vec::new();
    walk(&base, 0, &mut found);
    let mut hits: Vec<PathBuf> = found
        .into_iter()
        .filter(|p| p.file_name().and_then(|s| s.to_str()) == Some("agent_settings.db"))
        .collect();
    hits.sort_by(|a, b| {
        let sa = std::fs::metadata(a).map(|m| m.len()).unwrap_or(0);
        let sb = std::fs::metadata(b).map(|m| m.len()).unwrap_or(0);
        sb.cmp(&sa)
    });
    hits
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth >= 8 {
        return;
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            walk(&path, depth + 1, out);
        } else if ft.is_file() {
            out.push(path);
        }
    }
}

/// `true` si el agente parece instalado (dir de traps o algún servicio presente).
pub fn installed() -> bool {
    traps_dir().is_some() || !services_present().is_empty()
}
