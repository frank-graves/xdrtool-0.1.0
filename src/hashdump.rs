//! hashdump — extracción de pares `PasswordHash`/`PasswordSalt` desde los
//! ficheros `agent_settings.db` (dump de "Generate Support File").
//! Escaneo en crudo, sin binarios externos.

use crate::sys;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::path::PathBuf;

const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_VALUE_BYTES: usize = 512;

pub struct Pair {
    pub hash_b64: String,
    pub salt_b64: String,
}

/// Extrae los pares del fichero. Nunca falla: devuelve vacío si el fichero
/// no existe, no es legible o supera el límite.
pub fn extract(path: &PathBuf) -> Vec<Pair> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    if meta.len() > MAX_FILE_BYTES {
        return Vec::new();
    }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let hashes = collect(&data, b"\"PasswordHash\":\"");
    let salts = collect(&data, b"\"PasswordSalt\":\"");
    hashes
        .into_iter()
        .zip(salts)
        .map(|(hash_b64, salt_b64)| Pair {
            hash_b64,
            salt_b64,
        })
        .collect()
}

/// Recorre `data` con ventana deslizante; por cada aparición de `needle`
/// acumula el valor hasta la comilla de cierre (o hasta `MAX_VALUE_BYTES`).
/// Escaneo lineal: avanza de uno en uno sólo cuando no hay coincidencia.
fn collect(data: &[u8], needle: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let nl = needle.len();
    if nl == 0 || data.len() < nl {
        return out;
    }
    let mut i = 0usize;
    while i + nl <= data.len() {
        if &data[i..i + nl] == needle {
            let start = i + nl;
            let mut j = start;
            let mut val = Vec::new();
            while j < data.len() && val.len() < MAX_VALUE_BYTES {
                let b = data[j];
                if b == b'"' {
                    break;
                }
                val.push(b);
                j += 1;
            }
            out.push(String::from_utf8_lossy(&val).into_owned());
            i = match data.get(j) {
                Some(&b'"') => j + 1,
                _ => j,
            };
        } else {
            i += 1;
        }
    }
    out
}

/// Línea `sha512:<iter>:<salt>:<hash>` (los dos últimos en base64).
pub fn hashcat_line(iterations: u32, salt_b64: &str, hash_b64: &str) -> String {
    format!("sha512:{iterations}:{salt_b64}:{hash_b64}")
}

/// Representación `hash=<hex> salt=<hex>` decodificando ambos base64.
/// Si alguno no es base64 válido, deja la marca "(base64 inválido)".
pub fn debug_hex(p: &Pair) -> String {
    let h = STANDARD
        .decode(&p.hash_b64)
        .ok()
        .map(|b| sys::to_hex(&b))
        .unwrap_or_else(|| "(base64 inválido)".to_string());
    let s = STANDARD
        .decode(&p.salt_b64)
        .ok()
        .map(|b| sys::to_hex(&b))
        .unwrap_or_else(|| "(base64 inválido)".to_string());
    format!("hash={h} salt={s}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture inline: dos pares sintéticos, mismos bytes que fixtures/
    // agent_settings.db (README § Fixtures). Escrito a temp en el test para
    // que no dependa de un fichero en el árbol de fuentes.
    const FIXTURE_INLINE: &[u8] = concat!(
        r#"{"PasswordHash":"LCeLXnrGjjf85UYWhm1dHK4NhPiCMmtcfVBYbT9RuQ5nMNl0EL211UF9xhlU+kERNRo5Ty9XQXgZ0G6XPIM0Bw==","PasswordSalt":"MjEzN3EwcWVuc2hxNmtvdjAya3lq"}"#,
        "\n",
        r#"{"PasswordHash":"U0VDT05ESEFTSDJTRUNPTkRIQVNIMlNFQ09OREhBU0gyU0VDT05ESEFTSDJTRUNPTkRIQVNIMg==","PasswordSalt":"U0VDT05EU0FMVA=="}"#,
        "\n",
    )
    .as_bytes();

    #[test]
    fn extract_inline_two_pairs() {
        let dir = std::env::temp_dir().join("xdrkill_test_fixture");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("agent_settings.db");
        std::fs::write(&path, FIXTURE_INLINE).expect("write fixture");
        let pairs = extract(&path);
        let _ = std::fs::remove_file(&path);

        assert!(
            pairs.len() >= 2,
            "esperaba al menos 2 pares, obtenidos {}",
            pairs.len()
        );
        for p in &pairs {
            assert!(!p.hash_b64.is_empty());
            assert!(!p.salt_b64.is_empty());
        }
    }

    #[test]
    fn extract_fixture_dir_when_present() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("agent_settings.db");
        if !path.is_file() {
            eprintln!(
                "[skip] fixtures/agent_settings.db no presente; ver README.md § Fixtures"
            );
            return;
        }
        let pairs = extract(&path);
        assert!(
            pairs.len() >= 2,
            "esperaba al menos 2 pares en fixture, obtenidos {}",
            pairs.len()
        );
    }
}
