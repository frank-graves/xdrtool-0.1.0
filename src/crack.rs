//! crack — motor de cracking offline para hashes PBKDF2-HMAC-SHA512 del
//! agente Cortex XDR. Verificación en tiempo constante, sin red ni telemetría.
#![allow(dead_code)]

use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use std::path::Path;

/// Iteraciones de PBKDF2-HMAC-SHA512 (valor de fábrica de Cortex XDR).
pub const DEFAULT_ITERATIONS: u32 = 11_112;

/// Diccionario interno de candidatos habituales (contraseñas de fábrica,
/// defaults de laboratorio y variantes típicas).
pub const BUILTIN: &[&str] = &[
    "Password1",
    "password1",
    "Password",
    "password",
    "P@ssw0rd",
    "P@ssw0rd1",
    "Password12",
    "Password123",
    "Password1!",
    "Password01",
    "paloalto",
    "PaloAlto1",
    "PaloAltoNetworks",
    "PaloAlto",
    "cortex",
    "Cortex",
    "Cortex1",
    "cortexxdr",
    "CortexXDR",
    "xdr",
    "XDR1",
    "admin",
    "Admin",
    "Admin123",
    "Admin1234",
    "cyvera",
    "Cyvera1",
    "traps",
    "Traps1",
    "changeme",
    "ChangeMe123",
    "Cortex123",
    "Paloalto123",
    "PaloAlto123",
    "Xdr12345",
    "Traps123",
    "Password123!",
];

/// Igualdad en tiempo constante: longitudes distintas → false inmediato;
/// si no, OR acumulado de los XOR (sin early-return).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// Verifica `password` contra `expected` (dklen = expected.len()).
/// Iteraciones 0 se sustituyen por `DEFAULT_ITERATIONS`.
pub fn verify(password: &[u8], salt: &[u8], iterations: u32, expected: &[u8]) -> bool {
    let iter = if iterations == 0 {
        DEFAULT_ITERATIONS
    } else {
        iterations
    };
    let mut buf = vec![0u8; expected.len()];
    pbkdf2_hmac::<Sha512>(password, salt, iter, &mut buf);
    ct_eq(&buf, expected)
}

/// Prueba primero `BUILTIN` y, si se da `wordlist`, sus líneas. Devuelve
/// (contraseña, intentos) al primer acierto; `None` si se agota.
pub fn crack(
    expected: &[u8],
    salt: &[u8],
    iterations: u32,
    wordlist: Option<&Path>,
) -> Option<(String, u64)> {
    let iter = if iterations == 0 {
        DEFAULT_ITERATIONS
    } else {
        iterations
    };
    let mut tried: u64 = 0;
    for pw in BUILTIN {
        tried += 1;
        if verify(pw.as_bytes(), salt, iter, expected) {
            return Some(((*pw).to_string(), tried));
        }
    }
    if let Some(path) = wordlist {
        if let Ok(file) = std::fs::File::open(path) {
            use std::io::BufRead;
            let reader = std::io::BufReader::new(file);
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                let candidate = line.trim_end_matches(['\r', '\n']);
                if candidate.is_empty() || candidate.len() > 128 {
                    continue;
                }
                tried += 1;
                if verify(candidate.as_bytes(), salt, iter, expected) {
                    return Some((candidate.to_string(), tried));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    const HASH_B64: &str = "LCeLXnrGjjf85UYWhm1dHK4NhPiCMmtcfVBYbT9RuQ5nMNl0EL211UF9xhlU+kERNRo5Ty9XQXgZ0G6XPIM0Bw==";
    const SALT: &[u8] = b"2137q0qenshq6kov02kyj";
    const ITER: u32 = 11_112;

    fn decode_hash() -> Vec<u8> {
        STANDARD
            .decode(HASH_B64)
            .expect("hash b64 del artículo debe decodificar")
    }

    #[test]
    fn ct_eq_diff_lengths_false() {
        assert!(!ct_eq(&[1u8, 2, 3], &[1, 2]));
        assert!(!ct_eq(&[], &[0]));
    }

    #[test]
    fn ct_eq_equal() {
        assert!(ct_eq(&[], &[]));
        assert!(ct_eq(&[1u8, 2, 3], &[1, 2, 3]));
    }

    #[test]
    fn ct_eq_bit_difference_false() {
        assert!(!ct_eq(&[0b1010_1010u8], &[0b1010_1011]));
    }

    #[test]
    fn verify_password1_true() {
        let expected = decode_hash();
        assert!(verify(b"Password1", SALT, ITER, &expected));
    }

    #[test]
    fn verify_password_false() {
        let expected = decode_hash();
        assert!(!verify(b"Password", SALT, ITER, &expected));
    }

    #[test]
    fn crack_finds_password1() {
        let expected = decode_hash();
        let r = crack(&expected, SALT, ITER, None);
        let (pw, tried) = r.expect("Password1 debe estar en BUILTIN");
        assert_eq!(pw, "Password1");
        assert!(tried >= 1);
    }
}
