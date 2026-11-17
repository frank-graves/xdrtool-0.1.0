# xdrtool 0.1.1

Herramienta CLI de tamper/bypass de **Cortex XDR** para entornos de
laboratorio y auditorías autorizadas. Local-first, sin red, sin telemetría.

> Uso exclusivo en sistemas propios o con autorización escrita. El autor no
> se responsabiliza del mal uso.

## Qué hace

- **Reconocimiento** del agente y sus artefactos sin privilegios (`recon`).
- **Sabotaje** del arranque del agente cambiando `ServiceDll` de `CryptSvc`
  a un nombre inexistente (requiere reinicio).
- **Control limpio** vía `cytool.exe` con la contraseña de fábrica.
- **Volcado y crackeo** offline de la contraseña del agente a partir de los
  `.ldb` de `agent_settings.db`.
- **Cadena automática** (`auto`): `cytool` → `dumphash` + `crack` →
  `sabotage`. Con `--dry-run`, `cytool` y `sabotage` se omiten (solo se
  anuncia lo que se haría); el paso de volcado y crackeo **sí se ejecuta**
  porque es de solo lectura. `auto` no ejecuta un `recon` separado: la
  comprobación de que el agente está instalado es interna.
- **Persistencia opcional** (`--persist N` en `sabotage` o `auto`) que
  re-aplica el sabotaje cada N segundos (mínimo 5) si el agente lo revierte.

## Técnicas y requisitos

| Técnica              | Privilegios   | Reinicio | Deja rastro                                                       |
|----------------------|---------------|----------|-------------------------------------------------------------------|
| `recon`              | usuario       | no       | no                                                                |
| `cytool`             | admin         | no       | no (el propio cytool puede loguear)                               |
| `sabotage`           | admin         | sí       | `ServiceDll` (+ `%ProgramData%\xdrkill` si había valor original)  |
| `sabotage --restore` | admin         | sí       | elimina el backup gestionado (si existe)                          |
| `dumphash`           | usuario       | no       | no                                                                |
| `crack`              | usuario       | no       | no                                                                |
| `auto`               | según subpaso | según    | según subpaso                                                     |

La columna "Reinicio" indica cuándo el cambio **surte efecto**; el valor del
registro se escribe/restaura de inmediato.

## Compilación

Requiere Rust estable y target Windows (MSVC o GNU). En tiempo de ejecución
no hay red; el build sí descarga las dependencias una vez.

```powershell
cargo build --release
```

`Cargo.lock` está versionado, así que un checkout limpio se compila de forma
reproducible con:

```powershell
cargo build --release --locked
```

Para verificar la reproducibilidad **en esta máquina** (dos builds limpios +
comparación de SHA-256):

```powershell
powershell -File .\build.ps1
```

Debe terminar con `REPRODUCIBLE OK`. Si los hashes difieren, el script sale
con código 1 e imprime ambos.

**Límite de la reproducibilidad.** `--remap-path-prefix=/=//` en
`.cargo/config.toml` no casa con rutas Windows (`C:\...`), así que es un
no-op en esta plataforma. Consecuencias:

- **Misma máquina, dos builds limpios** → mismos paths absolutos embebidos →
  mismo SHA-256 → el DoD se cumple.
- **Otra máquina o usuario** → paths distintos → binarios distintos aunque
  el código sea idéntico. Para reproducibilidad cross-machine habría que
  usar `--remap-path-prefix=C:\Users\TuUsuario\=//` (o el `$PWD` real del
  proyecto). No se hace por defecto para no romper el contrato de la fase 0.

## Uso

```
xdrtool [--json] <COMANDO> [ARGS]

  recon
  sabotage [--restore] [--dll <nombre>] [--persist <seg>]
  cytool <acción> [-p <pw>] [--enable]
  dumphash [--out <ruta>]
  crack --hash <b64> --salt <b64> [--iterations <n>] [--wordlist <ruta>]
  auto [--dry-run] [--dll <nombre>] [--wordlist <ruta>] [--persist <seg>]
```

Códigos de salida: `0` ok, `1` uso, `2` sin admin, `3` no detectado, `4` fallo.

Ejemplos:

```powershell
.\xdrtool.exe recon
.\xdrtool.exe cytool runtime -p Password1
.\xdrtool.exe sabotage
.\xdrtool.exe sabotage --restore
.\xdrtool.exe sabotage --persist 30
.\xdrtool.exe dumphash --out h.json
.\xdrtool.exe crack --hash <b64> --salt <b64> --wordlist rockyou.txt
.\xdrtool.exe auto --dry-run
.\xdrtool.exe auto --wordlist rockyou.txt --persist 30
```

En modo `--json` los subcomandos emiten un único objeto por stdout y los
mensajes humanos van por stderr, de modo que `ConvertFrom-Json` valida sin
ruido.

`--restore` solo aplica a `sabotage`. En `auto` se ignora silenciosamente
(igual que `--dll`/`--persist` se ignoran en subcomandos que no los usan).
`--persist` requiere administrador: sin admin, el bucle se omite con aviso.

## Fixtures

`fixtures/agent_settings.db` es un fichero de texto con el formato mínimo que
`hashdump` escanea: dos objetos `{"PasswordHash":"…","PasswordSalt":"…"}`, uno
por línea. No contiene datos reales; los base64 son sintéticos salvo el primer
par, que es el vector del artículo (password `Password1`, iteraciones 11112).

Está versionado. Los tests lo usan directamente:

- `extract_fixture_dir_when_present` valida que salen al menos 2 pares del
  fichero real (`env!("CARGO_MANIFEST_DIR")/fixtures/agent_settings.db`).
- `extract_inline_two_pairs` usa los mismos bytes inline en `%TEMP%` para que
  `cargo test` siga siendo verde incluso si alguien borra el fixture.

## Qué NO hace

- **No evita el EDR en memoria**. Si `CryptSvc` ya cargó la DLL del agente,
  el proceso sigue activo hasta el próximo reinicio.
- **No rompe una contraseña fuera del diccionario interno** ni de la wordlist
  que le pases. Si el agente cambió la contraseña a algo no listado, `crack`
  falla; el resto de subcomandos siguen funcionando.
- **No actúa sin reinicio** en el sabotaje: el registro se modifica ya, pero
  `CryptSvc` solo relee `ServiceDll` al arrancar.
- **No habla por red**: todo el crackeo y el escaneo son locales.
- **No es sigiloso** por diseño: deja `%ProgramData%\xdrkill\cryptsvc.bak`
  (cuando había valor original) y modifica el registro. Ver `docs/opsec.md`.

## Dependencias y por qué

| Crate              | Uso concreto                                                                                                                      |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `windows-sys` 0.59 | Registry (`RegOpenKeyExW`/`RegQueryValueExW`/`RegSetValueExW`/`RegDeleteValueW`) y `BCryptGenRandom`.                             |
| `pbkdf2` 0.12      | Derivación PBKDF2-HMAC-SHA512 (feature `hmac`).                                                                                   |
| `sha2` 0.10        | SHA-512 como PRF de PBKDF2.                                                                                                       |
| `base64` 0.22      | Codificar/decodificar hashes y salts (formato del agente).                                                                        |

Sin `serde`, `anyhow`, `thiserror`, `clap`, `log`, `rand`, `chrono`. La salida
JSON se serializa a mano y los errores son `u32` de Win32 o `String`. La
comparación del hash se hace en tiempo constante (`ct_eq`).

## Licencia

GPL-3.0-or-later. Ver `LICENSE`.
