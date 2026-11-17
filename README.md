# xdrtool 0.1.0

CLI tamper/bypass tool for **Cortex XDR** in laboratory environments and
authorized audits. Local-first, no network, no telemetry.

> Use only on systems you own or with written authorization. The author is not
> responsible for misuse.

## What it does

- **Reconnaissance** of the agent and its artifacts without privileges.
- **Sabotage** of agent startup by changing the `ServiceDll` value of
  `CryptSvc` to a nonexistent name (requires a reboot).
- **Clean control** via `cytool.exe` using the factory password.
- **Offline dump and cracking** of the agent password from the `.ldb` files in
  `agent_settings.db`.
- **Automatic chain** (`auto`): recon → cytool → dump → crack → sabotage.
  With `--dry-run`, `cytool` and `sabotage` are skipped (only what would be
  done is announced); the crack step **still runs** because it is read-only.
- **Optional persistence** (`--persist N` in `sabotage` or `auto`) that
  reapplies the sabotage every N seconds (minimum 5) if the agent reverts it.

## Techniques and requirements

| Technique            | Privileges  | Restart     | Leaves traces                                                         |
| -------------------- | ----------- | ----------- | --------------------------------------------------------------------- |
| `recon`              | user        | no          | no                                                                    |
| `cytool`             | admin       | no          | no (cytool itself may log)                                            |
| `sabotage`           | admin       | yes         | `ServiceDll` (+ `%ProgramData%\xdrkill` if an original value existed) |
| `sabotage --restore` | admin       | yes         | removes the managed backup (if present)                               |
| `dumphash`           | user        | no          | no                                                                    |
| `crack`              | user        | no          | no                                                                    |
| `auto`               | per substep | per substep | per substep                                                           |

The "Restart" column indicates when the change **takes effect**; the registry
value is written/restored immediately.

## Build

Requires stable Rust and a Windows target (MSVC or GNU). At runtime there is no
network access; the build downloads dependencies once.

```text
cargo build --release
```

For a reproducible build (locks dependency resolution with `Cargo.lock` and
compares SHA-256 between two clean builds):

```text
cargo generate-lockfile          # only the first time, if Cargo.lock is absent
cargo build --release --locked
```

The verification script does this for you and also compares two builds:

```powershell
powershell -File .\build.ps1
```

If the SHA-256 of the two binaries differs, `build.ps1` exits with code 1.

> Note: the binary is named `xdrtool.exe` (the crate name). Some examples from
> earlier design phases said `xdrkill`; the actual name is `xdrtool`.

## Usage

```text
xdrtool [--json] <COMMAND> [ARGS]

  recon
  sabotage [--restore] [--dll <name>] [--persist <sec>]
  cytool <action> [-p <pw>] [--enable]
  dumphash [--out <path>]
  crack --hash <b64> --salt <b64> [--iterations <n>] [--wordlist <path>]
  auto [--dry-run] [--dll <name>] [--wordlist <path>] [--persist <sec>]
```

Exit codes: `0` ok, `1` usage, `2` not admin, `3` not detected, `4` failure.

Examples:

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

In `--json` mode, subcommands emit a single object on stdout and human-readable
messages go to stderr, so `ConvertFrom-Json` validates without noise.

## Fixtures

`fixtures/agent_settings.db` is a text file in the minimal format that
`hashdump` scans: two `{"PasswordHash":"…","PasswordSalt":"…"}` objects. It
contains no real data; the base64 values are synthetic except for the first
pair, which is the vector from the article (password `Password1`).

To generate it in PowerShell from the repository root:

```powershell
New-Item -ItemType Directory -Force -Path fixtures | Out-Null
$text = @'
{"PasswordHash":"LCeLXnrGjjf85UYWhm1dHK4NhPiCMmtcfVBYbT9RuQ5nMNl0EL211UF9xhlU+kERNRo5Ty9XQXgZ0G6XPIM0Bw==","PasswordSalt":"MjEzN3EwcWVuc2hxNmtvdjAya3lq"}
{"PasswordHash":"U0VDT05ESEFTSDJTRUNPTkRIQVNIMlNFQ09OREhBU0gyU0VDT05ESEFTSDJTRUNPTkRIQVNIMg==","PasswordSalt":"U0VDT05EU0FMVA=="}
'@
[System.IO.File]::WriteAllText("fixtures\agent_settings.db", $text)
```

The `extract_fixture_dir_when_present` test uses that file if it exists and
skips with a warning if it is missing. The `extract_inline_two_pairs` test
uses the same bytes inline in `%TEMP%` and **always** passes, so `cargo test`
is green on a clean checkout.

## What it does NOT do

- **It does not evade the EDR in memory.** If `CryptSvc` has already loaded the
  agent DLL, the process remains active until the next reboot.
- **It does not crack a password outside the internal dictionary** or the
  wordlist you provide. If the agent changed the password to an unlisted value,
  `crack` fails; the other subcommands still work.
- **It does not take effect without a reboot** for sabotage: the registry is
  modified immediately, but `CryptSvc` only rereads `ServiceDll` at startup.
- **It does not communicate over the network**: all cracking and scanning are
  local.
- **It is not stealthy by design**: it leaves
  `%ProgramData%\xdrkill\cryptsvc.bak` (when an original value existed) and
  modifies the registry. See `docs/opsec.md`.

## Dependencies and rationale

| Crate              | Specific use                                                                                            |
| ------------------ | ------------------------------------------------------------------------------------------------------- |
| `windows-sys` 0.59 | Registry (`RegOpenKeyExW`/`RegQueryValueExW`/`RegSetValueExW`/`RegDeleteValueW`) and `BCryptGenRandom`. |
| `pbkdf2` 0.12      | PBKDF2-HMAC-SHA512 derivation (feature `hmac`).                                                         |
| `sha2` 0.10        | SHA-512 as the PBKDF2 PRF.                                                                              |
| `base64` 0.22      | Encode/decode hashes and salts (agent format).                                                          |

No `serde`, `anyhow`, `thiserror`, `clap`, `log`, `rand`, or `chrono`. JSON
output is serialized by hand and errors are Win32 `u32` values or `String`.
Hash comparison is constant-time (`ct_eq`).

## License

GPL-3.0-or-later. See `LICENSE`.
