pub const USAGE: &str = "\
USO:
    xdrtool [--json] <COMANDO> [ARGS]

COMANDOS:
    recon                      Reconocimiento del entorno
    sabotage [--restore] [--dll <nombre>] [--persist <seg>]
                               Sabotaje de la protección (requiere reinicio)
    cytool <ACCIÓN> [-p <pw>] [--enable]
                               Manipulación de componentes Cytool
    dumphash [--out <ruta>]    Volcado de hashes locales
    crack --hash <b64> --salt <b64> [--iterations <n>] [--wordlist <ruta>]
                               Crackeo offline de hashes
    auto [--dry-run] [--dll <nombre>] [--wordlist <ruta>] [--persist <seg>]
                               Cadena automática recon→cytool→dumphash→crack→sabotage

ACCIONES DE CYTTOOL:
    startup
    protect
    runtime
    eventcollection
    uninstall

OPCIONES:
    --json                     Salida estructurada en JSON
    --persist <seg>            Repetir el sabotaje cada N segundos (mín. 5)
    -h, --help                 Muestra esta ayuda y sale
    -V, --version              Muestra versión y sale

NOTAS:
    - sabotage requiere reinicio para aplicar los cambios
    - Se requieren privilegios de administrador
    - Códigos de salida: 0 ok, 1 uso, 2 sin admin, 3 no detectado, 4 fallo
";

pub enum Action {
    Startup,
    Protect,
    Runtime,
    EventCollection,
    Uninstall,
}

impl Action {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "startup" => Ok(Action::Startup),
            "protect" => Ok(Action::Protect),
            "runtime" => Ok(Action::Runtime),
            "eventcollection" => Ok(Action::EventCollection),
            "uninstall" => Ok(Action::Uninstall),
            other => Err(format!("acción desconocida: {other}")),
        }
    }
}

pub enum Cmd {
    Recon,
    Sabotage {
        persist: Option<u32>,
    },
    Cytool(Action),
    DumpHash,
    Crack,
    Auto {
        persist: Option<u32>,
    },
}

pub struct Args {
    pub json: bool,
    pub cmd: Cmd,
}

fn parse_persist<'a, I: Iterator<Item = &'a str>>(it: &mut I) -> Result<Option<u32>, String> {
    let mut persist: Option<u32> = None;
    while let Some(tok) = it.next() {
        match tok {
            "--persist" => {
                let v = it
                    .next()
                    .ok_or_else(|| "--persist requiere un argumento".to_string())?;
                let secs: u32 = v
                    .parse()
                    .map_err(|_| format!("--persist inválido: {v}"))?;
                persist = Some(secs.max(5));
            }
            other => return Err(format!("argumento inesperado: {other}")),
        }
    }
    Ok(persist)
}

fn expect_no_extra<'a, I: Iterator<Item = &'a str>>(it: &mut I, name: &str) -> Result<(), String> {
    if let Some(extra) = it.next() {
        return Err(format!("{name}: argumento inesperado: {extra}"));
    }
    Ok(())
}

pub fn parse(argv: &[String]) -> Result<Args, String> {
    let mut json = false;
    let mut filtered: Vec<&str> = Vec::with_capacity(argv.len());
    for a in argv {
        if a == "--json" {
            json = true;
        } else {
            filtered.push(a.as_str());
        }
    }

    let mut it = filtered.into_iter();
    let sub = it.next().ok_or_else(|| "falta subcomando".to_string())?;

    let cmd = match sub {
        "recon" => {
            expect_no_extra(&mut it, "recon")?;
            Cmd::Recon
        }
        "sabotage" => {
            let persist = parse_persist(&mut it)?;
            Cmd::Sabotage { persist }
        }
        "cytool" => {
            let act = it
                .next()
                .ok_or_else(|| "cytool: falta acción".to_string())?;
            let a = Action::parse(act)?;
            expect_no_extra(&mut it, "cytool")?;
            Cmd::Cytool(a)
        }
        "dumphash" => {
            expect_no_extra(&mut it, "dumphash")?;
            Cmd::DumpHash
        }
        "crack" => {
            expect_no_extra(&mut it, "crack")?;
            Cmd::Crack
        }
        "auto" => {
            let persist = parse_persist(&mut it)?;
            Cmd::Auto { persist }
        }
        other => return Err(format!("subcomando desconocido: {other}")),
    };

    Ok(Args { json, cmd })
}
