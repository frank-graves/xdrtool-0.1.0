#Requires -Version 5.1
# build.ps1 — build reproducible de xdrtool
#   - SOURCE_DATE_EPOCH fijo
#   - doble build limpio (cargo clean + cargo build --release --locked)
#   - SHA-256 de cada binario y comparación; falla si difieren

$ErrorActionPreference = 'Stop'

# Epoch fijo para reproducibilidad: 2024-01-01T00:00:00Z
$env:SOURCE_DATE_EPOCH = "1704067200"

function Get-BinPath {
    $candidates = @(
        "target\x86_64-pc-windows-msvc\release\xdrtool.exe",
        "target\x86_64-pc-windows-gnu\release\xdrtool.exe",
        "target\release\xdrtool.exe"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

# Garantizar Cargo.lock en el primer build
if (-not (Test-Path "Cargo.lock")) {
    Write-Host "generando Cargo.lock..."
    cargo generate-lockfile
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "== build 1 (limpio) =="
cargo clean
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo build --release --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$bin1 = Get-BinPath
if (-not $bin1) { Write-Error "binario xdrtool.exe no encontrado (build 1)"; exit 1 }
$h1 = (Get-FileHash -Algorithm SHA256 $bin1).Hash.ToLower()

Write-Host "== build 2 (limpio) =="
cargo clean
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo build --release --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$bin2 = Get-BinPath
if (-not $bin2) { Write-Error "binario xdrtool.exe no encontrado (build 2)"; exit 1 }
$h2 = (Get-FileHash -Algorithm SHA256 $bin2).Hash.ToLower()

Write-Host "binario 1 : $bin1"
Write-Host "sha256    : $h1"
Write-Host "binario 2 : $bin2"
Write-Host "sha256    : $h2"

if ($h1 -ne $h2) {
    Write-Error "SHA-256 difieren ($h1 vs $h2); el build NO es reproducible"
    exit 1
}

Write-Host "REPRODUCIBLE OK"
