# Opsec

Esta herramienta es deliberadamente **no sigilosa**: deja rastro intencionado
para auditoría. Si necesitas un perfil bajo, no la uses. Aun así, aquí está lo
que toca y cómo revertirlo.

## Lo que NO deja rastro

- `recon` — solo lee registro y sistema de ficheros (metadatos).
- `dumphash` **sin** `--out` — solo lee `.ldb` y escribe por stdout/stderr.
- `crack` — cómputo puro en memoria; opcionalmente lee una wordlist.
- `auto --dry-run` — no lanza `cytool` ni toca el registro; solo anuncia lo que
  haría. El paso de volcado/crackeo sí corre, pero es de solo lectura.
- `sabotage --restore` cuando **sí** hay backup — reescribe el valor original y
  borra el backup gestionado.

## Rastros que deja

### 1. `%ProgramData%\xdrkill\` y `cryptsvc.bak`

Directorio y fichero que `reg::save_backup` crea **antes** de escribir en el
registro. Contiene el valor original de `ServiceDll` en texto
(`type=<n>` + `data=<hex>`). Sobrevive a reinicios.

- Se crea en `sabotage` cuando `ServiceDll` **existe** y no contiene ya
  `xdrkill_`. Si el valor no existe, no hay backup (no hay nada que guardar).
- En `sabotage --persist`, el backup lo crea la **primera** llamada a
  `sabotage` (antes de arrancar el bucle). El bucle en sí no crea backups
  nuevos; solo reescribe el valor si detecta que ya no contiene `xdrkill_`.
- Se elimina en `sabotage --restore` **después** de reescribir el registro.
  Si el borrado del fichero falla (p. ej. por permisos), se imprime un aviso y
  el backup persiste.
- Si el proceso muere antes del `--restore`, queda ahí.

**Limpieza**:

```powershell
Remove-Item -Recurse -Force "$env:ProgramData\xdrkill"
```

### 2. `dumphash --out <ruta>`

`--out` escribe el hash y el salt del agente en el fichero indicado, en claro
(base64 dentro de JSON). Es un rastro sensible: cualquiera con acceso a ese
fichero puede intentar crackear la contraseña offline.

- **No lo commitees**. Si vas a usar `--out`, redirige a una ruta temporal
  fuera del repo (`$env:TEMP\xdrkill\h.json`) y bórralo al terminar.
- A diferencia del backup, `dumphash --out` **no** es gestionado por
  `--restore`: la limpieza es manual.
- `dumphash` sin `--out` no escribe nada en disco.

### 3. Clave `HKLM\SYSTEM\CurrentControlSet\Services\CryptSvc\Parameters`

- Tras `sabotage`, `ServiceDll` queda apuntando a un nombre `xdrkill_<hex>.dll`
  que **no existe** en disco.
- `--restore` con backup: reescribe el valor original y borra el backup.
- `--restore` **sin** backup: si el valor existe, se **elimina** (no se
  restaura a un valor conocido). Ver "Escenarios de riesgo" abajo.

**Limpieza manual**:

```powershell
# Ver valor actual
reg query "HKLM\SYSTEM\CurrentControlSet\Services\CryptSvc\Parameters" /v ServiceDll

# Restaurar desde backup gestionado por xdrtool
.\xdrtool.exe sabotage --restore

# Restaurar a mano el valor por defecto de Windows (solo si el original
# era el de Windows, no si lo había modificado XDR)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CryptSvc\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "%SystemRoot%\system32\cryptsvc.dll" /f
```

### 4. Reinicio pendiente

`sabotage` no aplica el cambio hasta el próximo arranque. No se marca como
"reinicio requerido" en el sistema (no tocamos `PendingFileRenameOperations`
ni claves equivalentes), así que **tú decides cuándo** reiniciar.

Si no reinicias, no hay efecto visible salvo el cambio de valor en registro.

### 5. `--persist <seg>`: bucle en ejecución

`--persist` arranca un bucle que, cada N segundos (mínimo 5), lee `ServiceDll`
y si no contiene `xdrkill_` lo vuelve a sabotear. Consecuencias opsec:

- **Proceso de larga vida** visible en el administrador de tareas / EDR
  corporativo. No es stealth.
- **Modifica el registro periódicamente**: cada iteración que actúa genera
  una escritura adicional sobre `CryptSvc\Parameters`. Si XDR tiene
  anti-tamper activo, puede registrar eventos por iteración.
- **Sobrescribe el backup en un caso concreto**: si entre iteraciones el
  valor de `ServiceDll` cambia a algo que no contiene `xdrkill_` (intervención
  manual, otro agente, etc.), la siguiente iteración llama a `reg::sabotage`,
  que guarda un backup **nuevo** con ese valor. El backup original se pierde.
  Solo ocurre en bucle `--persist`; `sabotage` a secas no reescribe backups
  existentes salvo en el caso documentado en el código.
- Solo arranca si `sabotage` (o `auto`) terminó con código 0. Si el flag se
  pasa con `--restore`, se ignora: `--restore` tiene prioridad.
- Sin admin, el bucle se omite con aviso (pero `sabotage` puede haber tenido
  éxito si se ejecutó previamente en una shell elevada).
- Salida: **Ctrl-C**. No hay handler de SIGINT (intencionadamente, para no
  añadir dependencias); el proceso muere y el backup permanece en disco.

### 6. `cytool.exe`

No dejamos rastro propio, pero `cytool` puede registrar eventos en los logs
del agente. Revisa la configuración del producto antes de asumir cero rastro.
`auto --dry-run` **no** lanza `cytool`, así que no genera estos logs.

### 7. Ficheros temporales de test

`cargo test` escribe `%TEMP%\xdrkill_test_fixture\agent_settings.db` y lo
borra al terminar. Si un test hace panic a mitad, el fichero puede quedar; es
inocuo (los pares son sintéticos) y se borra con:

```powershell
Remove-Item -Recurse -Force "$env:TEMP\xdrkill_test_fixture"
```

No toca `%ProgramData%` ni el registro.

## Escenarios de riesgo

### `sabotage --restore` sin backup

El código actual hace:

1. `reg::load_backup()` → `None` (no hay fichero).
2. `reg::read()` → `Some((ty, data))` si `ServiceDll` existe.
3. `reg::delete_value()` → **borra** el valor (no lo restaura).
4. Devuelve `Ok(None)`.

Esto **rompe `CryptSvc`**: sin `ServiceDll`, el servicio no sabe qué DLL
cargar. En la práctica, `CryptSvc` falla al arrancar y arrastra a los
consumidores (BitLocker, EFS, IPsec, etc.). **No uses `--restore` sin backup
salvo que sepas exactamente qué había antes.**

Dos orígenes distintos de "no hay backup":

- Nunca ejecutaste `sabotage` → `ServiceDll` tiene el valor de fábrica
  (`%SystemRoot%\system32\cryptsvc.dll`) o el que puso XDR al instalarse.
- El backup se borró a mano → mismo caso.

Mitigación:

- Antes de cualquier `--restore`, verifica con `reg query ... /v ServiceDll`.
- Si no hay backup y quieres dejar Windows funcional, usa el `reg add` de
  arriba (asumiendo que el original era el de Windows) **antes** de borrar.
- Si XDR estaba instalado y quieres devolverle el control, no uses
  `reg add ... cryptsvc.dll`: reescribe el valor que tenía XDR (consúltalo
  primero, o reinstala el agente).

### `--restore` ignorado fuera de `sabotage`

`--restore` se pre-parsea en `main` pero solo tiene efecto en `sabotage`.
Pasarlo junto a `cytool`, `dumphash`, `crack` o `auto` se ignora
silenciosamente. En particular, `auto --restore` **no** restaura nada: ejecuta
la cadena completa de `auto` como si no llevaras el flag. Para restaurar, usa
`sabotage --restore` explícito.

### Flags cruzados

`--dll`, `--password`, `--wordlist`, `--out`, `--hash`, `--salt`,
`--iterations`, `--enable`, `--dry-run` se pre-parsean globalmente. Solo
tienen efecto en su subcomando; en el resto se descartan. Concretamente:

- `auto --out <ruta>` no escribe el volcado (eso es `dumphash --out`).
- `cytool --wordlist <ruta>` no usa la wordlist.
- `sabotage --password X` no cambia la contraseña de `cytool`.

Si algo no parece tener efecto, comprueba que estás usando el subcomando
correcto.

## Flujo de limpieza completo

```powershell
# 0. Ver el valor actual antes de tocar nada (imprescindible si no hay backup)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\CryptSvc\Parameters" /v ServiceDll

# 1. Restaurar ServiceDll (usa backup si existe; si no, BORRA el valor)
.\xdrtool.exe sabotage --restore

# 2. Borrar backup residual (si --restore no lo hizo)
Remove-Item -Recurse -Force "$env:ProgramData\xdrkill"

# 3. Borrar cualquier volcado de hash dejado por --out
Remove-Item -Force "$env:TEMP\xdrkill\h.json" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:TEMP\xdrkill_test_fixture" -ErrorAction SilentlyContinue

# 4. Reiniciar para que CryptSvc relea el valor
Restart-Computer
```

Tras el reinicio, `CryptSvc` volverá a cargar `cryptsvc.dll` (o el valor que
haya quedado tras `--restore`) y, si Cortex XDR está instalado y funcionando,
el agente recuperará su ciclo normal. Si el agente tenía protección
anti-manipulación activa y bloqueó alguna escritura, revisa los logs del
producto. Si tras el reinicio `CryptSvc` no arranca, revisa el valor de
`ServiceDll`: probablemente quedó borrado por un `--restore` sin backup.
