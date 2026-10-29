# rayvault

Secretos por la red, escrito en [raylang](https://github.com/ray-language/raylang). Un proceso pide
un secreto con un access token de [rayauth](../rayauth), por client credentials si es un servicio o
con su sesión si es una persona; las políticas dicen qué ruta puede leer o escribir cada cuenta, cada
cliente o cada grupo. Los secretos se guardan cifrados, el servidor arranca sellado, y cada petición
queda en un log de auditoría encadenado por hashes.

```
$ rayvault serve
rayvault 0.1.0: https://127.0.0.1:8200, data in data, tokens from https://auth.example with scope 'vault', 2 policies; sealed until `rayvault unseal`

$ rayvault init                        # una vez: la frase de desbloqueo, y el token raíz
$ RAYVAULT_TOKEN=rvr_… rayvault put apps/notes/db 'postgres://notes:…@db/notes'
apps/notes/db: version 1

$ export RAYVAULT_ISSUER=https://auth.example RAYVAULT_CLIENT_ID=… RAYVAULT_CLIENT_SECRET=…
$ rayvault get apps/notes/db           # el servicio, con su propio token de rayauth
postgres://notes:…@db/notes
$ rayvault wrap apps/notes/db --ttl 10m
rvw_6f1c…                              # para alguien sin acceso: sirve una sola vez
```

```
rayvault serve [--config rayvault.toml]
rayvault init | unseal | seal | status        frase por teclado o RAYVAULT_PASSPHRASE
rayvault audit verify [FILE]
rayvault get PATH [--version N] | put PATH VALUE [--ttl 24h] | ls [PREFIX] | rm PATH
rayvault wrap PATH [--ttl 10m] | unwrap TOKEN | whoami
  --addr URL (RAYVAULT_ADDR), --insecure (solo desarrollo; confía en una CA con SSL_CERT_FILE)
```

## Estado

| Qué | Estado |
|---|---|
| Identidad por access tokens RFC 9068 de rayauth (firma contra el JWKS, `iss`, `exp`, `typ: at+jwt`, scope exigido) | ✅ |
| Audiencia (`aud`) opcional, para emisores con RFC 8707 | ✅ (rayauth no la da, #290) |
| Token raíz `rvr_` (solo se guarda su SHA-256), para arrancar y para sellar | ✅ |
| Políticas: `client:ID`, `user:NAME`, `group:NAME` × rutas (`exacta`, `prefijo/*`, `*`) × `read write list delete wrap` | ✅ |
| Cifrado en reposo: ChaCha20-Poly1305 por valor, con ruta y versión como AAD | ✅ |
| Clave de datos envuelta por PBKDF2 (600 000 iteraciones) de la frase; arranque sellado, `seal`/`unseal` | ✅ |
| Versiones (las 10 últimas), `?version=N`, secretos con caducidad (`ttl`) | ✅ |
| Envoltorios de un solo uso (`wrap`/`unwrap`) con caducidad | ✅ |
| Auditoría: una línea por petición, sin valores, encadenada por SHA-256, `fsync` antes de responder | ✅ |
| `init` solo desde la propia máquina | ✅ |
| TLS (PEM de la configuración) | ✅ |
| Secretos dinámicos (credenciales de base de datos con lease), varias frases (Shamir), HA | ➖ v2 |

Pruebas: 5 tests (`make test`, `make test-native`), en VM y nativo, con un emisor propio en el test
(clave Ed25519, JWKS por `oidc/provider.with_keys`, tokens firmados ahí: cuenta de servicio, persona
con grupo, otra audiencia, sin el scope, caducado, firmado con otra clave). Y `make interop` (23
comprobaciones): un rayauth de verdad con dos cuentas de servicio, TLS con una CA propia hecha con
`openssl`, y la CLI pidiendo su token por client credentials.

## Cómo

```
src/main.ray     la línea de órdenes: servidor y cliente
src/config.ray   rayvault.toml y las políticas
src/server.ray   todo junto: la bóveda, la auditoría, el API por HTTP(S)
src/api.ray      el API (JSON)
src/auth.ray     quién llama: token raíz o access token de rayauth
src/vault.ray    la bóveda: una fibra dueña de SQLite y de la clave de datos
src/keyring.ray  las claves: envolver la de datos, sellar cada valor, los tokens
src/audit.ray    el log de auditoría encadenado
```

- **La clave de datos solo vive en una fibra.** La bóveda la tiene en memoria mientras está abierta;
  los handlers le mandan el texto a sellar y reciben el texto abierto, y nunca la clave. Sellar
  la olvida; reiniciar también.
- **En disco no hay nada legible.** Cada valor va cifrado con un nonce nuevo y con
  `rayvault:v1:<ruta>#<versión>` como datos asociados: un cifrado copiado a otra fila no se abre.
  La clave de datos está envuelta por una clave derivada de la frase de desbloqueo. Los tokens raíz
  y de envoltorio se guardan como SHA-256.
- **Un envoltorio se gasta antes de entregarse**: la fila se borra y después se abre el secreto.
- **Sin auditoría no hay respuesta.** Cada petición, permitida o no, se escribe y se sincroniza
  (`fs.sync_data`) antes de contestar; si el log no se puede escribir, la respuesta es un 500 sin el
  secreto. Cada línea lleva el SHA-256 de la anterior: `rayvault audit verify` dice en qué línea se
  rompe la cadena (una edición, un borrado, un cambio de orden), y el servidor no arranca sobre una
  cadena rota.
- **Los sujetos salen del token**: `client:<client_id>`, `user:<sub>`, `user:<preferred_username>` y
  un `group:` por cada grupo. Con rayauth, una cuenta de servicio es `client:` + su id.

## Hallazgos de dogfood

En `../findings/open/rayvault-1.27.85.md`. Re-medido con 1.27.86 y oidc 0.2.0: #289 arreglado (`verify_access_token_for`); #290 (rayauth) sin re-medir.

Lo que se encontró con 1.27.85:

- **#289 [B] oidc**: `tokens.verify_access_token` no comprueba `aud`, y un token para otro API del mismo
  emisor pasa. rayvault la comprueba aparte cuando se configura una audiencia.
- **#290 [E] rayauth**: sus access tokens llevan `aud` = el client_id que los pidió, y el parámetro
  `resource` (RFC 8707) se ignora, así que ningún API puede exigir su audiencia; rayvault exige el
  scope `vault`.

Lo que salió bien: `oidc/provider.with_keys` permitió probar la verificación de tokens sin red, y
los 5 tests y las 23 comprobaciones pasaron también en nativo. El cripto de `std/crypto` (PBKDF2,
ChaCha20-Poly1305, Ed25519, `constant_time_eq`) compuso sin un rodeo. Lo único raro fue de TLS y era
correcto: rustls rechaza un certificado autofirmado usado como el del propio servidor
(`CaUsedAsEndEntity`), y la interoperabilidad usa una CA propia.
