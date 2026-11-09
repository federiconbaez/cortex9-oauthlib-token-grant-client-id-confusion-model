# cortex9-oauthlib-token-grant-client-id-confusion-model

Modelo offline de **CVE-2026-118669** (GHSA-7984-qgvg-3j9c): en OAuthLib
anterior a 4.0.0 los handlers de token autentican `request.client` como un
cliente pero conservan el `client_id` que el atacante pone en el cuerpo y
se lo pasan a `validate_grant_type()` y `validate_scopes()`. Un cliente que
se autentica como `low` y envía `client_id=high` obtiene los controles de
grant y scope como `high` si el validador de la aplicación autoriza por el
argumento `client_id`. Corregido en el commit
[c951a1d09f99](https://github.com/oauthlib/oauthlib/commit/c951a1d09f99f14e3240973fa83c4f4287d4753d)
(`pre` = antes, `post` = después), publicado en 4.0.0.

Educativo, offline, determinista, solo stdlib de Python. No se instala ni
importa oauthlib y no se hace ningún request HTTP. El validador es el demo
en memoria de la PoC del GHSA (`low`: scope `read`; `high`: `read admin`)
más `batch`, que solo puede usar `client_credentials`.

Inglés: [README.md](README.md). Ejercicios: [PRACTICE.md](PRACTICE.md).

## Qué cambia el fix (líneas del diff guardado)

- `client_credentials` (diff:117-124, 130): antes se autenticaba, se
  comprobaba el atributo, se validaba el grant con el `client_id` del
  cuerpo y *después* `client_id = client_id or client.client_id`. Ahora
  `validate_client_confidential` (diff:125) va antes del grant.
- `password` (diff:165, 173, 180-184, 190-191): la autenticación pasa a
  `validate_token_request` y se elimina el relleno posterior.
- `authorization_code`, `refresh_token`, `device_code` (diff:23-28,
  150-152, 235-243): se eliminan los rellenos locales.
- base.py (diff:41-81): tras autenticar, `client` debe tener `client_id`
  (52-56 / 72-76); si falta `client_id` se completa (58-59 / 78-79); si
  difiere, `ServerError` (60-61 / 80-81).

## Evidencia diferencial

| Caso | pre | post |
|---|---|---|
| `p01` PoC del GHSA, `client_credentials`, auth `low`, `client_id=high`, `admin` | `TOKEN_SPLIT` con `admin` | `ServerError` |
| `p02` igual con `password` | `TOKEN_SPLIT` | `ServerError` |
| `p03` `batch` (sin grant password) con `client_id=high` | `TOKEN_SPLIT` | `ServerError` |
| `p05` cliente público, el validador pone otro cliente | `TOKEN_SPLIT` | `ServerError` |
| `n01`, `n02` controles del GHSA | `InvalidScopeError` | igual |
| `a01` sin `client_id` en el cuerpo | `UnauthorizedClientError` | `TOKEN` |
| `a03` validador que autoriza por `request.client` | `TOKEN_SPLIT` (scopes de `low`, token registrado como `high`) | `ServerError` |

Barrido de 7.200 casos: `post` nunca termina con identidades distintas;
cada `split` de `pre` pasa a `ServerError` o `NotImplementedError`; si el
`client_id` del cuerpo es el del cliente autenticado, el fix no cambia nada.

**Observaciones del modelo, no hallazgos:** en `pre`, `client_credentials`
sin `client_id` en el cuerpo llama a `validate_grant_type(None, …)`; y
`refresh_token` con un cliente sin `client_id` lanza `AttributeError` en
diff:151-152. Ambas dependen del validador demo.

## Uso

```sh
python3 tests/run.py
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/derive_expected.py sweep | diff - results/sweep.csv
PYTHONPATH=src python3 -m oauthlib_model results fixtures/cases.tsv /tmp/r && diff -r results /tmp/r
```

Ver [LIMITATIONS.md](LIMITATIONS.md) y [SOURCES.md](SOURCES.md).
Licencia: Apache-2.0.
