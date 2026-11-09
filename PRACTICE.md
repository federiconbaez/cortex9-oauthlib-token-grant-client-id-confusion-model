# Guía práctica (7 niveles)

Ejercicios **offline y locales** sobre el modelo. No hace falta oauthlib ni
red. Cada respuesta está comprobada en `tests/test_model.py`
(`Practice.test_practice_levels`).

**Alcance:** practica solo en tu propia máquina, en un laboratorio propio
(VM o contenedor local con tu propio servidor OAuth de prueba y clientes
creados por vos) o en máquinas de HTB/plataformas de práctica donde tengas
autorización expresa. Nunca contra servidores de autorización, clientes o
usuarios de terceros.

Comando:
`PYTHONPATH=src python3 -m oauthlib_model case pre|post <grant> confidential|public <autenticado> <set_client> <client_id|@missing> <scope|@empty> <ok|bad|-> arg|client`

**Básico**

1. **Lo normal.** `client_credentials`, autenticado `low`, `client_id=low`,
   `read`, en `pre`. (`TOKEN`)
2. **El control del GHSA.** Igual pero pidiendo `admin`. (`InvalidScopeError`)

**Intermedio**

3. **La confusión.** Autenticado `low`, `client_id=high`, `admin`, `pre`.
   ¿Con qué identidad se validó el grant y el scope? (`TOKEN_SPLIT`; como
   `high`; diff:127-132 con el relleno de diff:130 que no pisa el valor)
4. **El fix.** El mismo caso en `post`. ¿Qué línea lo corta? (`ServerError`,
   diff:125 y 58-61)
5. **Validador que mira `request.client`.** El caso 3 con política
   `client`. (`InvalidScopeError`: el scope se valida como `low`; aun así,
   con `read`, `pre` registra el token como `high`)

**Avanzado**

6. **Sin `client_id` en el cuerpo.** Autenticado `low`, `@missing`, `read`,
   `pre`, política `arg`. ¿Por qué falla? (`UnauthorizedClientError`: el
   grant se valida con `None` antes del relleno; observación del modelo)
7. **Cliente público.** `password`, `public`, el validador pone `other:low`,
   `client_id=high`, en `post`. (`ServerError`, diff:173 y 78-81)

**Defensa propia:** en tu propio servidor OAuth de laboratorio, escribí un
validador que autorice siempre desde `request.client` y un test que
rechace cualquier `client_id` del cuerpo distinto del cliente autenticado
antes de validar grant y scopes. Agregá un caso a `fixtures/cases.tsv` con
su etiqueta a mano, regenerá `fixtures/expected.tsv` con
`scripts/derive_expected.py` y comprobá que todo coincide.
