# Limitations

- **A model is not a finding.** This repo re-states public behaviour from
  CVE-2026-118669, its advisory and the fix commit. Nothing here is a new
  vulnerability, and nothing was run against oauthlib (the GHSA PoC was not
  executed; its validator is re-implemented in memory).
- **Partial handlers.** Only client authentication, the client-id binding,
  `validate_user` (password), `validate_grant_type` and `validate_scopes`
  are modelled. Request parsing, duplicate-parameter checks, custom
  validators, token creation, PKCE, code / refresh-token / device-code
  validation are not: those grants stop at `STAGE_OK`.
- **Validator-dependent.** The impact depends on the application
  validator. Policy `arg` follows the GHSA PoC; policy `client` authorises
  from `request.client`, which the advisory says may not be affected (the
  model still shows the recorded `client_id` differing in `pre`).
- **Error names, not HTTP.** Labels use oauthlib exception names. The
  advisory suggested `InvalidClientError` for a mismatch; the fix raises
  `ServerError('Discrepency found between client identifier')` (diff:61,
  81, upstream spelling). HTTP status codes and JSON bodies are not
  modelled.
- **Exact string comparison** only, as `!=` in diff:60/80. Normalisation of
  client IDs by a validator is out of scope.
- **Direct calls.** In `pre`, ROPC's client authentication sits in
  `create_token_response` (diff:165), so calling `validate_token_request`
  directly skips it; the model uses the endpoint path only and does not
  model that difference.
- **Supplementary files.** `validate_grant_type` / `validate_scopes` and the
  pre-fix handler bodies were read from files fetched live at the parent
  commit; they are not in `sources/cve2026/SHA256SUMS` (hashes in
  SOURCES.md).
- **Versions.** Only before/after c951a1d09f99 is modelled; "< 4.0.0
  affected" comes from the advisory.
- **Sweep** is a fixed grid of 7,200 cases, not a proof.
