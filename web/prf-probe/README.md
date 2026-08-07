# PRF + JSPI capability probe

Static, dependency-free. Decides decision **D4** (mosh-key-at-rest) and
validates **D6** (Firefox mobile Nightly + JSPI flag as a target).

Deploy `index.html` to the target GitHub Pages origin (the RP ID the real
client will use — WebAuthn results from another origin do not transfer),
then on each browser/authenticator combination:

1. open the page (https required),
2. run `1. create()` then `2. get()`,
3. `copy report` and paste the JSON into the README findings.

Combinations that matter, per D4/D6:

- Firefox mobile Nightly (JSPI flag on) + platform authenticator — on
  Android, Firefox delegates WebAuthn to Play Services FIDO2, so this
  measures that stack as much as Firefox.
- Firefox mobile Nightly + NFC/USB security key, if that path is in use.
- Desktop Chromium and Firefox as baselines.

Decision rule: `prf-enabled-at-create`, `prf-eval-at-get`, and
`prf-deterministic` all PASS on the combinations you care about ⇒ D4
takes the PRF-wrap + proxy-escrow arm. Any relied-upon combination FAILs
⇒ plaintext-localStorage arm.

Known interference: password-manager extensions wrap
`navigator.credentials.*` and can fail inside themselves with
non-WebAuthn errors (seen: `tabs.update` "highlighted" TypeError — a
Chrome-only extension API, on Firefox). The page calls the
`CredentialsContainer.prototype` methods to bypass own-property
wrappers and reports `webauthn-unwrapped`; if a run still fails with a
non-WebAuthn error, retry in a private window or with extensions
disabled — that result says nothing about the platform.

Local trial run (not a substitute — origin and authenticator differ):

    python3 -m http.server -d web/prf-probe 8000   # http://localhost:8000
