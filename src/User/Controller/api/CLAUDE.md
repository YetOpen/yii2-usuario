# API controllers

Active REST API controllers live here (the `rest/` sibling folder is deprecated).

## Authorization model

- `AdminController` — every action calls `checkAccess()`, which requires
  `module->enableRestApi` and `Yii::$app->user->identity->isAdmin`. Keep this
  guard on any new action.
- `AuthController` — RBAC introspection endpoints (`roles`, `permissions`) must
  scope their output by privilege: **admins** (`identity->isAdmin`) get the full
  RBAC set (`authManager->getRoles()` / `getPermissions()`); **any other user**
  gets only what is assigned to them (`getRolesByCurrentUser()` /
  `getPermissionsByUser($userId)`). Never return the whole RBAC map to a
  non-admin — it leaks the authorization schema.
- Authentication is via `JwtHttpBearerAuth` / `module->authenticatorClass`.
  Authentication alone is NOT authorization — add an explicit privilege check.

## `RecoveryController` (password recovery over REST)

REST twin of the web `Da\User\Controller\RecoveryController`, for a decoupled frontend.
All actions are **public** (`authenticator` unset) — a pre-auth flow whose only credential
is the recovery token.

- `POST recovery/request` (`{ email }`) → **always** `{ ok: true }`, whether or not the
  address is registered and whether or not the mail sent (upstream failures are only
  logged). Never let this differ by outcome — it would enumerate users.
- `GET recovery/reset?token=` → `{ valid: bool }`; `POST recovery/reset` (`{ token,
  password }`) → `{ ok: true }`. Two distinct failure shapes on purpose: a bad/expired token
  is a generic **400** (token state must stay ambiguous — no leak of *why*); a password that
  fails validation/policy is a **422** with `[{field, message}]` (the chosen-password detail
  is not sensitive, so the client can show the requirement the user must meet).
- The web `(id, code)` pair travels as one opaque token — `Token::getApiToken()` /
  `Token::splitApiToken()`.
- **Reset link points at the frontend, not the backend.** The email URL comes from
  `Module::$passwordRecoveryUrl` (a `{token}` template) via
  `PasswordRecoveryService::setResetUrlTemplate()`. This is backend config on purpose: the
  link host must never be client-supplied (reset-email host injection → phishing). When the
  property is unset, the request action logs an error and still returns `{ ok: true }`.
- The recovery token is **deleted after a successful reset** (single use, no replay), via
  `Token::deleteAll()` — **not** the AR instance `delete()`. `delete()` fires
  `EVENT_BEFORE_DELETE`, which a host app may hook to gate deletions on a user permission; since
  reset is unauthenticated, that guard would silently veto the cleanup and leave the token
  replayable. `deleteAll()` issues a plain `DELETE` with no AR events.

## `SecurityController::actionLogin`

- Token value comes from `User::getAccessToken()` (base impl throws `NotSupportedException`;
  apps override — e.g. to return a JWT). The action stays token-format agnostic.
- On success the token is returned in the body (`{ "token": ... }`) **and** set as an httpOnly
  cookie (see `sendAccessTokenCookie()`) so clients can persist it without touching the token in
  JS. Configurable on the `Module`:
  - `apiTokenCookieName` (default `userToken`; null/empty disables the cookie),
  - `apiTokenCookieDuration` (seconds; `0` = session cookie — keep aligned with the token expiry),
  - `apiTokenCookieSameSite` (`Strict`/`Lax`/`None`; `None` needs HTTPS),
  - `apiTokenCookieRaw` (default `false`). When `false` the cookie goes through the response cookie
    collection and, if `cookieValidationKey` is set, its value is Yii's signed/serialized envelope
    (readable only by this app — fine for cookie-based auth on this backend). When `true` the
    cookie carries the **bare token** via a hand-built `Set-Cookie` header, so an SSR/BFF layer can
    read it and forward it as a `Bearer` credential.
  - `Secure` is added automatically over HTTPS (`request->isSecureConnection`).
