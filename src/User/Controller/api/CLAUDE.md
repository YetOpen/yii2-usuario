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
