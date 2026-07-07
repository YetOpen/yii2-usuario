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
  cookie so browser clients can authenticate without touching the token in JS. The cookie is
  configurable on the `Module`: `apiTokenCookieName` (default `userToken`; set null/empty to
  disable) and `apiTokenCookieDuration` (seconds; `0` = session cookie). It is `SameSite=Strict`
  and `Secure` only over HTTPS (`request->isSecureConnection`). Keep the duration aligned with the
  token's own expiry.
