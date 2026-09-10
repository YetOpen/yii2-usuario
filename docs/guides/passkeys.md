# How to Implement and Use Passkeys

Passkeys let a user sign in with a WebAuthn credential (a platform authenticator such as Windows
Hello / Touch ID, or a roaming authenticator such as a YubiKey) instead of a password.

## Requirements and preconditions

- **PHP >= 8.1** and the WebAuthn stack, which is an optional dependency:

  ```bash
  composer require web-auth/webauthn-framework spomky-labs/cbor-php symfony/uid
  ```

- **HTTPS is mandatory.** Browsers only expose the WebAuthn API on secure origins (`https://`, or
  `http://localhost` for development). Nothing works over plain `http` on a real host.
- **A server-side session.** The ceremony challenge is stored in the session; a session-less or
  fully stateless setup is not supported.
- The **Relying Party ID** is derived from `Yii::$app->request->hostName`. Credentials are bound to
  that host: if the application domain changes, previously registered passkeys stop working and
  users must register new ones.

## Enabling passkeys

1. **Run the migration** that creates the `user_entity` table:
   [`m000000_000011_create_user_entity_table.php`](../../src/User/Migration/m000000_000011_create_user_entity_table.php)

2. **Turn the feature on** in your module configuration:

   ```php
   'modules' => [
       'user' => [
           'class' => Da\User\Module::class,
           'enablePasskeyLogin' => true,
       ],
   ],
   ```

   `enablePasskeyLogin` is a real kill switch: while it is `false` every passkey route (including the
   login ceremony) returns `404`, so disabling it also revokes passkey access, not just the button
   on the login form.

Once enabled, a **Passkey Login** button appears on the usuario login form. It does nothing until
the signed-in user has registered at least one passkey from
`/user/user-entity/index-passkey` (or the pretty route `user/passkey/index`).

## Attestation

Registration is performed with `attestation: 'none'`: the server does **not** verify an attestation
certificate chain and therefore does not need a FIDO Metadata Service repository. The
`attestation_type` column records the attestation type the authenticator reported
(`none | basic | self | attca | anonca`), for information only — in practice this is almost always
`none`. Packed / TPM / Android Key *attestation formats* are not validated or required.

## Discoverable (resident) credentials

Registration requests `residentKey: 'required'`. The login ceremony sends an **empty**
`allowCredentials` list and relies entirely on the authenticator picking a discoverable credential
for the RP. Consequence: a non-discoverable credential can never be used to sign in. This is why the
`residentKey` requirement is load-bearing and must not be relaxed.

## Two-factor authentication

By default a passkey login is treated as a complete, strong authentication: a user who also has 2FA
enabled is **not** asked for the second factor after a passkey login (a verified passkey is device
possession + user verification, and is phishing-resistant).

If an organisational policy requires the second factor regardless of the login method, set:

```php
'passkeyLoginRequiresTwoFactor' => true,
```

With that flag on, a passkey login is refused for any account that has 2FA enabled and the user is
asked to sign in with password + 2FA instead.

Passkey logins go through the same account-state checks as a password login: blocked accounts and
(when `enableEmailConfirmation` is on and `allowUnconfirmedEmailLogin` is off) unconfirmed accounts
are rejected.

## Views / routes

- `user/passkey/index` (`/user/user-entity/index-passkey`) — list and manage the current user's passkeys.
- `user/passkey/create` (`/user/user-entity/create-passkey`) — register a new passkey.

## Expiration and maintenance

```php
'modules' => [
    'user' => [
        'class' => Da\User\Module::class,
        'enablePasskeyPopUp' => true,
        'enablePasskeyExpiringNotification' => true,
        'maxPasskeysForUser' => 10,
        'maxPasskeyAge' => 365,
        'passkeyExpirationTimeLimit' => 30,
    ],
],
```

- `enablePasskeyPopUp` — after a password login, show a modal suggesting the user register a passkey
  (only when they have none and `enablePasskeyLogin` is on).
- `enablePasskeyExpiringNotification` — after login, show a modal for passkeys entering their expiry
  window. Dismissing it three times hides it for that passkey; this is a best-effort browser cookie,
  not a per-user, cross-device setting, and it resets when cookies are cleared.
- `maxPasskeysForUser` — hard cap per user (typically 5–10).
- `maxPasskeyAge` — days of inactivity after which a passkey is considered expired (typically
  180–365).
- `passkeyExpirationTimeLimit` — days before expiry that the warning starts showing (typically
  15–30).

To actually delete expired passkeys, schedule the console command (e.g. daily):

```bash
php yii user/user-entity/delete-expired-passkeys
php yii user/user-entity/delete-expired-passkeys --dryRun   # report only, no deletion
```

It reads the live module configuration (so `maxPasskeyAge` in the **console** config applies) and
never deletes a user's last remaining passkey. A passkey row holds the only copy of its public key,
so deletion is irreversible — start with `--dryRun`.

## Widgets

Add these to a layout or dashboard view to render the pop-ups configured above:

```php
echo \Da\User\Widget\UserEntityPasskeyWidget::widget();   // "register a passkey" suggestion
echo \Da\User\Widget\UserEntityExpiringWidget::widget();  // "a passkey is expiring" notice
```
