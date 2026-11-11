# CompareShopAuthAPI

Dedicated authentication API for CompareShopUI customers. The application uses ASP.NET Core Identity with PBKDF2-HMAC-SHA256 (310,000 iterations), SQL Server persistence, RS256 access tokens and hashed refresh/reset/verification credentials.

## Configuration

Supply configuration through the environment or the deployment Secret. Do not commit key material or connection credentials.

- `ConnectionStrings__Auth`: dedicated `CompareShopAuth` database connection.
- `Jwt__PrivateKeyPem` or `Jwt__PrivateKeyPath`, `Jwt__KeyId`, `Jwt__Issuer`, `Jwt__Audience`; optional `Jwt__PreviousPublicKeyPem` and `Jwt__PreviousKeyId` keep the prior signing key verifiable during rotation.
- `Outbox__EncryptionKey`: base64 encoded 256-bit AES-GCM key.
- `Pin__Pepper` and `Throttle__HashKey`: independent random secrets used to hash reset PINs and throttle identifiers.
- `RabbitMQ__Host`, `RabbitMQ__Username`, `RabbitMQ__Password`, `RabbitMQ__EmailCommandQueue`: authenticated broker connection and durable versioned command queue.
- `Cors__UiOrigin` and `CompareShopUI__BaseUrl`: the exact UI origin and configured link base.
- `Turnstile__Enabled`, `Turnstile__Secret`, and `Turnstile__AllowedHostnames`. The `example.com` test hostname exists only in Development configuration. `Turnstile__AllowUnavailableInDev` defaults to false and only bypasses siteverify transport failures in Development.
- `SecurityTiming__MinimumDurationMs` (default `250`) and `SecurityTiming__JitterMs` (default `25`) pad register, login, and forgot-password responses to reduce account-enumeration timing differences.

The app does not run schema changes at startup. Apply the checked-in EF migrations using the deployment migration identity, then run the app with its least-privilege runtime database credential.

## Auth routes

The `/api/v1/auth` group provides register, verify-email, resend-verification, login, refresh, logout, forgot-password, verify-reset-code, reset-password, change-password, and me routes. Refresh credentials are rotated opaque values in the `__Secure-CS-Refresh` HttpOnly cookie. The public signing keys are exposed at `/.well-known/jwks.json` and `/api/v1/auth/jwks`.

Forgot-password issues a six-digit PIN that expires after ten minutes. Five failed attempts invalidate it; a new request replaces the old PIN. A valid PIN exchanges for a five-minute, single-use reset token. Public email responses remain generic.
