# Tamper-Evident Audit Log Service

Spring Boot service for recording, querying, verifying, retaining, redacting, and exporting audit events. Events are append-only and linked by a SHA-256 hash chain.

## Prerequisites

* Java 17
* Maven 3.9+ (or the included `mvnw` / `mvnw.cmd`)

## Local run (prototype profile)

The default profile is for local development. It uses an H2 file database, allows the H2 console, and ships prototype JWT/CORS values. **Do not use those defaults in production.**

```bash
./mvnw spring-boot:run
```

Windows:

```bash
.\mvnw.cmd spring-boot:run
```

The API listens on `http://localhost:8081`. Application users must already exist in the H2 `USERS` table (username, bcrypt password, `user_type`, `user_email`). The service does not seed users on startup.

Login:

```bash
curl -s -X POST http://localhost:8081/audit/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"YOUR_USER\",\"password\":\"YOUR_PASSWORD\"}"
```

Use the returned token as `Authorization: Bearer <token>` on all other `/audit` endpoints.

## API

Base path: `/audit`

| Method | Endpoint | Purpose | Roles |
| --- | --- | --- | --- |
| POST | `/auth/login` | Issue JWT | Public (rate limited) |
| POST | `/createEvent` | Append an event | ADMIN |
| GET | `/events` | Query events | ADMIN, REGULATOR |
| GET | `/verify` | Verify the complete hash chain | ADMIN |
| PUT | `/checkForRetention` | Archive events older than `days` | ADMIN |
| PUT | `/redact` | Redact selected payload fields | ADMIN |
| GET | `/export` | CSV export with chain metadata | ADMIN, REGULATOR |

## Security controls (current)

* JWT HS256 with `iss`, `aud`, and unique `jti` validation (`audit.jwt.issuer`, `audit.jwt.audience`, `audit.jwt.require-jti`).
* CORS allowlist (`http://localhost:8080`, `8081`, `8082`), methods GET/PUT/POST, header `Authorization`, exposed `Content-Disposition`, `allowCredentials=false`, preflight `maxAge=3600`.
* Login rate limit: 5 failed attempts per username+IP in 15 minutes, then HTTP `429`. Successful login resets the window. Error bodies do not disclose whether a username exists.
* Request limits: multipart/request 1 MB, payload field max 8192 characters. Oversized bodies return `400` (Bean Validation) or `413` (request too large). Error responses do not echo payload contents.

## Production profile

Activate with `--spring.profiles.active=prod`. This profile:

* Requires secrets from the environment (`AUDIT_JWT_SECRET`, `AUDIT_DB_USERNAME`, `AUDIT_DB_PASSWORD`, CORS, TLS keystore).
* Disables the H2 console and SQL logging.
* Sets `spring.jpa.hibernate.ddl-auto=validate`.
* Enables Flyway migrations from `src/main/resources/db/migration`.
* Enables TLS (`AUDIT_TLS_ENABLED`, `AUDIT_TLS_KEYSTORE`, `AUDIT_TLS_KEYSTORE_PASSWORD`).

Example:

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=prod
```

Set at least:

```text
AUDIT_JWT_SECRET
AUDIT_DB_USERNAME
AUDIT_DB_PASSWORD
AUDIT_CORS_ALLOWED_ORIGINS
AUDIT_TLS_KEYSTORE
AUDIT_TLS_KEYSTORE_PASSWORD
```

Prototype `application.properties` values are not copied into production.

## Testing

Run tests, Surefire reports, and JaCoCo coverage with the check thresholds:

```bash
./mvnw verify
```

Windows:

```bash
.\mvnw.cmd verify
```

Artifacts:

* Surefire: `target/surefire-reports/`
* JaCoCo HTML: `target/site/jacoco/index.html`
* JaCoCo CSV: `target/site/jacoco/jacoco.csv`

Coverage gates (JaCoCo `check` during `verify`):

* Line coverage minimum **0.99**
* Branch coverage minimum **0.90**

The suite covers JWT claim validation, CORS, RBAC, login rate limiting, payload size limits, and direct SQL tamper detection.
