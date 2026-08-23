# Tamper-Evident Audit Log Service

A Spring Boot prototype for recording, querying, verifying, retaining, redacting, and exporting audit events. The service is designed around an append-only event history and a SHA-256 hash chain.

> This document is a repository deliverable template. Update paths, commands, database details, and endpoint examples to match the final codebase before submission.

## Assignment coverage

|Scenario|Capability|Status|
|-|-|-|
|A|Event creation|Implemented|
|A|Filtered and paginated queries|Implemented|
|A|Hash-chain verification|Implemented|
|A|Direct data-store tamper detection|Implemented and tested|
|B|Retention/archive handling|Implemented|
|B|Structured redaction without changing the event hash|Implemented|
|B|CSV bulk export with chain metadata|Implemented|
|C|Compliance requirement clarification and RBAC design|Implemented in scope described below|

## Prerequisites

* Java 
* Maven 
* Git

## Run locally

1. Clone the private repository.
2. Configure the database URL, username, password, and application port.
3. Start the service:

```bash
./mvnw spring-boot:run
```

4. Confirm the service is running:

```bash
curl http://localhost:8081/actuator/health
```

Replace the command and port if the project uses different values.

## API overview

Base path: `/audit`

|Method|Endpoint|Purpose|Role|
|-|-|-|-|
|POST|`/createEvent`|Append an event|ADMIN|
|GET|`/events`|Query events with filters and pagination|ADMIN, REGULATOR|
|GET|`/verify`|Verify the complete chain|ADMIN|
|PUT|`/checkForRetention`|Apply the retention policy|ADMIN|
|PUT|`/redact`|Redact selected payload fields|ADMIN|
|GET|`/export`|Export events for an actor or resource|ADMIN, REGULATOR|

All protected endpoints require the headers `username` and `useremail` in the current prototype.

## Example event

```json
{
  "eventType": "USER\_LOGIN",
  "actorId": "A1234",
  "resourceType": "webapp",
  "resourceId": "R1234",
  "payload": "{'userName':'u1','action':'loggedin'}"
}
```

The server assigns the timestamp during creation. The service stores the visible payload separately from the internal sealed payload used for deterministic hashing.

## Verification behavior

`GET /audit/verify` recalculates each event hash from the current database values and verifies its `previousHash` link. It reports the first invalid event and the violation type.

Expected outcomes:

* Unmodified chain: intact.
* Authorized redaction through `/redact`: intact; the event hash is preserved.
* Direct modification of protected event data: event hash mismatch.
* Direct modification of an earlier stored hash: the modified event fails its own hash check; later links are no longer trusted.
* Broken `previousHash`: previous-hash mismatch.

## Export behavior

`GET /audit/export` returns `text/csv` with `Content-Disposition: attachment; filename="Event\_Bundle.csv"`. Postman may display the CSV inline; use “Send and Download” or save the response as a `.csv` file.

## Testing

Run the project test command:

```bash
./mvnw test
```

The test suite covered:

* Event creation and hash generation.
* Empty and populated payloads.
* Query filters and pagination.
* First-record genesis behavior.
* Multiple-event chain verification.
* Direct database modification detection.
* Redaction preserving the original hash.
* Retention archiving without a false chain break.
* Export content type, headers, escaping, and chain metadata.
* RBAC permissions and missing/invalid headers.

