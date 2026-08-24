# Architecture Overview

## 1. Purpose and boundaries

The service records an append-only history of audit events and provides controlled read, verification, retention, redaction, and export operations. The prototype focuses on service-layer correctness and evidence of tamper detection. It does not attempt to replace a full enterprise identity provider, key-management system, or immutable storage platform.

## 2. Components

```text
HTTP client
   |
   v
AuditLogsController
   |-- validates identity Using JWT token
   |-- maps requests to service operations
   v
EventService
   |-- creates events
   |-- queries and paginates
   |-- verifies hash chain
   |-- applies retention and redaction
   |-- builds export bundles
   |
   +--> EventRepository --> relational database
   |
   +--> PayloadMerkleHasher
           |-- seals payloads
           |-- computes deterministic leaf/root hashes
           |-- supports redaction-safe verification

UserRepository --> UserService --> controller authorization
```

## 3. Data model

### Event

| Field | Purpose | Integrity role |
|---|---|---|
| `id` | Database identifier and chain ordering | Determines verification order |
| `eventType` | Action classification | Included in event hash |
| `actorId` | Actor or system identity | Included in event hash |
| `resourceType` | Resource category | Included in event hash |
| `resourceId` | Affected resource | Included in event hash |
| `payload` | User-visible structured payload | Returned by APIs |
| `sealedPayload` | Internal payload with salts and leaf hashes | Used for hash recomputation; not exposed |
| `timestamp` | Server-assigned event time | Included in canonical hash input |
| `hash` | Hash of the event content and predecessor link | Detects event changes |
| `previousHash` | Hash of the immediately preceding event | Links the chain |
| `status` | Active or archived state | Supports retention without deletion |

### User

| Field | Purpose |
|---|---|
| `userId` | Auto-generated primary key |
| `username` | User identity attribute |
| `userType` | `ADMIN`, `REGULATOR`, or `USER` |
| `userEmail` | Unique lookup attribute |

## 4. Hash-chain design

The event hash is calculated as SHA-256 over a canonical representation:

```text
eventType | actorId | resourceType | resourceId |
payloadRootHash | canonicalTimestamp | previousHash
```

The first record uses a defined null/empty predecessor value. Each later record stores the prior record's hash in `previousHash`.

Verification walks records in ascending ID order and performs two checks for every record:

1. Recalculate the record's hash from current database values and compare it with the stored hash.
2. Compare the record's `previousHash` with the expected predecessor hash.

The first failure is returned with its record ID and violation description.

## 5. Deterministic timestamp handling

The database may store an `Instant` with lower precision than Java originally created. The hash utility therefore converts timestamps into one canonical UTC representation before hashing. The current implementation uses a precision compatible with the configured database column. The database precision and hash precision must remain documented and tested together.

## 6. Payload sealing and redaction

At creation time, the payload is sealed into the internal `sealedPayload` field. Per-field salts and leaf hashes are stored there, not in the visible `payload` field.

The payload root is calculated from sorted field leaf hashes. During authorized redaction:

- The visible payload field is set to `null`.
- The corresponding field in `sealedPayload` is also set to `null`.
- The original leaf hash remains in sealed metadata.
- Verification uses the preserved leaf hash for the redacted field.
- The event hash and chain links remain unchanged.

This preserves tamper evidence while preventing the original sensitive value from being returned.

### Redaction trade-off

Redaction intentionally preserves evidence that a value existed and preserves its original leaf hash, but it does not permit reconstruction of the value from the hash. The sealed metadata is sensitive integrity material and must not be exposed through the API. The prototype stores it in the same database row; a hardened design could separate it into a restricted integrity table or use an external integrity store.

## 7. Retention design

Records older than the configured window are marked `ARCHIVED` rather than physically deleted. Archived rows remain available to chain verification, preserving the historical sequence and avoiding a false positive caused by a missing predecessor. Physical deletion is outside the current prototype because deletion would require a separately designed checkpoint/genesis strategy.

## 8. RBAC design

| Operation | ADMIN | REGULATOR | USER |
|---|---:|---:|---:|
| Create | Yes | No | No |
| Query | Yes | Yes | No |
| Verify | Yes | No | No |
| Retention | Yes | No | No |
| Redact | Yes | No | No |
| Export | Yes | Yes | No |

The prototype resolves the user from `username` and `useremail` headers. This is a development-scoped identity mechanism, not production authentication.

## 9. Export design

The export endpoint returns CSV containing event data and chain metadata derived from `hash` and `previousHash`. It is self-contained enough for a recipient to inspect the records and verify the included links, provided the recipient has the verification algorithm and the relevant chain context. A production bundle should additionally include a signed manifest, export timestamp, schema version, and explicit boundary metadata for filtered subsets.

## 10. Key decisions and alternatives

| Decision | Rationale | Trade-off |
|---|---|---|
| SHA-256 | Widely available and deterministic | Does not provide authenticity without a protected trust anchor |
| Server-assigned timestamps | Prevents callers from backdating events in the prototype | Requires a clear distinction between occurrence time and ingestion time |
| Database ID ordering | Simple chain ordering in a single service | Requires careful concurrency control and does not by itself solve multi-writer ordering |
| Archive instead of delete | Preserves chain history | Retains rows and requires storage planning |
| Separate `sealedPayload` | Keeps integrity metadata out of API responses | Adds storage and schema migration complexity |
| Simple RBAC | Matches current roles and endpoints | Less granular than permission-based authorization |
