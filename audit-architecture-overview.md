AUDIT SYSTEM - ARCHITECTURAL OVERVIEW

1. Scenario A - Write API

Timestamp

The timestamp represents when the event occurred.

The system uses server-assigned timestamps.

Server-assigned timestamps are the correct choice because they guarantee accuracy, consistency, and prevent tampering.

If the client supplies the timestamp, it can be manipulated or incorrect, for example because of a wrong system clock or malicious tampering.

Multiple clients can be in different time zones or have clocks that drift.

The server provides a single authoritative time source, making logs reliable.

If timestamps are caller-supplied, an attacker could backdate or forward-date events to hide activity.

Server-assigned timestamps prevent this loophole.

Summary:

Server-assigned timestamps are the authoritative source.

Caller-supplied timestamps can be logged as metadata but must never be trusted for audit integrity.

This provides security, compliance, and consistency across all audit events.


2. Repository Design

@NoRepositoryBean is not required for the Event repository because it is a concrete repository interface for the Event entity.

@NoRepositoryBean is only required for an intermediate or base repository interface that should not be created as a Spring bean.

findAll(Pageable) does not need to be overridden because JpaRepository already provides it.


3. EventRepositoryImpl Design

All fields are mandatory when creating an event.

Therefore, null and empty checks are not required for eventType, actorId, resourceType, resourceId, payload, and timestamp during hash calculation.

Only previousHash can be null for the first event in the chain.

For the first event, previousHash is handled as an empty value during hash calculation.

The hash input is a straightforward concatenation of fields using the | separator.

Payload is already received as a String containing JSON text.

Therefore, payload does not need to be converted from a Map to JSON before hash calculation.

The payload String is directly used during hash calculation.


4. SHA-256 Hashing

SHA-256 is used for event hashing.

Reasons:

- SHA-256 is secure and trusted.
- SHA-256 is a modern, NIST-standardized cryptographic hash.
- SHA-256 is tamper-evident: changing even one character in a record completely changes the hash.
- SHA-256 produces a fixed-size value, making it easy to store in a database column.
- SHA-256 is deterministic: the same input always produces the same hash.
- Deterministic hashing is required for integrity checks and hash chains.
- SHA-256 is fast enough for normal audit-record processing.


5. Scenario B - Salted Per-Field Hashing (Merkle-Lite)

The Salted Per-Field Hashing (Merkle-Lite) approach is selected because it balances cryptographic immutability, strict data privacy, and low system complexity in standard frameworks such as Spring Boot and H2.

Why Merkle-Lite is selected:

- Granular erasure: Nested JSON payloads are flattened into separate path-value pairs, for example user.account.
- Each path-value pair receives a random salt and a unique hash.
- When data is redacted, the raw value and salt are permanently deleted from H2, while the individual field hash is retained.
- During verification, the preserved hash is used for redacted fields and hashes are recalculated for active fields.
- The overall block hash remains identical, maintaining tamper evidence.

Why other approaches are not selected:

Monolithic Hashing:

Hashing the entire JSON payload means erasing one field changes the whole payload string and immediately breaks the hash chain.

Crypto-Shredding:

Deleting encryption keys leaves scrambled ciphertext in the database. This does not permanently remove the encrypted data and may be vulnerable to future decryption attempts.

Full Binary Merkle Trees:

Full Merkle trees are designed for very large distributed networks such as Bitcoin. Using them in an H2 relational database introduces unnecessary complexity for simple audit payloads.

Zero-Knowledge Proofs:

Zero-knowledge proofs use complex mathematics, can reduce application performance, do not have native Spring Boot support, and create significant maintenance overhead.
