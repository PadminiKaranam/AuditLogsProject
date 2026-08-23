# Scenario A — Greenfield Core Audit Log Service

## Requirement interpretation

The service must accept audit events, persist them in append-only form, support filtered and paginated retrieval, and detect modifications to historical records. A chain verification endpoint must identify the first inconsistency and its type.

## Normalized requirement

The system shall append an event containing `eventType`, `actorId`, `resourceType`, `resourceId`, `payload`, and a server-assigned `timestamp`. Each event shall include a deterministic SHA-256 hash over its canonical content and the predecessor hash. The first event shall use an empty predecessor value. The service shall expose query and verification APIs but no update or delete API for ordinary event records.

## Decomposition

1. Confirm event fields, timestamp ownership, ordering, and genesis behavior.
2. Define the event schema and repository operations.
3. Implement event creation and predecessor lookup.
4. Implement canonical hashing and chain metadata.
5. Implement filters and pagination.
6. Implement full-chain verification.
7. Add tests for valid chains and direct database changes.
8. Document setup, API behavior, limitations, and validation evidence.

## Design

* Server assigns the timestamp once at creation.
* Events are ordered by ascending database ID.
* `previousHash` is null/empty for the first event.
* Hash inputs use a canonical delimiter-based representation.
* Payload integrity uses a sealed internal representation.
* Verification recalculates hashes from current database state before checking predecessor links.

## Acceptance criteria

* Creating an event returns its ID and hash.
* Creating a second event links it to the first event's hash.
* Query filters can be combined.
* Pagination works for large result sets.
* An unchanged chain verifies successfully.
* Modifying event content directly in the database causes an event-hash mismatch.
* Modifying an earlier hash causes the modified event to fail and invalidates trust in subsequent links.
* Modifying `previousHash` causes a previous-hash mismatch.
* No ordinary update/delete endpoint is exposed.

## Validation evidence to capture

* Request and response for two event creations.
* Successful `/audit/verify` response.
* Direct database modification statement and resulting verification response.
* Test report showing unit and integration results.
* Commit history demonstrating incremental implementation and review.

