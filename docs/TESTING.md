# Testing Approach and Validation Plan

## Testing goals

The test strategy demonstrates functional correctness, integrity behavior, security boundaries, regression safety, and operational evidence. Tests should run locally and in CI without requiring an external consumer.

## Test layers

### Unit tests

Test pure and isolated behavior:

* SHA-256 is deterministic for identical canonical input.
* Timestamp normalization is deterministic and compatible with database precision.
* Payload sealing creates stable metadata for an existing sealed payload.
* Leaf hashes are sorted deterministically.
* Redaction preserves the stored leaf hash and payload root.
* Invalid JSON and invalid field names are rejected.
* CSV values are escaped correctly.
* User service returns the correct role or the expected exception.

### Service tests

* `createEvent` assigns a timestamp, finds the predecessor, seals the payload, and persists both visible and sealed payloads.
* The first event uses the configured genesis predecessor value.
* Subsequent events use the previous event hash.
* `verifyChain` recalculates every event hash.
* `verifyChain` detects changed event metadata, payload, sealed payload, stored hash, and predecessor links.
* `verifyChain` includes archived records.
* Authorized redaction preserves event hash and verification success.
* Retention changes status only and does not break verification.
* Export returns the requested events and chain metadata.

### Controller tests

For every protected endpoint:

* Missing `username` returns `400`.
* Missing `useremail` returns `400`.
* Unknown identity returns `401`.
* A known user with an insufficient role returns `403`.
* An authorized role reaches the service layer.
* Existing success and validation responses remain unchanged.

### Integration tests

Use a real test database or containerized database to prove persistence behavior:

1. Create two events.
2. Verify the chain successfully.
3. Modify an event directly through a repository/native SQL operation.
4. Verify and assert the first invalid event and violation.
5. Create an event, record its hash, redact a field, and assert the hash remains unchanged.
6. Verify after redaction.
7. Archive old events and verify again.
8. Export filtered records and inspect headers/content.

## Quality gates

Run these before submission:

```bash
./mvnw test
./mvnw verify
```

Also run the project's configured formatter, checkstyle, SpotBugs, dependency audit, and test coverage commands if present.

## Manual validation evidence

Capture sanitized evidence in the repository or review notes:

* API request/response examples.
* Database row before and after redaction, excluding sensitive values.
* Verification output before and after direct tampering.
* Export response headers and a sample CSV.
* Test command output.
* Git commit history.

## Testing limitations

* A mock repository does not prove database precision behavior; integration tests are required for timestamp round trips.
* A local database under developer control is not a trusted integrity anchor.
* CSV chain metadata does not by itself provide a digital signature.
* Header-based identity tests validate authorization logic but not production authentication.

