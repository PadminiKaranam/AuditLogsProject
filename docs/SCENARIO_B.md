# Scenario B — Retention, Redaction, and Export

## Requirement interpretation

The service must support policy-driven archival, redact selected sensitive payload fields without breaking the chain, and export records for a resource or actor in a verifiable format.

## Normalized requirements

1. Records older than a configurable age shall be archived or soft-deleted without causing verification to treat policy-compliant archival as tampering.
2. A privileged redaction operation shall replace selected payload values with `null`, preserve the event's original integrity hash, and retain sufficient protected integrity metadata for verification.
3. The export endpoint shall return all matching records with chain metadata needed to validate the included sequence and identify its relationship to the full chain.

## Decomposition

1. Define active and archived states.
2. Implement retention cutoff calculation and archival updates.
3. Ensure verification includes archived rows in chain order.
4. Define visible versus internal payload representation.
5. Seal payload fields with stable salts and leaf hashes at creation.
6. Implement redaction that changes only visible values and preserves leaf evidence.
7. Implement CSV serialization with escaping.
8. Test retention, redaction, tampering, and export independently and together.

## Retention design

The current implementation marks old records `ARCHIVED`; it does not delete them. Verification reads both active and archived records in chain order. This preserves predecessor relationships and prevents a false-positive break.

### Out of scope

Physical deletion, compaction, and cryptographic chain checkpointing are out of scope for the prototype. A production design would need a signed checkpoint or a defined replacement genesis record before removing historical rows.

## Redaction design

The event has two payload fields:

* `payload`: visible client/API payload, with sensitive values redacted.
* `sealedPayload`: restricted internal payload containing integrity metadata.

At creation, each payload field receives a stable salt and leaf hash. The payload root is calculated from sorted leaf hashes. Redaction sets the field to `null` in both representations but retains its original leaf hash in sealed metadata. Verification therefore reconstructs the same payload root without retaining the cleartext value in the visible payload.

### Important integrity rule

Only the authorized `/redact` operation may perform this transformation. Directly replacing the sealed payload, deleting integrity metadata, changing a non-redacted value, or changing event metadata must cause verification failure.

## Export design

The endpoint returns:

```text
id,eventType,actorId,resourceType,resourceId,payload,timestamp,chainMetadata
```

The visible payload is exported; internal salts and leaf hashes are excluded. `chainMetadata` is derived from the event hash and predecessor hash. The prototype supports inspection and link verification for the exported rows. Independent verification of the event content requires the verifier to have the canonical hashing rules and, for redacted fields, an appropriate trusted integrity reference.

## Acceptance criteria

* Events older than the configured window become archived.
* Archived events remain part of verification.
* Redacting one or more fields returns a payload without cleartext sensitive values.
* The event hash remains unchanged after authorized redaction.
* Verification succeeds after authorized redaction.
* Changing a non-redacted payload value directly in the database fails verification.
* Changing or removing sealed integrity metadata fails verification.
* CSV values containing commas, quotes, or line breaks are escaped correctly.
* Export responses have `text/csv` and attachment headers.

