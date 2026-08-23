# Scenario C — Compliance Reporting and RBAC

## Original ambiguous statement

> Regulators need to be able to audit access to client account data.

## Ambiguities identified

* Who qualifies as a regulator, and how are regulators authenticated?
* Does “audit access” mean viewing, exporting, verifying, creating, or modifying records?
* What data is considered client account data?
* Must regulators access all accounts or only assigned accounts?
* Are access attempts themselves required to be logged?
* What retention, redaction, privacy, and export requirements apply?
* Which regulatory framework and evidence format must be supported?
* Is the service internal, partner-facing, or public?
* What status codes and error details should unauthorized requests receive?
* Does the system need SSO, MFA, token validation, or an external identity provider?

## Clarifying questions

1. Which identities and roles exist today?
2. How are users provisioned, disabled, and reviewed?
3. What exact operations may a regulator perform?
4. What resource-level scope applies to each regulator?
5. Which fields are sensitive and what redaction policy applies?
6. Must successful and failed access attempts be separately recorded?
7. What regulator-specific export format and evidence are required?
8. Which authentication system is authoritative?
9. What response codes and audit alerts are expected?
10. What are the retention and legal-hold rules?

## Assumptions for the prototype

* Roles are `ADMIN`, `REGULATOR`, and `USER`.
* A regulator needs read-only access to event queries, verification evidence, and exports; the current endpoint policy permits regulator query/export and keeps verification administrative.
* Administrative mutation operations remain ADMIN-only.
* The prototype resolves a user by `username` and `useremail` request headers.
* User email is unique and user type is stored in the database.
* Resource-level authorization is not implemented yet; role-level authorization is the boundary of this prototype.
* Authentication strength, MFA, SSO, and token signing are deferred to the platform identity layer.

## Clarified requirement statement

The audit log service shall maintain a database-backed user registry and enforce role-based authorization for audit operations. An authenticated `ADMIN` may create events, verify the chain, apply retention, and redact sensitive fields. An authenticated `ADMIN` or `REGULATOR` may query and export audit records. A `USER` or an identity with insufficient permissions shall be denied. Every protected request shall identify the caller through the configured identity mechanism, validate that identity, and return a documented error response for missing, unknown, or unauthorized identities. Regulators shall not be able to mutate audit records through the service API.

## Concrete design

### User data

```text
USERS
- user\_id       primary key, generated
- username      required
- user\_type     ADMIN | REGULATOR | USER
- user\_email    required, unique
```

### Response behavior

* Missing identity headers: `400 Bad Request`.
* Unknown identity: `401 Unauthorized`.
* Known identity without endpoint permission: `403 Forbidden`.
* Successful creation: `201 Created`.
* Successful reads and administrative operations: existing endpoint success codes.

## Implemented scope

* User entity, repository, and service lookup.
* Header extraction and validation in the controller.
* Role checks for all protected endpoints.
* Centralized exception handling in the exceptions package.
* New and modified tests for role combinations and failure responses.
* Separation between read-only regulator operations and ADMIN-only mutations.

## Scoped out

* Password handling and account registration.
* JWT/OAuth/SSO/MFA integration.
* Resource-level authorization.
* User administration APIs.
* A dedicated security audit stream for access attempts.
* Regulatory-specific report templates.

