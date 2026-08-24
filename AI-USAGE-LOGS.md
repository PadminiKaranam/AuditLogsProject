Tool Used: Cursor IDE

Scenario-A

### Prompt- 1:
Create a table using H2 (Entity Model):

1. Add all the required properties related to h2 file-based db, JPA in application.properties
2. Create an Event entity model (com.persistent.audit.model package) with:
   - id (Long, auto-generated)
   - eventType (String)
   - actorId (String)
   - resourceType (String)
   - resourceId (String)
   - payload (JSON type)
   - timestamp (server-assigned, not null)
   - hash (hash of this record)
   - previousHash (hash of previous record)
   
4. Use @Table(name = "EVENT") and proper validation annotations
5. Include all getters, setters, and constructors
6. Add all the required dependencies in pom.xml

Modifications:
1. Changed from Map<String, Object> with @JdbcTypeCode(SqlTypes.JSON) to plain String with columnDefinition = "TEXT".
2. Removed all the boiler plate code and added lombok annotations.



### Prompt- 2:
Create a JPA repository for the Event entity:

1. Package: com.persistent.audit.repository
2. Interface: EventRepository extends JpaRepository<Event, Long>
3. Add a custom query method using @Query:
   - Method name: findEvents
   - Parameters: eventType, actorId, resourceType, resourceId, fromTimestamp, toTimeStamp, Pageable
   - All filter parameters should be optional (use IS NULL OR pattern in WHERE clause)
   - Return type: Page<Event>
The query should allow filtering by any combination of:
- eventType
- actorId
- resourceType and resourceId
- timestamp range (from/to)
If all filters are null, it should return all events including pagination.
4. Also add standard findAll(Pageable) method
5. Add a method to create an event with the mandatory parameters: eventType, actorId, resourceType, resourceId, payload

Add all the implementations to this interface by creating a class and implementing it and return the query results.

Modifications:
1. Removed @NoRepositoryBean because this is a concrete repository interface for a specific entity (Event), not an intermediate/base interface meant to be extended by other repositories. @NoRepositoryBean is only for base/repository fragment interfaces that should not get their own Spring bean.
2. Removed the @Override Page<Event> findAll(Pageable pageable) method.
3. Kept only the custom findEvents and createEvent methods.
4. Key changes in EventRepositoryImpl:
   - Removed null/empty checks in computeHash as all fields are mandatory when creating an event, there’s no need to defensively convert them to empty strings.
   - The hash input is now a straightforward concatenation of the fields with | separators.
   - Only previousHash can be null (for the very first event), so handled that with (previousHash != null ? previousHash : "").
   - Removed toJson(String payload) and related logic
   - payload is already a String (JSON text) when passed in, so there’s no need to convert a Map to a string.
   - Directly used payload in the hash computation.

Justification:
1. Delete/update methods from JpaRepository will still exist in the type, but you can simply avoid calling them in your service layer. If you truly want them unavailable at compile time, you’d need a custom base repository that overrides them to throw, which is usually unnecessary.
2. Why SHA-256:
   - Secure and trusted: SHA‑256 is a modern, NIST‑standardized cryptographic hash; no known practical collisions.
   - Tamper‑evident: Changing even one character in the record completely changes the hash.
   - Fixed size: Easy to store in a column.
   - Deterministic: Same input always gives the same hash, which is essential for integrity checks and hash chains.
   - Fast enough: Very quick to compute for typical record sizes; negligible overhead compared to DB and network I/O.



### Prompt- 3:

Create a service class for Event management:

1. Package: com.persistent.audit.service
2. Class: EventService with @Service annotation
3. Inject EventRepository via constructor
4. Add methods:
   - createEvent(eventType, actorId, resourceType, resourceId, payload) - creates and saves event by directly calling JpaRepositories save method and remove the createEvent method which is no more required in repository.
   - getEvents(eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp) - If there are more no.of records, 10 records per page should be displayed. Change the findEvents method in repository accordingly.
5. The getEvents method should:
- Check if any filter is provided
- If yes, call repository's findEvents method
- If no filters, call findAll method of JpaRepositories and also If there are more no.of records, 10 records should be displayed per page. (Handle pagination here as well). If required use a common utility method for pagination as it is used in findEvents as well



### Prompt- 4:
Adding the endpoints in the controller:

 Change the package of AuditLogsController to com.persistent.audit.controller
1. POST /audit/createEvent endpoint:
   - Accept JSON body with all these fields as mandatory: eventType, actorId, resourceType, resourceId, payload 
   - Create a DTO class EventCreateRequest inside model package with the fields: eventType, actorId, resourceType, resourceId, payload(exclude id and timestamp)
   - Return 201 Created with the saved event
   - Add @Valid for request body validation
   - Validate the input and accordingly give the status codes.
   - Call CreateEvent() method inside service Layer
This is an append-only audit log. Do NOT create any PUT, PATCH, or DELETE endpoints.

2. GET /audit/events endpoint:
   - Query params (all optional): eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp, page, size, sort
   - Return all the records with 10 records per page
   - If all filters are null, return all events
   - Call getEvents(String eventType, String actorId, String resourceType, String resourceId,
			Instant fromTimestamp, Instant toTimestamp) method inside service layer.

3. Only change createEvent method so that it should return a EventCreateResponse Object. Create a DTO EventCreateResponseObject class in model package which contains all the firlds in the Event object except hash and previousHash fields.
4. Do not change any logic in the service layer for getEvents method and pagination related logic. Only change the return type of the getEvents method such that it returns page<EventCreateResponseObject>


### Prompt- 5:

Create a new GET /audit/verify endpoint in the existing controller class:
- Do not change the existing code
- create a new class named ChainVerificationResult with the fields - firstInvalidRecordId, violationDescription
- It should not accet any input params. It should call verifyChain() method in service class and return ChainVerificationResult Object.
- add verifyChain() method in the already existing service class
- what verifyChain() method should do:
   1. Parse through all the events.
   2. compare event.hash and event.previousHash (Except for the first event whose previousHash is always NULL)
   3. if both are equal for all the events in the table, return an empty object.
   4. if there is a mismatch stop the process and assign event.id to ChainVerificationResult.firstInvalidRecordId  and ChainVerificationResult.violationDescription as "HASH MISMATCH" and return ChainVerificationResult object to the controller



### Prompt- 6:
ADD LOGGING and unit testcases (Without Changing Existing Logic)
1. Logging requirements:
   - Use @Slf4j (Lombok)
   - Log levels: INFO for business operations, DEBUG for details, ERROR for exceptions
   - DO NOT change any existing business logic, only add log statements
2. Add logs for:
   - Controller: Request received, request parameters, response status, exceptions
   - Service: hashing, chainVerification, any errors
3. Log format should include:
   - Timestamp
   - Log level
   - Relevant parameters (avoid logging sensitive data like payload)
4. Update application.properties:
   - Configure log levels (INFO for prod, DEBUG and error for dev)
   - Add file logging configuration (logs in ./logs/audit-events.log)
5. And also add unit testcases without changing the existing code including all the edge case scenarios like pagination (what if more than 10 records), chainVerification (what if there is only one record) and many more like this using junit and Mockito and also execute all the testcases and they should pass 





Scenario-B

### Prompt-1:
Act as a Senior Backend Engineer. 

I need you to extend this existing audit-log-service tamper-evident system to support a data retention policy without breaking event chain verification.

### Context
In Scenario A, we built a sequentially linked events where each event contains PreviousHash, and Hash. 
We are now introducing Scenario B: records older than a configurable window (e.g., 90 days) must delete the events, but the system must still verify the overall integrity of the chain.

### Technical Requirements
1. Controller changes: Create PUT - /audit/checkForRetention endpoint which accepts no.of days as an input. Validate this that it should be an integer otherwise throw BAD Request. Pass this field(days) to the service layer.
2. Schema Extension: Update the Event model to include a `status` field (which will have either ACTIVE or ARCHIVED)
3. Retention Worker: Write a method in already existing service layer that does the following:
   - Retrieve the events from the Event table whose newly added 'status' files is 'ACTIVE'
   - Check if the value of the timestamp field of the event is older than 90 days from todays date
   - If yes, then update the value of status field to 'ARCHIVED'
4. Do not change any logic for calculating hash code or verify endpoint. The chain linking should still be the same irrespective of the value of status field.
5. Add the unit testcases for this endpoint by inserting mocked data into Event table:
   - Include testcases for invalid days input, valid days input, and check for the value of status field
   - Include the testcase to check for the chain of the events before and after retention.
   - verify whether all the testcases are getting passed


### Prompt-2:
Act as a Principal Java Architect and Cryptographic Engineer. 

I need you to design and implement a "Structured Redaction" scheme for a tamper-evident audit-log-service. The system must allow specific fields within a payload field of the Event table (such as account numbers or PII) to be permanently redacted for privacy compliance without breaking the sequential cryptographic hash chain.

### Context & Problem Statement
This is a genuine engineering problem: a standard event hash covers the original raw values as a string. Simply removing or masking a value would invalidate the hash and signal a false-positive data tampering event. We need a scheme where a field value from payload(json) can be completely deleted from the database, but its cryptographic proof remains behind, allowing the overall event hash (and the subsequent chain) to verify perfectly.

### Architectural Approach
Implement a "Salted Per-Field Hashing" (Merkle-lite) approach:
1. Instead of hashing the entire JSON payload string together, each key-value pair in the payload is assigned a unique random salt (nonce) to prevent attacks on redacted data.
2. Each field's leaf hash is computed as: SHA-256(key + value + salt).
3. The individual field hashes are sorted lexicographically by key and hashed together to create a single `PayloadRootHash`.
Example:
Original Payload: {"name": "Alice", "account": "12345"}

[Field: name]    -> SHA-256("name" + "Alice" + "SaltXYZ...")   -> Leaf Hash A \
                                                                                -> Combine & Hash -> [Payload Root Hash]
[Field: account] -> SHA-256("account" + "12345" + "SaltABC...") -> Leaf Hash B /

4. The final `hash` (CurrentHash) is computed over the following fields of the event:
    - eventType
    - actorId
    - resourceType
    - resourceId
    - PayloadRootHash
    - timestamp
    - previousHash

5. When a field is redacted, its raw value and salt are permanently deleted from the database, but its pre-computed leaf hash is kept.

### Technical Requirements
1. In createEvent method inside service layer change the logic of calculating hash for both the fields 'previousHash' and 'hash'.
2. Use the common approach for calculating hash for both the fields ('previousHash' and 'hash') based on the above "Salted Per-Field Hashing" (Merkle-lite) approach.
   - while calculating previousHash retrieve the first eventRecord orderby id desc, then call computeHash() method.
   - Change the computeHash() method - convert String to JSON Object using Jacckson. Generate salts for each key-value pair. Calculate hash for key, value and the salt generated. Do, the same for all the keyValue pairs. Combine all these hashes and generate a single final hash and return it.  
3. Leave the type of payload in the model classes as a string only but convert that string to JSON Object using Jackson only while calculating hash for payload.
4. After creating this hashing algorithm, add an endpoint /audit/redact in the already existing controller which accepts id, fields(comma separated key values from payload json) which calls a method redactFieldsFromPayload in service layer and returns EventObject. Also, validate the input fields
5. Create redactFieldsFromPayload() method which
   - accepts id and fields(comma separated values of string) from /redact endpoint
   - retrieve the payload of event record based on the id given
   - convert the string payload to JSON Object using jackson
   - for all the keys present in fields:
      1. check whether the key is present in payload jsonObjet
      2. If present, change the value of the key to null
   - Update the value of the payload in the database.
   - It will return Event Object to the controller.
6. Do not change any other existing logics. Do not add any new fields to the model classes.
7. Add junit testcases for all the edge case scenario with the mocked data. Also change the existing testcases which calculates the hash with old logic and verify all the existing and new added testcases.

### Constraints
- Do not use external heavy blockchain frameworks. Use standard Java security libraries.
- Write readable code with explicit exception handling.


### Prompt-3:
Act as a Software Engineer.

I need you to implement a "Bulk Export" feature for our tamper-evident ledger system using Java 17+, Spring Boot, and an H2 database. The endpoint must export all ledger records associated with a specific resourceId or actorId into a self-contained, cryptographically verifiable bundle.

### Context
Export event records into a file and it must be a self-contained cryptographic snapshot. A third-party recipient must be able to independently verify that none of the records inside the bundle have been modified, reordered, or deleted since the export occurred.

### Technical Requirements
1. Export Endpoint: Create a /audit/export that accepts `resourceId` and `actorId` as query parameters. Botha re optional. It must fetch the sequential event records based on the input params. call exportBundle() method in service layer
2. Create a model class BundleExportStructureResponse.java with the fields
   - id
   - eventType
   - actorId
   - resourceType
   - resourceId
   - payload
   - timestamp
   - chainMetadata
3. create a new method in service layer exportBundle() which does:
   - Accepts `resourceId` and `actorId` as params
   - Retrieve the list of events based on the given resourceId` and `actorId fields.
   - For each event record calculate chainMetadata = hash(event.hash, event.previousHash)
   - Convert into List<BundleExportStructureResponse> and create an excel sheet with the filename: 'Event_Bundle.csv' which contains list of BundleExportStructureResponse
   - Give the file as an output
4. Write the testcases and verify them.
5. Do not change any existing logic







Scenario-C:

### Prompt-1:
Act as a Software Engineer and 

Enhance the existing audit-log-service with user management and role-based access control.

Requirements:
1. Create a new USERS table with fields:
   - userId (primary key, auto-generated)
   - username (string)
   - userType (string: e.g., ADMIN, REGULATOR, USER)
   - userEmail (string, unique)
2. Create User Entity Class (Use Lombok annotations to avoid boiler-plate code), User Repository Interface extends JPA
3. Create a User service class which contains a method named retrieveUserType() which accepts userEmail and userName as parameters.
4. Update the existing controller class to accept header information("username" and "useremail") in all the endpoints. Validate the headers and return specific responseStatsu Codes.
  - Call the user service layer and check for the userType
  - Constraints: /createEvent, /verify, /checkForRetention, /redact endpoints requires ADMIN as userTpe. /getEvents, /export endpoint requires ADMIN or REGULATOR as userType. If not, return 403 Access Forbidden.
5. Do no change the existing logic for all the endpoints and event service layer, repository and entity layers. Just add the header info in the controller for all of these endpoints.
6. Separate Exception handlers written in controller to a separate package audit.exceptions
7. Write the new testcases and also modify the existing testcases for this role based access control given to the endpoints and verify all the existing and new testcases.


Enhancements:

### Prompt- 1:
Act as a Security Engineer and 

Enhance this audit-log-service by replacing the `username` and `useremail` request-header authentication approach with JWT-based authentication while retaining the existing user records and user types in the H2 `USERS` table.

Requirements:

1. Remove manual header authentication
- Do not accept or trust `username` and `useremail` headers in controller endpoints.
- Remove repeated header validation logic from controllers.
- Obtain the authenticated username/email from Spring Security’s authenticated principal after JWT validation.
- The JWT must be sent through: Authorization: Bearer <access-token>

2. Login endpoint
Create a public login endpoint in already existing controller: POST audit/auth/login

The login endpoint must:
- Validate username and password against the existing `USERS` table in H2.
- Retrieve the userType from the user record and treat it as a role.
- Return the JWT, token type, expiry, username, email, and user type.

3. Authorization rules:
- `POST /createEvent` -> `hasRole("ADMIN")`
- `GET /verify` -> `hasRole("ADMIN")`
- `POST /checkForRetention` -> `hasRole("ADMIN")`
- `POST /redact` -> `hasRole("ADMIN")`
- `GET /getEvents` -> `hasAnyRole("ADMIN", "REGULATOR")`
- `GET /export` -> `hasAnyRole("ADMIN", "REGULATOR")`

4. Add the junit testcases and try to cover 100% and verify them


### Prompt- 2:

Act as a Security engineer and perform the below upgrades to the existing audit-log-service without changing the actual functionality:

1. Update CORS configuration to remove wide-open CORS access.

Replace it with a secure allowlist-based CORS configuration.

Requirements:
- Do not use `setAllowedOriginPatterns(List.of("*"))`.
- Allow only known frontend origins through configuration properties.
- Use the below allowed origins
  - `http://localhost:8080`
  - `http://localhost:8081`
  - `http://localhost:8082`
- Allow only required methods: GET, PUT and POST
- Allow only required headers: Authorization
- Expose `Content-Disposition` only if required for CSV export file names.
- Set `allowCredentials(false)` because JWT is sent through the `Authorization: Bearer <token>` header rather than cookies.
- Configure `maxAge` for preflight requests, for example `3600L`.
- Ensure unauthorized origins are blocked by browsers.
- Ensure that the original functionality should behave as same.

2. Update the JWT authentication implementation so username and password are not hard-coded in Java code, request headers, or application.properties.

Requirements:
- Do not add username/password values to application.properties.
- Do not use JSON containing username/password in configuration files.
- Assume that we are already storing application users in the existing H2 `USERS` table and make sure that this users table will not be reloaded again and again on every start of the application.
- Generate the JWT token by assuming that the USERS table already has all the details required. Just validate the data given with the users table. Do not set external username or password. All the other implementation and functionality should remain same.

3. Add the new testcases and modify the existing testacases if required to cover 100% code and verify those by executing.


### Prompt-3:

a. Enhance the existing audit-log-service JWT implementation by adding JWT issuer, audience, and token ID validation.

Requirements:

1. Add the properties of JWT issuer, audience and token ID validation to application.properties
2. Update JwtService:
- Inject issuer and audience.
- During token generation, add:
  - `iss` claim using the configured issuer.
  - `aud` claim using the configured audience.
  - `jti` claim containing a newly generated UUID for every token.
- Keep existing claims as is. During the token validation include all these.
4. Do not change existing endpoint role mappings.
5. Generate:Unit tests for:
  - Valid token.
  - Missing issuer.
  - Wrong issuer.
  - Missing audience.
  - Wrong audience.
  - Missing JWT ID.
  - Expired token.


b. Add request-size and payload-abuse controls to the existing audit-log-service

Goal:
Prevent oversized HTTP requests and extremely large payload values from consuming excessive memory, CPU, database storage, or hash-computation time.

Requirements:

1. Update `application.properties` with sensible limit like maxFileSize, maxRequestSize, .....
2. Update EventCreateRequest:
- Add these validations to payload field in the request body.
- Keep existing validation for the remaining fields.

4. Add a global exception handler:
- Return HTTP `400 Bad Request` for Bean Validation failures.
- Return HTTP `413 Payload Too Large` for oversized request bodies when supported by the server.
- Do not include sensitive payload data in error responses.


c. Add basic in-memory login rate limiting 

Goal:
Prevent repeated brute-force password attempts against `/auth/login`.

Requirements:
- Allow a maximum of 5 failed login attempts.
- Rate-limit window: 15 minutes.
- If limit is exceeded, return HTTP `429 Too Many Requests`.
- Successful login clears/reset failed attempts for that username and client IP.
- After 15 minutes, the failed-attempt window automatically resets.
- Do not reveal whether a username exists.
- Do not log passwords, JWTs, or password hashes.

d. Create security regression tests for the existing Spring Boot audit API.
e. Update all the testcases and also add actor/resource ownership authorization and cross-tenant denial testcases, Use database locking/sequence strategy and add concurrent append/direct SQL tamper testcases. for all the endpoints. Ensure that all the testcases covers 100% code and publish Surefire/JaCoCo artifacts, thresholds and exact run command/output.
f. README.md retains template language and runtime configuration is prototype-only. Finalize README and provide separate production profile with strict secrets, migrations and TLS.

