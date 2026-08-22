###Prompt- 1:
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



###Prompt- 2:
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



###Prompt- 3:

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



###Prompt- 4:
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


###Prompt- 5:

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
