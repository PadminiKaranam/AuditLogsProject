package com.persistent.audit.controller;

import java.time.Instant;
import java.util.Set;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.data.domain.Page;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.persistent.audit.exceptions.AccessForbiddenException;
import com.persistent.audit.exceptions.ApiErrorResponse;
import com.persistent.audit.model.ChainVerificationResult;
import com.persistent.audit.model.EventCreateRequest;
import com.persistent.audit.model.EventCreateResponseObject;
import com.persistent.audit.model.RetentionCheckResult;
import com.persistent.audit.service.EventService;
import com.persistent.audit.service.UserService;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/audit")
public class AuditLogsController {

	private static final String ADMIN = "ADMIN";
	private static final String REGULATOR = "REGULATOR";
	private static final Set<String> ADMIN_ONLY = Set.of(ADMIN);
	private static final Set<String> ADMIN_OR_REGULATOR = Set.of(ADMIN, REGULATOR);

	private final EventService eventService;
	private final UserService userService;

	public AuditLogsController(EventService eventService, UserService userService) {
		this.eventService = eventService;
		this.userService = userService;
	}

	@PostMapping("/createEvent")
	public ResponseEntity<EventCreateResponseObject> createEvent(
			@RequestHeader("username") String username,
			@RequestHeader("useremail") String useremail,
			@Valid @RequestBody EventCreateRequest request) {
		authorize(username, useremail, ADMIN_ONLY);
		log.info("Request received: POST /audit/createEvent eventType={} actorId={} resourceType={} resourceId={}",
				request.getEventType(), request.getActorId(), request.getResourceType(), request.getResourceId());
		log.debug("Create event request parameters: eventType={}, actorId={}, resourceType={}, resourceId={}",
				request.getEventType(), request.getActorId(), request.getResourceType(), request.getResourceId());
		EventCreateResponseObject saved = eventService.createEvent(
				request.getEventType(),
				request.getActorId(),
				request.getResourceType(),
				request.getResourceId(),
				request.getPayload());
		log.info("Response status={} eventId={}", HttpStatus.CREATED.value(), saved.getId());
		return ResponseEntity.status(HttpStatus.CREATED).body(saved);
	}

	@GetMapping("/events")
	public ResponseEntity<Page<EventCreateResponseObject>> getEvents(
			@RequestHeader("username") String username,
			@RequestHeader("useremail") String useremail,
			@RequestParam(required = false) String eventType,
			@RequestParam(required = false) String actorId,
			@RequestParam(required = false) String resourceType,
			@RequestParam(required = false) String resourceId,
			@RequestParam(required = false) Instant fromTimestamp,
			@RequestParam(required = false) Instant toTimestamp
			) {
		authorize(username, useremail, ADMIN_OR_REGULATOR);
		log.info("Request received: GET /audit/events eventType={} actorId={} resourceType={} resourceId={} fromTimestamp={} toTimestamp={}",
				eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp);
		log.debug("Get events request parameters: eventType={}, actorId={}, resourceType={}, resourceId={}, fromTimestamp={}, toTimestamp={}",
				eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp);
		Page<EventCreateResponseObject> events = eventService.getEvents(
				eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp);
		log.info("Response status={} totalElements={} pageSize={}",
				HttpStatus.OK.value(), events.getTotalElements(), events.getSize());
		return ResponseEntity.ok(events);
	}

	@GetMapping("/verify")
	public ResponseEntity<ChainVerificationResult> verifyChain(
			@RequestHeader("username") String username,
			@RequestHeader("useremail") String useremail) {
		authorize(username, useremail, ADMIN_ONLY);
		log.info("Request received: GET /audit/verify");
		ChainVerificationResult result = eventService.verifyChain();
		log.info("Response status={} firstInvalidRecordId={} violationDescription={}",
				HttpStatus.OK.value(), result.getFirstInvalidRecordId(), result.getViolationDescription());
		return ResponseEntity.ok(result);
	}

	@PutMapping("/checkForRetention")
	public ResponseEntity<?> checkForRetention(
			@RequestHeader("username") String username,
			@RequestHeader("useremail") String useremail,
			@RequestParam("days") Integer days) {
		authorize(username, useremail, ADMIN_ONLY);
		log.info("Request received: PUT /audit/checkForRetention days={}", days);
		if (days == null || days <= 0) {
			log.error("Invalid retention days input: {}", days);
			return ApiErrorResponse.of(HttpStatus.BAD_REQUEST, "days must be a positive integer", null);
		}
		RetentionCheckResult result = eventService.checkForRetention(days);
		log.info("Response status={} archivedCount={}", HttpStatus.OK.value(), result.getArchivedCount());
		return ResponseEntity.ok(result);
	}

	@PutMapping("/redact")
	public ResponseEntity<?> redactFieldsFromPayload(
			@RequestHeader("username") String username,
			@RequestHeader("useremail") String useremail,
			@RequestParam("id") Long id,
			@RequestParam("fields") String fields) {
		authorize(username, useremail, ADMIN_ONLY);
		log.info("Request received: PUT /audit/redact id={} fields={}", id, fields);
		if (id == null || id <= 0) {
			log.error("Invalid redact id input: {}", id);
			return ApiErrorResponse.of(HttpStatus.BAD_REQUEST, "id must be a positive integer", null);
		}
		if (fields == null || fields.isBlank()) {
			log.error("Invalid redact fields input");
			return ApiErrorResponse.of(HttpStatus.BAD_REQUEST, "fields is required", null);
		}
		EventCreateResponseObject redacted = eventService.redactFieldsFromPayload(id, fields);
		log.info("Response status={} eventId={}", HttpStatus.OK.value(), redacted.getId());
		return ResponseEntity.ok(redacted);
	}

	@GetMapping("/export")
	public ResponseEntity<byte[]> exportBundle(
			@RequestHeader("username") String username,
			@RequestHeader("useremail") String useremail,
			@RequestParam(required = false) String resourceId,
			@RequestParam(required = false) String actorId) {
		authorize(username, useremail, ADMIN_OR_REGULATOR);
		log.info("Request received: GET /audit/export actorId={} resourceId={}", actorId, resourceId);
		byte[] csv = eventService.exportBundle(resourceId, actorId);
		log.info("Response status={} file=Event_Bundle.csv size={}", HttpStatus.OK.value(), csv.length);
		return ResponseEntity.ok()
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"Event_Bundle.csv\"")
				.contentType(MediaType.parseMediaType("text/csv"))
				.body(csv);
	}

	private void authorize(String username, String useremail, Set<String> allowedTypes) {
		if (!StringUtils.hasText(username) || !StringUtils.hasText(useremail)) {
			throw new IllegalArgumentException("username and useremail headers are required");
		}
		String userType = userService.retrieveUserType(useremail, username);
		if (userType == null || !allowedTypes.contains(userType.trim().toUpperCase())) {
			throw new AccessForbiddenException("Access Forbidden");
		}
	}
}
