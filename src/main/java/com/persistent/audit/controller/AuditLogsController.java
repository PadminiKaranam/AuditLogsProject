package com.persistent.audit.controller;

import java.time.Instant;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.data.domain.Page;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.persistent.audit.exceptions.ApiErrorResponse;
import com.persistent.audit.model.ChainVerificationResult;
import com.persistent.audit.model.EventCreateRequest;
import com.persistent.audit.model.EventCreateResponseObject;
import com.persistent.audit.model.LoginRequest;
import com.persistent.audit.model.LoginResponse;
import com.persistent.audit.model.RetentionCheckResult;
import com.persistent.audit.security.AuditUserPrincipal;
import com.persistent.audit.service.EventService;
import com.persistent.audit.service.UserService;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/audit")
public class AuditLogsController {

	private final EventService eventService;
	private final UserService userService;

	public AuditLogsController(EventService eventService, UserService userService) {
		this.eventService = eventService;
		this.userService = userService;
	}

	@PostMapping("/auth/login")
	public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
		log.info("Request received: POST /audit/auth/login username={}", request.getUsername());
		LoginResponse response = userService.login(request.getUsername(), request.getPassword());
		log.info("Response status={} username={} userType={}", HttpStatus.OK.value(), response.getUsername(),
				response.getUserType());
		return ResponseEntity.ok(response);
	}

	@PostMapping("/createEvent")
	public ResponseEntity<EventCreateResponseObject> createEvent(@Valid @RequestBody EventCreateRequest request) {
		log.info("Request received: POST /audit/createEvent by={} eventType={} actorId={} resourceType={} resourceId={}",
				authenticatedUsername(), request.getEventType(), request.getActorId(), request.getResourceType(),
				request.getResourceId());
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
			@RequestParam(required = false) String eventType,
			@RequestParam(required = false) String actorId,
			@RequestParam(required = false) String resourceType,
			@RequestParam(required = false) String resourceId,
			@RequestParam(required = false) Instant fromTimestamp,
			@RequestParam(required = false) Instant toTimestamp
			) {
		log.info("Request received: GET /audit/events by={} eventType={} actorId={} resourceType={} resourceId={} fromTimestamp={} toTimestamp={}",
				authenticatedUsername(), eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp);
		Page<EventCreateResponseObject> events = eventService.getEvents(
				eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp);
		log.info("Response status={} totalElements={} pageSize={}",
				HttpStatus.OK.value(), events.getTotalElements(), events.getSize());
		return ResponseEntity.ok(events);
	}

	@GetMapping("/verify")
	public ResponseEntity<ChainVerificationResult> verifyChain() {
		log.info("Request received: GET /audit/verify by={}", authenticatedUsername());
		ChainVerificationResult result = eventService.verifyChain();
		log.info("Response status={} firstInvalidRecordId={} violationDescription={}",
				HttpStatus.OK.value(), result.getFirstInvalidRecordId(), result.getViolationDescription());
		return ResponseEntity.ok(result);
	}

	@PutMapping("/checkForRetention")
	public ResponseEntity<?> checkForRetention(@RequestParam("days") Integer days) {
		log.info("Request received: PUT /audit/checkForRetention by={} days={}", authenticatedUsername(), days);
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
			@RequestParam("id") Long id,
			@RequestParam("fields") String fields) {
		log.info("Request received: PUT /audit/redact by={} id={} fields={}", authenticatedUsername(), id, fields);
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
			@RequestParam(required = false) String resourceId,
			@RequestParam(required = false) String actorId) {
		log.info("Request received: GET /audit/export by={} actorId={} resourceId={}",
				authenticatedUsername(), actorId, resourceId);
		byte[] csv = eventService.exportBundle(resourceId, actorId);
		log.info("Response status={} file=Event_Bundle.csv size={}", HttpStatus.OK.value(), csv.length);
		return ResponseEntity.ok()
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"Event_Bundle.csv\"")
				.contentType(MediaType.parseMediaType("text/csv"))
				.body(csv);
	}

	private String authenticatedUsername() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			return "anonymous";
		}
		if (authentication.getPrincipal() instanceof AuditUserPrincipal principal) {
			return principal.getUsername() + "/" + principal.getEmail();
		}
		return authentication.getName();
	}
}
