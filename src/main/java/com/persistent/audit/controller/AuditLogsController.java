package com.persistent.audit.controller;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.persistent.audit.model.ChainVerificationResult;
import com.persistent.audit.model.EventCreateRequest;
import com.persistent.audit.model.EventCreateResponseObject;
import com.persistent.audit.service.EventService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/audit")
public class AuditLogsController {

	private final EventService eventService;

	public AuditLogsController(EventService eventService) {
		this.eventService = eventService;
	}

	@PostMapping("/createEvent")
	public ResponseEntity<EventCreateResponseObject> createEvent(@Valid @RequestBody EventCreateRequest request) {
		EventCreateResponseObject saved = eventService.createEvent(
				request.getEventType(),
				request.getActorId(),
				request.getResourceType(),
				request.getResourceId(),
				request.getPayload());
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
		Page<EventCreateResponseObject> events = eventService.getEvents(
				eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp);
		return ResponseEntity.ok(events);
	}

	@GetMapping("/verify")
	public ResponseEntity<ChainVerificationResult> verifyChain() {
		return ResponseEntity.ok(eventService.verifyChain());
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
		Map<String, String> fieldErrors = ex.getBindingResult().getFieldErrors().stream()
				.collect(Collectors.toMap(
						error -> error.getField(),
						error -> error.getDefaultMessage() != null ? error.getDefaultMessage() : "invalid",
						(first, ignored) -> first,
						LinkedHashMap::new));
		return error(HttpStatus.BAD_REQUEST, "Validation failed", fieldErrors);
	}

	@ExceptionHandler({ HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class })
	public ResponseEntity<Map<String, Object>> handleBadRequest(Exception ex) {
		return error(HttpStatus.BAD_REQUEST, ex.getMessage(), null);
	}

	private ResponseEntity<Map<String, Object>> error(HttpStatus status, String message, Map<String, String> fields) {
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("status", status.value());
		body.put("error", message);
		if (fields != null) {
			body.put("fields", fields);
		}
		return ResponseEntity.status(status).body(body);
	}
}
