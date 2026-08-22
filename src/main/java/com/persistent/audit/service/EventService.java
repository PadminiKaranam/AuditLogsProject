package com.persistent.audit.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.persistent.audit.model.Event;
import com.persistent.audit.model.EventCreateResponseObject;
import com.persistent.audit.repository.EventRepository;
import com.persistent.audit.util.PaginationUtils;

@Service
public class EventService {

	private final EventRepository eventRepository;

	public EventService(EventRepository eventRepository) {
		this.eventRepository = eventRepository;
	}

	@Transactional
	public EventCreateResponseObject createEvent(String eventType, String actorId, String resourceType,
			String resourceId, String payload) {
		Instant timestamp = Instant.now();
		String normalizedPayload = StringUtils.hasText(payload) ? payload : "{}";
		String previousHash = eventRepository.findTopByOrderByIdDesc()
				.map(Event::getHash)
				.orElse(null);
		String hash = computeHash(eventType, actorId, resourceType, resourceId, normalizedPayload, timestamp,
				previousHash);

		Event event = new Event();
		event.setEventType(eventType);
		event.setActorId(actorId);
		event.setResourceType(resourceType);
		event.setResourceId(resourceId);
		event.setPayload(normalizedPayload);
		event.setTimestamp(timestamp);
		event.setHash(hash);
		event.setPreviousHash(previousHash);
		return EventCreateResponseObject.from(eventRepository.save(event));
	}

	@Transactional(readOnly = true)
	public Page<EventCreateResponseObject> getEvents(String eventType, String actorId, String resourceType,
			String resourceId, Instant fromTimestamp, Instant toTimestamp) {
		return getEvents(eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp, 0);
	}

	@Transactional(readOnly = true)
	public Page<EventCreateResponseObject> getEvents(String eventType, String actorId, String resourceType,
			String resourceId, Instant fromTimestamp, Instant toTimestamp, int page) {
		Pageable pageable = PaginationUtils.pageRequest(page);
		Page<Event> events;
		if (hasFilters(eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp)) {
			events = eventRepository.findEvents(
					blankToNull(eventType),
					blankToNull(actorId),
					blankToNull(resourceType),
					blankToNull(resourceId),
					fromTimestamp,
					toTimestamp,
					pageable);
		} else {
			events = eventRepository.findAll(pageable);
		}
		return events.map(EventCreateResponseObject::from);
	}

	private boolean hasFilters(String eventType, String actorId, String resourceType, String resourceId,
			Instant fromTimestamp, Instant toTimestamp) {
		return StringUtils.hasText(eventType)
				|| StringUtils.hasText(actorId)
				|| StringUtils.hasText(resourceType)
				|| StringUtils.hasText(resourceId)
				|| fromTimestamp != null
				|| toTimestamp != null;
	}

	private String blankToNull(String value) {
		return StringUtils.hasText(value) ? value : null;
	}

	private String computeHash(String eventType, String actorId, String resourceType, String resourceId,
			String payload, Instant timestamp, String previousHash) {
		String canonical = eventType + "|"
				+ actorId + "|"
				+ resourceType + "|"
				+ resourceId + "|"
				+ payload + "|"
				+ timestamp + "|"
				+ (previousHash != null ? previousHash : "");
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashed = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(hashed);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 is not available", e);
		}
	}
}
