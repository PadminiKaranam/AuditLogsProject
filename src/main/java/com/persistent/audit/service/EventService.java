package com.persistent.audit.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.persistent.audit.model.ChainVerificationResult;
import com.persistent.audit.model.Event;
import com.persistent.audit.model.EventCreateResponseObject;
import com.persistent.audit.model.EventStatus;
import com.persistent.audit.model.RetentionCheckResult;
import com.persistent.audit.repository.EventRepository;
import com.persistent.audit.util.PaginationUtils;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class EventService {

	private final EventRepository eventRepository;

	public EventService(EventRepository eventRepository) {
		this.eventRepository = eventRepository;
	}

	@Transactional
	public EventCreateResponseObject createEvent(String eventType, String actorId, String resourceType,
			String resourceId, String payload) {
		log.info("Creating event eventType={} actorId={} resourceType={} resourceId={}",
				eventType, actorId, resourceType, resourceId);
		Instant timestamp = Instant.now();
		String normalizedPayload = StringUtils.hasText(payload) ? payload : "{}";
		String previousHash = eventRepository.findTopByOrderByIdDesc()
				.map(Event::getHash)
				.orElse(null);
		log.debug("Hashing event with previousHash={}", previousHash);
		String hash = computeHash(eventType, actorId, resourceType, resourceId, normalizedPayload, timestamp,
				previousHash);
		log.debug("Computed hash={}", hash);

		Event event = new Event();
		event.setEventType(eventType);
		event.setActorId(actorId);
		event.setResourceType(resourceType);
		event.setResourceId(resourceId);
		event.setPayload(normalizedPayload);
		event.setTimestamp(timestamp);
		event.setHash(hash);
		event.setPreviousHash(previousHash);
		event.setStatus(EventStatus.ACTIVE);
		EventCreateResponseObject saved = EventCreateResponseObject.from(eventRepository.save(event));
		log.info("Saved event id={} hash computed successfully", saved.getId());
		return saved;
	}

	@Transactional(readOnly = true)
	public Page<EventCreateResponseObject> getEvents(String eventType, String actorId, String resourceType,
			String resourceId, Instant fromTimestamp, Instant toTimestamp) {
		return getEvents(eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp, 0);
	}

	@Transactional(readOnly = true)
	public Page<EventCreateResponseObject> getEvents(String eventType, String actorId, String resourceType,
			String resourceId, Instant fromTimestamp, Instant toTimestamp, int page) {
		log.info("Fetching events page={} eventType={} actorId={} resourceType={} resourceId={} fromTimestamp={} toTimestamp={}",
				page, eventType, actorId, resourceType, resourceId, fromTimestamp, toTimestamp);
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
		log.debug("Fetched {} events of {} total for page {}", events.getNumberOfElements(), events.getTotalElements(),
				pageable.getPageNumber());
		return events.map(EventCreateResponseObject::from);
	}

	@Transactional(readOnly = true)
	public ChainVerificationResult verifyChain() {
		List<Event> events = eventRepository.findAll(Sort.by(Sort.Direction.ASC, "id"));
		log.info("Starting chain verification eventCount={}", events.size());
		for (int i = 1; i < events.size(); i++) {
			Event current = events.get(i);
			Event previous = events.get(i - 1);
			log.debug("Verifying chain eventId={} previousEventId={}", current.getId(), previous.getId());
			if (!Objects.equals(current.getPreviousHash(), previous.getHash())) {
				log.info("Chain verification HASH MISMATCH firstInvalidRecordId={}", current.getId());
				return new ChainVerificationResult(current.getId(), "HASH MISMATCH");
			}
		}
		log.info("Chain verification completed with no mismatches");
		return new ChainVerificationResult();
	}

	@Transactional
	public RetentionCheckResult checkForRetention(int days) {
		log.info("Checking retention policy days={}", days);
		Instant cutoff = Instant.now().minus(days, ChronoUnit.DAYS);
		List<Event> activeEvents = eventRepository.findByStatus(EventStatus.ACTIVE);
		int archivedCount = 0;
		for (Event event : activeEvents) {
			if (event.getTimestamp() != null && event.getTimestamp().isBefore(cutoff)) {
				event.setStatus(EventStatus.ARCHIVED);
				eventRepository.save(event);
				archivedCount++;
				log.debug("Archived event id={} timestamp={}", event.getId(), event.getTimestamp());
			}
		}
		log.info("Retention check completed days={} archivedCount={}", days, archivedCount);
		return new RetentionCheckResult(days, archivedCount);
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
			log.error("Error while hashing event eventType={} actorId={}", eventType, actorId, e);
			throw new IllegalStateException("SHA-256 is not available", e);
		}
	}
}
