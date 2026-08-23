package com.persistent.audit.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.persistent.audit.crypto.PayloadMerkleHasher;
import com.persistent.audit.model.BundleExportStructureResponse;
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
		String sealedPayload = PayloadMerkleHasher.seal(normalizedPayload);
		String hash = computeHash(eventType, actorId, resourceType, resourceId, sealedPayload, timestamp, previousHash);
		log.debug("Computed hash={}", hash);

		log.info("CREATE EVENT DEBUG:");
        log.info("  normalizedPayload: {}", normalizedPayload);
        log.info("  sealedPayload: {}", sealedPayload);
        log.info("  timestamp: {}", timestamp);
        log.info("  computed hash: {}", hash);

		Event event = new Event();
		event.setEventType(eventType);
		event.setActorId(actorId);
		event.setResourceType(resourceType);
		event.setResourceId(resourceId);
		event.setPayload(normalizedPayload);
		event.setSealedPayload(sealedPayload);
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
        String expectedPreviousHash = null;

        for (Event event : events) {
            String recalculatedHash = computeHash(event);
            
			log.info("VERIFY EVENT id={} DEBUG:", event.getId());
            log.info("  stored hash:       {}", event.getHash());
            log.info("  recalculated hash: {}", recalculatedHash);
            log.info("  hashes match: {}", Objects.equals(event.getHash(), recalculatedHash));
            log.info("  sealedPayload: {}", event.getSealedPayload());
            log.info("  timestamp: {}", event.getTimestamp());
			
            // Check if event's own hash matches (detects data tampering)
            if (!Objects.equals(event.getHash(), recalculatedHash)) {
                return invalid(event.getId(), "EVENT HASH MISMATCH");
            }

            // Check if previousHash link is valid (detects chain breaks)
            if (!Objects.equals(event.getPreviousHash(), expectedPreviousHash)) {
                return invalid(event.getId(), "PREVIOUS HASH MISMATCH");
            }

            expectedPreviousHash = event.getHash();
        }

        return new ChainVerificationResult();
    }

    private ChainVerificationResult invalid(Long eventId, String reason) {
        log.warn("Chain verification failed eventId={} reason={}", eventId, reason);
        return new ChainVerificationResult(eventId, reason);
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

	@Transactional
	public EventCreateResponseObject redactFieldsFromPayload(Long id, String fields) {
		if (id == null) {
			throw new IllegalArgumentException("id is required");
		}
		if (!StringUtils.hasText(fields)) {
			throw new IllegalArgumentException("fields is required");
		}
		List<String> keys = parseFieldKeys(fields);
		if (keys.isEmpty()) {
			throw new IllegalArgumentException("fields must contain at least one payload key");
		}
		log.info("Redacting payload fields eventId={} fieldCount={}", id, keys.size());
		Event event = eventRepository.findById(id)
				.orElseThrow(() -> new NoSuchElementException("Event not found for id=" + id));
		 // Redact the SEALED payload (contains __leaves metadata)
		 String redactedSealedPayload = PayloadMerkleHasher.redact(event.getSealedPayload(), keys);
		 event.setSealedPayload(redactedSealedPayload);
		 
		 // Also update the visible payload (without __salts/__leaves)
		 String redactedPayload = PayloadMerkleHasher.redact(event.getPayload(), keys);
		 event.setPayload(redactedPayload);
 
		EventCreateResponseObject saved = EventCreateResponseObject.from(eventRepository.save(event));
		log.info("Redaction completed eventId={} hash unchanged", saved.getId());
		return saved;
	}

	@Transactional(readOnly = true)
	public byte[] exportBundle(String resourceId, String actorId) {
		log.info("Exporting event bundle actorId={} resourceId={}", actorId, resourceId);
		List<Event> events = eventRepository.findForExport(blankToNull(actorId), blankToNull(resourceId));
		List<BundleExportStructureResponse> rows = new ArrayList<>();
		for (Event event : events) {
			String chainMetadata = PayloadMerkleHasher.sha256(
					nullToEmpty(event.getHash()) + nullToEmpty(event.getPreviousHash()));
			rows.add(new BundleExportStructureResponse(
					event.getId(),
					event.getEventType(),
					event.getActorId(),
					event.getResourceType(),
					event.getResourceId(),
					event.getPayload(),
					event.getTimestamp(),
					chainMetadata));
		}
		byte[] csv = toCsv(rows);
		log.info("Exported event bundle rowCount={} file=Event_Bundle.csv", rows.size());
		return csv;
	}

	private String nullToEmpty(String value) {
		return value == null ? "" : value;
	}

	private byte[] toCsv(List<BundleExportStructureResponse> rows) {
		StringBuilder csv = new StringBuilder();
		csv.append("id,eventType,actorId,resourceType,resourceId,payload,timestamp,chainMetadata\n");
		for (BundleExportStructureResponse row : rows) {
			csv.append(csvValue(row.getId()))
					.append(',')
					.append(csvValue(row.getEventType()))
					.append(',')
					.append(csvValue(row.getActorId()))
					.append(',')
					.append(csvValue(row.getResourceType()))
					.append(',')
					.append(csvValue(row.getResourceId()))
					.append(',')
					.append(csvValue(row.getPayload()))
					.append(',')
					.append(csvValue(row.getTimestamp() == null ? null : row.getTimestamp().toString()))
					.append(',')
					.append(csvValue(row.getChainMetadata()))
					.append('\n');
		}
		return csv.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
	}

	private String csvValue(Object value) {
		if (value == null) {
			return "";
		}
		String text = String.valueOf(value);
		if (text.contains(",") || text.contains("\"") || text.contains("\n") || text.contains("\r")) {
			return "\"" + text.replace("\"", "\"\"") + "\"";
		}
		return text;
	}

	private List<String> parseFieldKeys(String fields) {
		List<String> keys = new ArrayList<>();
		for (String token : fields.split(",")) {
			String key = token.trim();
			if (StringUtils.hasText(key) && !keys.contains(key)) {
				keys.add(key);
			}
		}
		return keys;
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

	private String computeHash(Event event) {
        String payloadRootHash = PayloadMerkleHasher.payloadRootFromPayload(event.getSealedPayload());
        return PayloadMerkleHasher.computeEventHash(
            event.getEventType(),
            event.getActorId(),
            event.getResourceType(),
            event.getResourceId(),
            payloadRootHash,
            event.getTimestamp(),
            event.getPreviousHash()
        );
    }


	private String computeHash(String eventType, String actorId, String resourceType, String resourceId,
		String sealedPayload, Instant timestamp, String previousHash) {
	String payloadRootHash = PayloadMerkleHasher.payloadRootFromPayload(sealedPayload);
	return PayloadMerkleHasher.computeEventHash(eventType, actorId, resourceType, resourceId,
			payloadRootHash, timestamp, previousHash);
}


	// private String computeHash(String eventType, String actorId, String resourceType, String resourceId,
	// 		String payload, Instant timestamp, String previousHash) {
	// 	try {
	// 		String payloadRootHash = PayloadMerkleHasher.payloadRootFromPayload(payload);
	// 		return PayloadMerkleHasher.computeEventHash(eventType, actorId, resourceType, resourceId, payloadRootHash,
	// 				timestamp, previousHash);
	// 	} catch (RuntimeException e) {
	// 		log.error("Error while hashing event eventType={} actorId={}", eventType, actorId, e);
	// 		throw e;
	// 	}
	// }
}
