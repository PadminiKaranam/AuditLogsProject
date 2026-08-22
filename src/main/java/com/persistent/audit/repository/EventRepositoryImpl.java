package com.persistent.audit.repository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.support.SimpleJpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.persistent.audit.model.Event;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;

@Repository
@Transactional(readOnly = true)
public class EventRepositoryImpl extends SimpleJpaRepository<Event, Long> implements EventRepository {

	private static final String FILTER_WHERE = """
			WHERE (:eventType IS NULL OR e.eventType = :eventType)
			  AND (:actorId IS NULL OR e.actorId = :actorId)
			  AND (:resourceType IS NULL OR e.resourceType = :resourceType)
			  AND (:resourceId IS NULL OR e.resourceId = :resourceId)
			  AND (:fromTimestamp IS NULL OR e.timestamp >= :fromTimestamp)
			  AND (:toTimeStamp IS NULL OR e.timestamp <= :toTimeStamp)
			""";

	private static final Set<String> SORTABLE_PROPERTIES = Set.of(
			"id", "eventType", "actorId", "resourceType", "resourceId", "timestamp", "hash", "previousHash");

	private final EntityManager entityManager;

	public EventRepositoryImpl(EntityManager entityManager) {
		super(Event.class, entityManager);
		this.entityManager = entityManager;
	}

	@Override
	public Page<Event> findEvents(String eventType, String actorId, String resourceType, String resourceId,
			Instant fromTimestamp, Instant toTimeStamp, Pageable pageable) {
		TypedQuery<Event> query = entityManager.createQuery(
				"SELECT e FROM Event e " + FILTER_WHERE + orderBy(pageable), Event.class);
		bindFilters(query, eventType, actorId, resourceType, resourceId, fromTimestamp, toTimeStamp);
		query.setFirstResult((int) pageable.getOffset());
		query.setMaxResults(pageable.getPageSize());

		TypedQuery<Long> countQuery = entityManager.createQuery(
				"SELECT COUNT(e) FROM Event e " + FILTER_WHERE, Long.class);
		bindFilters(countQuery, eventType, actorId, resourceType, resourceId, fromTimestamp, toTimeStamp);

		List<Event> content = query.getResultList();
		long total = countQuery.getSingleResult();
		return new PageImpl<>(content, pageable, total);
	}

	@Override
	@Transactional
	public Event createEvent(String eventType, String actorId, String resourceType, String resourceId,
			Map<String, Object> payload) {
		Instant timestamp = Instant.now();
		String previousHash = findLatestHash();
		String hash = computeHash(eventType, actorId, resourceType, resourceId, payload, timestamp, previousHash);

		Event event = new Event(eventType, actorId, resourceType, resourceId, payload, hash, previousHash);
		event.setTimestamp(timestamp);
		return save(event);
	}

	private void bindFilters(TypedQuery<?> query, String eventType, String actorId, String resourceType,
			String resourceId, Instant fromTimestamp, Instant toTimeStamp) {
		query.setParameter("eventType", eventType);
		query.setParameter("actorId", actorId);
		query.setParameter("resourceType", resourceType);
		query.setParameter("resourceId", resourceId);
		query.setParameter("fromTimestamp", fromTimestamp);
		query.setParameter("toTimeStamp", toTimeStamp);
	}

	private String orderBy(Pageable pageable) {
		if (pageable.getSort().isUnsorted()) {
			return " ORDER BY e.timestamp DESC, e.id DESC";
		}
		StringBuilder orderBy = new StringBuilder(" ORDER BY ");
		boolean first = true;
		for (Sort.Order order : pageable.getSort()) {
			String property = order.getProperty();
			if (!SORTABLE_PROPERTIES.contains(property)) {
				continue;
			}
			if (!first) {
				orderBy.append(", ");
			}
			orderBy.append("e.").append(property).append(" ").append(order.isAscending() ? "ASC" : "DESC");
			first = false;
		}
		if (first) {
			return " ORDER BY e.timestamp DESC, e.id DESC";
		}
		return orderBy.toString();
	}

	private String findLatestHash() {
		List<Event> latest = entityManager
				.createQuery("SELECT e FROM Event e ORDER BY e.id DESC", Event.class)
				.setMaxResults(1)
				.getResultList();
		return latest.isEmpty() ? null : latest.get(0).getHash();
	}

	private String computeHash(String eventType, String actorId, String resourceType, String resourceId,
			Map<String, Object> payload, Instant timestamp, String previousHash) {
		String canonical = String.join("|",
				nullToEmpty(eventType),
				nullToEmpty(actorId),
				nullToEmpty(resourceType),
				nullToEmpty(resourceId),
				toJson(payload),
				timestamp.toString(),
				nullToEmpty(previousHash));
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashed = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(hashed);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 is not available", e);
		}
	}

	private String toJson(Map<String, Object> payload) {
		if (payload == null || payload.isEmpty()) {
			return "";
		}
		return payload.entrySet().stream()
				.sorted(Map.Entry.comparingByKey())
				.map(entry -> entry.getKey() + "=" + entry.getValue())
				.collect(Collectors.joining(",", "{", "}"));
	}

	private static String nullToEmpty(String value) {
		return value == null ? "" : value;
	}
}
