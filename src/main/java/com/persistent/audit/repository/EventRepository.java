package com.persistent.audit.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.persistent.audit.model.Event;
import com.persistent.audit.model.EventStatus;

public interface EventRepository extends JpaRepository<Event, Long> {

	Optional<Event> findTopByOrderByIdDesc();

	List<Event> findByStatus(EventStatus status);

	@Query("""
			SELECT e FROM Event e
			WHERE (:eventType IS NULL OR e.eventType = :eventType)
			  AND (:actorId IS NULL OR e.actorId = :actorId)
			  AND (:resourceType IS NULL OR e.resourceType = :resourceType)
			  AND (:resourceId IS NULL OR e.resourceId = :resourceId)
			  AND (:fromTimestamp IS NULL OR e.timestamp >= :fromTimestamp)
			  AND (:toTimestamp IS NULL OR e.timestamp <= :toTimestamp)
			""")
	Page<Event> findEvents(
			@Param("eventType") String eventType,
			@Param("actorId") String actorId,
			@Param("resourceType") String resourceType,
			@Param("resourceId") String resourceId,
			@Param("fromTimestamp") Instant fromTimestamp,
			@Param("toTimestamp") Instant toTimestamp,
			Pageable pageable);

	@Query("""
			SELECT e FROM Event e
			WHERE (:actorId IS NULL OR e.actorId = :actorId)
			  AND (:resourceId IS NULL OR e.resourceId = :resourceId)
			ORDER BY e.id ASC
			""")
	List<Event> findForExport(@Param("actorId") String actorId, @Param("resourceId") String resourceId);
}
