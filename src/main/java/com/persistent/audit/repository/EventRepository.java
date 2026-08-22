package com.persistent.audit.repository;

import java.time.Instant;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.persistent.audit.model.Event;

public interface EventRepository extends JpaRepository<Event, Long>, EventRepositoryCustom {

	@Override
	Page<Event> findAll(Pageable pageable);

	@Query("""
			SELECT e FROM Event e
			WHERE (:eventType IS NULL OR e.eventType = :eventType)
			  AND (:actorId IS NULL OR e.actorId = :actorId)
			  AND (:resourceType IS NULL OR e.resourceType = :resourceType)
			  AND (:resourceId IS NULL OR e.resourceId = :resourceId)
			  AND (:fromTimestamp IS NULL OR e.timestamp >= :fromTimestamp)
			  AND (:toTimeStamp IS NULL OR e.timestamp <= :toTimeStamp)
			""")
	Page<Event> findEvents(
			@Param("eventType") String eventType,
			@Param("actorId") String actorId,
			@Param("resourceType") String resourceType,
			@Param("resourceId") String resourceId,
			@Param("fromTimestamp") Instant fromTimestamp,
			@Param("toTimeStamp") Instant toTimeStamp,
			Pageable pageable);
}
