package com.persistent.audit.model;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EventCreateResponseObject {

	private Long id;
	private String eventType;
	private String actorId;
	private String resourceType;
	private String resourceId;
	private String payload;
	private Instant timestamp;

	public static EventCreateResponseObject from(Event event) {
		return new EventCreateResponseObject(
				event.getId(),
				event.getEventType(),
				event.getActorId(),
				event.getResourceType(),
				event.getResourceId(),
				event.getPayload(),
				event.getTimestamp());
	}
}
