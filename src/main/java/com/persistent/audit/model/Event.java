package com.persistent.audit.model;

import java.time.Instant;
import java.util.Map;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Entity
@Table(name = "EVENT")
public class Event {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank
	@Size(max = 100)
	@Column(name = "event_type", nullable = false, length = 100)
	private String eventType;

	@NotBlank
	@Size(max = 255)
	@Column(name = "actor_id", nullable = false, length = 255)
	private String actorId;

	@NotBlank
	@Size(max = 100)
	@Column(name = "resource_type", nullable = false, length = 100)
	private String resourceType;

	@NotBlank
	@Size(max = 255)
	@Column(name = "resource_id", nullable = false, length = 255)
	private String resourceId;

	@JdbcTypeCode(SqlTypes.JSON)
	@Column(name = "payload", columnDefinition = "json")
	private Map<String, Object> payload;

	@NotNull
	@Column(name = "timestamp", nullable = false, updatable = false)
	private Instant timestamp;

	@NotBlank
	@Size(max = 128)
	@Column(name = "hash", nullable = false, length = 128)
	private String hash;

	@Size(max = 128)
	@Column(name = "previous_hash", length = 128)
	private String previousHash;

	public Event() {
	}

	public Event(String eventType, String actorId, String resourceType, String resourceId,
			Map<String, Object> payload, String hash, String previousHash) {
		this.eventType = eventType;
		this.actorId = actorId;
		this.resourceType = resourceType;
		this.resourceId = resourceId;
		this.payload = payload;
		this.hash = hash;
		this.previousHash = previousHash;
	}

	public Event(Long id, String eventType, String actorId, String resourceType, String resourceId,
			Map<String, Object> payload, Instant timestamp, String hash, String previousHash) {
		this.id = id;
		this.eventType = eventType;
		this.actorId = actorId;
		this.resourceType = resourceType;
		this.resourceId = resourceId;
		this.payload = payload;
		this.timestamp = timestamp;
		this.hash = hash;
		this.previousHash = previousHash;
	}

	@PrePersist
	protected void assignServerTimestamp() {
		if (this.timestamp == null) {
			this.timestamp = Instant.now();
		}
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getEventType() {
		return eventType;
	}

	public void setEventType(String eventType) {
		this.eventType = eventType;
	}

	public String getActorId() {
		return actorId;
	}

	public void setActorId(String actorId) {
		this.actorId = actorId;
	}

	public String getResourceType() {
		return resourceType;
	}

	public void setResourceType(String resourceType) {
		this.resourceType = resourceType;
	}

	public String getResourceId() {
		return resourceId;
	}

	public void setResourceId(String resourceId) {
		this.resourceId = resourceId;
	}

	public Map<String, Object> getPayload() {
		return payload;
	}

	public void setPayload(Map<String, Object> payload) {
		this.payload = payload;
	}

	public Instant getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Instant timestamp) {
		this.timestamp = timestamp;
	}

	public String getHash() {
		return hash;
	}

	public void setHash(String hash) {
		this.hash = hash;
	}

	public String getPreviousHash() {
		return previousHash;
	}

	public void setPreviousHash(String previousHash) {
		this.previousHash = previousHash;
	}
}
