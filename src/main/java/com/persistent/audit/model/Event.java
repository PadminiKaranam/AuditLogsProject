package com.persistent.audit.model;

import java.time.Instant;

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

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "EVENT")
@Data
@NoArgsConstructor
@AllArgsConstructor
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

	@NotBlank
	@Column(name = "payload", nullable = false, columnDefinition = "TEXT")
	private String payload;

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

	@PrePersist
	protected void assignServerTimestamp() {
		if (this.timestamp == null) {
			this.timestamp = Instant.now();
		}
	}

	public Event(String eventType, String actorId, String resourceType, String resourceId,
		String payload, String hash, String previousHash) {
	this.eventType = eventType;
	this.actorId = actorId;
	this.resourceType = resourceType;
	this.resourceId = resourceId;
	this.payload = payload;
	this.hash = hash;
	this.previousHash = previousHash;
}
}
